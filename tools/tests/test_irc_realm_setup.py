import contextlib
import io
import json
import os
import sys
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import irc_realm_setup  # noqa: E402
from irc_realm_setup import Session, drop_legacy_scram_attributes  # noqa: E402

TOKEN_PATH = "/realms/master/protocol/openid-connect/token"


class _Response:
    def __init__(self, status, body):
        self.status = status
        self._raw = body if isinstance(body, bytes) else json.dumps(body).encode()

    def read(self):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeKeycloak:
    """A stub opener: the token endpoint hands out numbered tokens; other requests are answered by `answer`."""

    def __init__(self, expires_in=60, answer=None):
        self.expires_in = expires_in
        self.logins = 0
        self.calls = []   # (method, path, token)
        self.answer = answer or (lambda method, path, token: (200, {"ok": True}))

    def __call__(self, req):
        path = req.full_url.split("http://kc.test", 1)[1]
        if path == TOKEN_PATH:
            self.logins += 1
            return _Response(200, {"access_token": "t%d" % self.logins, "expires_in": self.expires_in})
        token = req.get_header("Authorization")[len("Bearer "):]
        self.calls.append((req.get_method(), path, token))
        status, body = self.answer(req.get_method(), path, token)
        if status >= 400:
            raise urllib.error.HTTPError(req.full_url, status, "refused", {}, io.BytesIO(b""))
        return _Response(status, body)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class SessionRelogin(unittest.TestCase):
    def test_a_401_logs_in_again_and_retries_the_request_once(self):
        kc = FakeKeycloak(answer=lambda m, p, token: (401, None) if token == "t1" else (200, {"ok": True}))
        s = Session("http://kc.test", "admin", "pw", opener=kc)
        self.assertEqual(s.request("GET", "/admin/realms/r"), (200, {"ok": True}))
        self.assertEqual(kc.logins, 2)
        self.assertEqual([c[2] for c in kc.calls], ["t1", "t2"])

    def test_a_second_401_is_an_error_not_a_loop(self):
        kc = FakeKeycloak(answer=lambda m, p, token: (401, None))
        s = Session("http://kc.test", "admin", "pw", opener=kc)
        with self.assertRaisesRegex(RuntimeError, "HTTP 401"):
            s.request("GET", "/admin/realms/r")
        self.assertEqual(kc.logins, 2)
        self.assertEqual(len(kc.calls), 2)

    def test_logs_in_again_before_the_token_expires(self):
        kc = FakeKeycloak(expires_in=60)
        clock = Clock()
        s = Session("http://kc.test", "admin", "pw", opener=kc, clock=clock)
        s.request("GET", "/a")
        clock.now += 30
        s.request("GET", "/b")
        self.assertEqual(kc.logins, 1)
        clock.now += 25   # 55 s after the login: within the margin before expires_in runs out
        s.request("GET", "/c")
        self.assertEqual(kc.logins, 2)
        self.assertEqual([c[2] for c in kc.calls], ["t1", "t1", "t2"])

    def test_a_long_run_never_sees_a_401(self):
        clock = Clock()
        issued = {}

        def answer(method, path, token):   # a token is good for 60 s after it was issued
            return (401, None) if clock.now - issued[token] >= 60 else (200, {"ok": True})

        kc = FakeKeycloak(expires_in=60, answer=answer)
        real = kc.__call__

        def opener(req):
            r = real(req)
            if req.full_url.endswith(TOKEN_PATH):
                issued["t%d" % kc.logins] = clock.now
            return r

        s = Session("http://kc.test", "admin", "pw", opener=opener, clock=clock)
        for _ in range(100):
            clock.now += 7
            self.assertEqual(s.request("GET", "/x")[0], 200)
        self.assertTrue(all(token in issued for _, _, token in kc.calls))
        self.assertEqual(len(kc.calls), 100)   # no request needed a retry

    def test_a_response_that_is_not_json_is_a_runtime_error(self):
        kc = FakeKeycloak(answer=lambda m, p, t: (200, b"<html>"))
        s = Session("http://kc.test", "admin", "pw", opener=kc)
        with self.assertRaisesRegex(RuntimeError, "not JSON"):
            s.request("GET", "/x")


class FakeSession:
    """Answers drop_legacy_scram_attributes' admin-API calls; the PUT for user ids in `refuse` is refused."""

    def __init__(self, users, refuse=()):
        self.users = users
        self.refuse = set(refuse)
        self.put = []

    def request(self, method, path, body=None, ok=(200, 201, 204)):
        if path.endswith("/users/profile"):
            return 200, {"unmanagedAttributePolicy": "ADMIN_EDIT"}
        if "/users?" in path:
            first = int(path.split("first=")[1].split("&")[0])
            return 200, self.users[first:first + 2]
        uid = path.rsplit("/", 1)[1]
        if method == "GET":
            return 200, dict(next(u for u in self.users if u["id"] == uid))
        if uid in self.refuse:
            raise RuntimeError("%s %s: HTTP 400" % (method, path))
        self.put.append(uid)
        return 204, None


class DropLegacyAttributes(unittest.TestCase):
    def test_a_refused_user_is_counted_and_the_run_goes_on(self):
        legacy = {"scram_sha256_salt": ["x"], "keep": ["y"]}
        users = [{"id": "a", "username": "a", "attributes": legacy},
                 {"id": "b", "username": "b", "attributes": legacy},
                 {"id": "c", "username": "c", "attributes": {"keep": ["y"]}},
                 {"id": "d", "username": "d", "attributes": legacy}]
        s = FakeSession(users, refuse={"b"})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(drop_legacy_scram_attributes(s, "r"), (2, 1))
        self.assertEqual(s.put, ["a", "d"])
        self.assertIn("removed legacy SCRAM attributes from 2 user(s)", out.getvalue())
        self.assertIn("failed for 1 user(s)", out.getvalue())
        self.assertIn("user b", err.getvalue())

    def test_main_exits_1_when_a_user_failed(self):
        with mock.patch.object(irc_realm_setup, "Session"), \
                mock.patch.object(irc_realm_setup, "plan_flows"), \
                mock.patch.object(irc_realm_setup, "ensure_role"), \
                mock.patch.object(irc_realm_setup, "ensure_required_action"), \
                mock.patch.object(irc_realm_setup, "ensure_certfp_attribute"), \
                mock.patch.object(irc_realm_setup, "ensure_event_listener"), \
                mock.patch.object(irc_realm_setup, "apply_flows"), \
                mock.patch.object(irc_realm_setup, "drop_legacy_scram_attributes", return_value=(3, 1)), \
                mock.patch.dict(os.environ, {"KC_PW": "pw"}):
            self.assertEqual(irc_realm_setup.main(
                ["--url", "http://kc.test", "--realm", "r", "--admin-user", "a", "--admin-pass-env", "KC_PW",
                 "--drop-legacy-scram-attributes"]), 1)


class ConnectionErrors(unittest.TestCase):
    def run_main(self, opener):
        err = io.StringIO()
        with mock.patch.object(irc_realm_setup.urllib.request, "urlopen", opener), \
                mock.patch.dict(os.environ, {"KC_PW": "pw"}), contextlib.redirect_stderr(err):
            status = irc_realm_setup.main(["--url", "http://kc.test", "--realm", "r", "--admin-user", "a",
                                           "--admin-pass-env", "KC_PW"])
        return status, err.getvalue()

    def test_an_unreachable_keycloak_is_one_clean_message(self):
        def refuse(req):
            raise urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))
        status, err = self.run_main(refuse)
        self.assertEqual(status, 1)
        self.assertNotIn("Traceback", err)
        self.assertEqual(len(err.strip().splitlines()), 1)
        self.assertTrue(err.startswith("error: "))

    def test_a_reply_that_is_not_json_is_one_clean_message(self):
        def html(req):
            return _Response(200, b"<html>proxy error</html>")
        status, err = self.run_main(html)
        self.assertEqual(status, 1)
        self.assertNotIn("Traceback", err)
        self.assertEqual(len(err.strip().splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
