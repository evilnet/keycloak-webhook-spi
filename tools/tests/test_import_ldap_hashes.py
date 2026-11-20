import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import import_ldap_hashes  # noqa: E402
from import_ldap_hashes import parse_ldif, process_user, scheme_of, to_credential  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "sample.ldif")
MD5 = "{MD5}Xr4ilOzQ4PCOq3aQ0qbuaQ=="
SSHA = "{SSHA}uJDd0BIdJ9Z7yDCZNWdgYeb33+cBAgME"


class SchemeOf(unittest.TestCase):
    def test_schemes(self):
        self.assertEqual(scheme_of(MD5), "{MD5}")
        self.assertEqual(scheme_of("{ssha}uJDd0BIdJ9Z7yDCZNWdgYeb33+cBAgME"), "{SSHA}")
        self.assertEqual(scheme_of("{CRYPT}$1$abc"), "{CRYPT}")
        self.assertEqual(scheme_of("hunter2"), "(no scheme prefix)")


class ToCredential(unittest.TestCase):
    def test_md5_credential(self):
        c = to_credential(MD5)
        self.assertEqual(json.loads(c["credentialData"]), {"hashIterations": 1, "algorithm": "x3-md5"})
        self.assertEqual(json.loads(c["secretData"]), {"value": "Xr4ilOzQ4PCOq3aQ0qbuaQ==", "salt": ""})
        self.assertEqual(c["userLabel"], "ldap-import")
        self.assertEqual(c["type"], "password")

    def test_scheme_name_is_case_insensitive(self):
        self.assertEqual(to_credential("{md5}Xr4ilOzQ4PCOq3aQ0qbuaQ=="), to_credential(MD5))

    def test_ssha_credential_splits_digest_and_salt(self):
        c = to_credential(SSHA)
        self.assertEqual(json.loads(c["credentialData"]), {"hashIterations": 1, "algorithm": "ldap-ssha"})
        self.assertEqual(json.loads(c["secretData"]),
                         {"value": "uJDd0BIdJ9Z7yDCZNWdgYeb33+c=", "salt": "AQIDBA=="})
        self.assertEqual(c["userLabel"], "ldap-import")

    def test_unsupported(self):
        self.assertIsNone(to_credential("{CRYPT}$1$abc"))
        self.assertIsNone(to_credential("hunter2"))

    def test_malformed_md5(self):
        self.assertIsNone(to_credential("{MD5}AAAA"))            # decodes to 3 bytes
        self.assertIsNone(to_credential("{MD5}not base64 !!"))

    def test_malformed_ssha(self):
        self.assertIsNone(to_credential("{SSHA}" + "QUJD"))        # 3 bytes
        self.assertIsNone(to_credential("{SSHA}uJDd0BIdJ9Z7yDCZNWdgYeb33+c="))   # digest only, no salt
        self.assertIsNone(to_credential("{SSHA}%%%%"))


class ParseLdif(unittest.TestCase):
    def test_parse_ldif(self):
        with open(FIXTURE) as f:
            self.assertEqual(parse_ldif(f.read()), [
                ("alice", MD5), ("bob", SSHA), ("carol", None), ("dave", MD5)])

    def test_comments_version_crlf_and_case(self):
        text = ("version: 1\r\n\r\n# a comment\r\ndn: uid=a,dc=x\r\nUID: alice\r\n"
                "# another\r\nuserpassword: {MD5}abc\r\n\r\n")
        self.assertEqual(parse_ldif(text), [("alice", "{MD5}abc")])

    def test_entry_without_uid_is_skipped(self):
        text = "dn: ou=people,dc=x\nobjectClass: organizationalUnit\n\ndn: uid=a,dc=x\nuid: a\n"
        self.assertEqual(parse_ldif(text), [("a", None)])

    def test_several_values_is_marked(self):
        text = "dn: uid=a,dc=x\nuid: a\nuserPassword: {MD5}abc\nuserPassword: {MD5}def\n"
        [(name, pw)] = parse_ldif(text)
        self.assertEqual(name, "a")
        self.assertEqual(scheme_of(pw), "(several values)")
        self.assertIsNone(to_credential(pw))

    def test_other_uid_attribute(self):
        text = "dn: cn=a,dc=x\ncn: alice\nuid: nope\nuserPassword: x\n"
        self.assertEqual(parse_ldif(text, uid_attr="cn"), [("alice", "x")])


class FakeSession:
    """Answers process_user's admin-API calls for the users in `users` (name -> representation)."""

    def __init__(self, users, fail_after=None):
        self.users = users
        self.lookups = 0
        self.fail_after = fail_after
        self.loaded = []

    def request(self, method, path, body=None, ok=(200, 201, 204)):
        if "/users?username=" in path:
            self.lookups += 1
            if self.fail_after is not None and self.lookups > self.fail_after:
                raise urllib.error.URLError(ConnectionResetError(104, "Connection reset by peer"))
            name = path.split("username=")[1].split("&")[0]
            return 200, [self.users[name]] if name in self.users else []
        if path.endswith("/credentials"):
            return 200, []
        self.loaded.append(path)
        return 204, None


class LinkedUsers(unittest.TestCase):
    LINKED = {"id": "1", "username": "lin", "federationLink": "ldap-provider-id"}

    def test_a_linked_user_is_not_loaded_by_default(self):
        for apply in (False, True):
            s = FakeSession({"lin": self.LINKED})
            self.assertEqual(process_user(s, "r", "lin", MD5, apply), "linked")
            self.assertEqual(s.loaded, [])

    def test_allow_linked_loads_it(self):
        s = FakeSession({"lin": self.LINKED})
        self.assertEqual(process_user(s, "r", "lin", MD5, False, allow_linked=True), "would-load")
        self.assertEqual(process_user(s, "r", "lin", MD5, True, allow_linked=True), "loaded")
        self.assertEqual(len(s.loaded), 1)

    def test_an_empty_federation_link_is_not_linked(self):
        s = FakeSession({"u": {"id": "2", "username": "u", "federationLink": ""}})
        self.assertEqual(process_user(s, "r", "u", MD5, False), "would-load")


class ConnectionLostPartWay(unittest.TestCase):
    def test_the_summary_so_far_is_printed_before_exit_2(self):
        users = {n: {"id": n, "username": n} for n in ("alice", "bob", "dave")}
        fake = FakeSession(users, fail_after=2)
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as d:
            ldif = os.path.join(d, "u.ldif")
            with open(ldif, "w") as f:
                f.write("dn: uid=alice\nuid: alice\nuserPassword: %s\n\ndn: uid=bob\nuid: bob\n\n"
                        "dn: uid=dave\nuid: dave\nuserPassword: %s\n" % (MD5, MD5))
            with mock.patch.object(import_ldap_hashes, "Session", return_value=fake), \
                    mock.patch.dict(os.environ, {"KC_PW": "pw"}), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                status = import_ldap_hashes.main(["--ldif", ldif, "--url", "http://kc.test", "--realm", "r",
                                                  "--admin-user", "a", "--admin-pass-env", "KC_PW"])
        self.assertEqual(status, 2)
        self.assertIn("would-load 1", out.getvalue())
        self.assertIn("no-password 1", out.getvalue())
        self.assertIn("error: ", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())


if __name__ == "__main__":
    unittest.main()
