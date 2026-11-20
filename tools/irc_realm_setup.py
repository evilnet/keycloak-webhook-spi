#!/usr/bin/env python3
"""Idempotent set-up of a Keycloak realm for the IRC credentials SPI.  Standard library only.

    irc_realm_setup.py --url U --realm R --admin-user A --admin-pass-env VAR [--service-client CLIENT]
                       [--drop-legacy-scram-attributes]

Creates the realm role `irc-read-credentials` that GET /realms/R/irc/credentials/{username}
requires and, with --service-client, grants it to that client's service account.

Copies the realm's bound direct-grant and browser flows (whatever they are: the built-in ones
or custom ones) to `irc direct grant` and `irc browser`, puts the IRC steps in each as REQUIRED,
and binds both copies to the realm:

- `irc direct grant`: `irc-account-state`, then `irc-credential-sync`, as the last two top-level
  executions, after every other step of the flow (the conditional OTP sub-flow included), so they
  run only once every factor the flow demands is satisfied;
- `irc browser`: `irc-credential-sync` directly after the username/password form, in the same
  (sub-)flow, since only that form's request carries the password.

A copy an earlier version set up is brought to this layout.  If a bound flow has no password
step, it exits 1 before changing anything.

Registers and enables the required action `irc-ecdsa-enroll` (not a default action), with which
a user adds an ECDSA key from the account page.

With --drop-legacy-scram-attributes, also removes the SCRAM verifier user attributes of earlier
versions (scram_sha256_*, x3_scram_*) from every user and prints how many users it changed.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

ROLE = "irc-read-credentials"

SYNC_STEP = "irc-credential-sync"
ACCOUNT_STATE_STEP = "irc-account-state"
# Where a copy's IRC steps go: the last top-level executions, or directly after the password step.
LAST = "last"
AFTER_PASSWORD = "after-password"
# (the copy, the realm's binding it replaces, the password step it must contain, placement, the steps in order)
FLOW_COPIES = (
    ("irc direct grant", "directGrantFlow", "direct-grant-validate-password", LAST, (ACCOUNT_STATE_STEP, SYNC_STEP)),
    ("irc browser", "browserFlow", "auth-username-password-form", AFTER_PASSWORD, (SYNC_STEP,)),
)

ECDSA_ENROLL = "irc-ecdsa-enroll"
ECDSA_ENROLL_NAME = "IRC: add an ECDSA key"

LEGACY_SCRAM_ATTRIBUTES = ("scram_sha256_salt", "scram_sha256_iterations",
                           "scram_sha256_stored_key", "scram_sha256_server_key")
LEGACY_SCRAM_PREFIX = "x3_scram_"   # X3's x3_scram_* and x3_scram_sha256_*


class Session:
    """A minimal admin-API client: one bearer token, JSON in and out."""

    def __init__(self, url, token):
        self.url = url.rstrip("/")
        self.token = token

    def request(self, method, path, body=None, ok=(200, 201, 204)):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=data, method=method, headers={
            "Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as r:
                status, raw = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, raw = e.code, e.read()
        if status not in ok:
            raise RuntimeError("%s %s: HTTP %d" % (method, path, status))
        return status, (json.loads(raw) if raw else None)


def login(url, user, password):
    data = urllib.parse.urlencode({"grant_type": "password", "client_id": "admin-cli",
                                   "username": user, "password": password}).encode()
    req = urllib.request.Request(url.rstrip("/") + "/realms/master/protocol/openid-connect/token", data=data)
    try:
        with urllib.request.urlopen(req) as r:
            return json.load(r)["access_token"]
    except urllib.error.HTTPError as e:
        raise RuntimeError("admin login failed: HTTP %d" % e.code)


def ensure_role(session, realm, service_client=None):
    """Create the role if missing; with service_client, grant it to that client's service account."""
    r = urllib.parse.quote(realm, safe="")
    status, role = session.request("GET", "/admin/realms/%s/roles/%s" % (r, ROLE), ok=(200, 404))
    if status == 404:
        session.request("POST", "/admin/realms/%s/roles" % r, {
            "name": ROLE, "description": "Read IRC credentials and account state (irc SPI endpoint)"})
        _, role = session.request("GET", "/admin/realms/%s/roles/%s" % (r, ROLE))
    if service_client:
        _, clients = session.request("GET", "/admin/realms/%s/clients?clientId=%s&search=false"
                                     % (r, urllib.parse.quote(service_client, safe="")))
        client = next((c for c in clients if c["clientId"] == service_client), None)
        if client is None:
            raise RuntimeError("no client %r in realm %s" % (service_client, realm))
        _, account = session.request("GET", "/admin/realms/%s/clients/%s/service-account-user" % (r, client["id"]))
        mappings = "/admin/realms/%s/users/%s/role-mappings/realm" % (r, account["id"])
        _, current = session.request("GET", mappings)
        if not any(m["name"] == ROLE for m in current):
            session.request("POST", mappings, [{"id": role["id"], "name": ROLE}])


def ensure_required_action(session, realm):
    """Register the irc-ecdsa-enroll required action if missing; make it enabled and not a default action."""
    r = _q(realm)
    path = "/admin/realms/%s/authentication/required-actions/%s" % (r, _q(ECDSA_ENROLL))
    status, action = session.request("GET", path, ok=(200, 404))
    if status == 404:
        session.request("POST", "/admin/realms/%s/authentication/register-required-action" % r,
                        {"providerId": ECDSA_ENROLL, "name": ECDSA_ENROLL_NAME})
        _, action = session.request("GET", path)
    if not action.get("enabled") or action.get("defaultAction"):
        session.request("PUT", path, dict(action, enabled=True, defaultAction=False))


def _q(value):
    return urllib.parse.quote(value, safe="")


def plan_flows(session, realm):
    """Check both bindings before anything is written;
    returns [(copy, binding, password step, placement, steps, flow to copy or None)]."""
    r = _q(realm)
    _, rep = session.request("GET", "/admin/realms/%s" % r)
    _, flows = session.request("GET", "/admin/realms/%s/authentication/flows" % r)
    aliases = {f["alias"] for f in flows}
    plan = []
    for copy, binding, password_step, placement, steps in FLOW_COPIES:
        bound = rep.get(binding)
        if bound == copy:
            source = None
        elif copy in aliases:
            raise RuntimeError("realm %s binds %s to %r, but a flow %r already exists; bind it or remove it"
                               % (realm, binding, bound, copy))
        else:
            source = bound
        checked = copy if source is None else source
        _, executions = session.request("GET", "/admin/realms/%s/authentication/flows/%s/executions" % (r, _q(checked)))
        if not any(e.get("providerId") == password_step for e in executions):
            raise RuntimeError("flow %r (the realm's %s) has no %s step" % (checked, binding, password_step))
        plan.append((copy, binding, password_step, placement, steps, source))
    return plan


def apply_flows(session, realm, plan):
    """Copy, put the IRC steps in place, and bind, as plan_flows decided."""
    r = _q(realm)
    for copy, _, password_step, placement, steps, source in plan:
        if source is not None:
            session.request("POST", "/admin/realms/%s/authentication/flows/%s/copy" % (r, _q(source)),
                            {"newName": copy})
        if placement == LAST:
            _ensure_steps_last(session, r, copy, steps)
        else:
            after = password_step
            for step in steps:
                _ensure_step_after(session, r, copy, step, after)
                after = step
    bindings = {binding: copy for copy, binding, _, _, _, source in plan if source is not None}
    if bindings:
        session.request("PUT", "/admin/realms/%s" % r, bindings)


def ensure_flows(session, realm):
    """Copy the realm's bound direct-grant and browser flows, put the IRC steps in place, bind the copies."""
    apply_flows(session, realm, plan_flows(session, realm))


def _ensure_step_after(session, r, flow, provider, after):
    """Make `provider` a REQUIRED execution directly after the `after` execution, in the same (sub-)flow."""
    path = "/admin/realms/%s/authentication/flows/%s/executions" % (r, _q(flow))

    def find():
        _, executions = session.request("GET", path)
        anchor = next((e for e in executions if e.get("providerId") == after), None)
        if anchor is None:
            raise RuntimeError("flow %r has no %s step" % (flow, after))
        siblings = _siblings(executions, anchor)
        return anchor, next((e for e in siblings if e.get("providerId") == provider), None), executions

    anchor, step, executions = find()
    if step is None:
        session.request("POST", "/admin/realms/%s/authentication/flows/%s/executions/execution"
                        % (r, _q(_parent_alias(executions, anchor, flow))), {"provider": provider})
        anchor, step, _ = find()
    for _ in range(64):   # each move swaps the step with one neighbour
        if step["index"] == anchor["index"] + 1:
            break
        move = "raise-priority" if step["index"] > anchor["index"] else "lower-priority"
        session.request("POST", "/admin/realms/%s/authentication/executions/%s/%s" % (r, step["id"], move))
        anchor, step, _ = find()
    else:
        raise RuntimeError("could not place %s after %s in flow %r" % (provider, after, flow))
    if step["requirement"] != "REQUIRED":
        session.request("PUT", path, dict(step, requirement="REQUIRED"))


def _ensure_steps_last(session, r, flow, providers):
    """Make `providers` REQUIRED executions of `flow`, each once, as its last top-level executions, in this order.

    One inside a sub-flow (where an earlier version put it after a nested password step) is removed.
    """
    path = "/admin/realms/%s/authentication/flows/%s/executions" % (r, _q(flow))

    def top():
        _, executions = session.request("GET", path)
        return executions, [e for e in executions if e["level"] == 0]

    executions, level0 = top()
    nested = [e for e in executions if e.get("providerId") in providers and e["level"] != 0]
    missing = [p for p in providers if not any(e.get("providerId") == p for e in level0)]
    for e in nested:
        session.request("DELETE", "/admin/realms/%s/authentication/executions/%s" % (r, e["id"]))
    for provider in missing:   # a new execution is appended at the end of the flow
        session.request("POST", "%s/execution" % path, {"provider": provider})
    if nested or missing:
        executions, level0 = top()
    # Last provider first: once it is last, moving an earlier one down never passes it.
    for offset, provider in enumerate(reversed(providers), start=1):
        for _ in range(64):   # each move swaps the step with one neighbour
            step = next(e for e in level0 if e.get("providerId") == provider)
            target = len(level0) - offset
            position = level0.index(step)
            if position == target:
                break
            move = "lower-priority" if position < target else "raise-priority"
            session.request("POST", "/admin/realms/%s/authentication/executions/%s/%s" % (r, step["id"], move))
            executions, level0 = top()
        else:
            raise RuntimeError("could not place %s last in flow %r" % (provider, flow))
        if step["requirement"] != "REQUIRED":
            session.request("PUT", path, dict(step, requirement="REQUIRED"))
            executions, level0 = top()


def _siblings(executions, anchor):
    """The executions of the (sub-)flow that holds `anchor`: the listing is depth-first, with levels."""
    i = executions.index(anchor)
    level = anchor["level"]
    start = i
    while start > 0 and executions[start - 1]["level"] >= level:
        start -= 1
    end = i
    while end + 1 < len(executions) and executions[end + 1]["level"] >= level:
        end += 1
    return [e for e in executions[start:end + 1] if e["level"] == level]


def _parent_alias(executions, anchor, flow):
    """The alias of the (sub-)flow that holds `anchor`; a sub-flow is listed under its alias."""
    if anchor["level"] == 0:
        return flow
    i = executions.index(anchor)
    while executions[i]["level"] >= anchor["level"]:
        i -= 1
    return executions[i]["displayName"]


def _is_legacy_scram(name):
    return name in LEGACY_SCRAM_ATTRIBUTES or name.startswith(LEGACY_SCRAM_PREFIX)


def drop_legacy_scram_attributes(session, realm, page=100):
    """Remove the legacy SCRAM verifier attributes from every user; print and return how many users changed."""
    r = _q(realm)
    _, profile = session.request("GET", "/admin/realms/%s/users/profile" % r)
    policy = (profile or {}).get("unmanagedAttributePolicy")
    if policy not in ("ENABLED", "ADMIN_EDIT"):
        raise RuntimeError("realm %s: the unmanaged attribute policy is %s; the legacy attributes can be "
                           "removed only when it is ENABLED or ADMIN_EDIT" % (realm, policy or "off"))
    changed = 0
    first = 0
    while True:
        _, users = session.request("GET", "/admin/realms/%s/users?briefRepresentation=false&first=%d&max=%d"
                                   % (r, first, page))
        if not users:
            break
        for listed in users:
            if not any(_is_legacy_scram(k) for k in (listed.get("attributes") or {})):
                continue
            user_path = "/admin/realms/%s/users/%s" % (r, listed["id"])
            _, user = session.request("GET", user_path)
            user["attributes"] = {k: v for k, v in (user.get("attributes") or {}).items() if not _is_legacy_scram(k)}
            session.request("PUT", user_path, user)
            changed += 1
        first += len(users)
    print("removed legacy SCRAM attributes from %d user(s)" % changed)
    return changed


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", required=True)
    p.add_argument("--realm", required=True)
    p.add_argument("--admin-user", required=True)
    p.add_argument("--admin-pass-env", required=True, help="name of the environment variable holding the admin password")
    p.add_argument("--service-client", help="client whose service account gets the role")
    p.add_argument("--drop-legacy-scram-attributes", action="store_true",
                   help="remove the scram_sha256_* and x3_scram_* user attributes from every user")
    a = p.parse_args(argv)
    password = os.environ.get(a.admin_pass_env)
    if password is None:
        print("environment variable %s is not set" % a.admin_pass_env, file=sys.stderr)
        return 2
    try:
        session = Session(a.url, login(a.url, a.admin_user, password))
        flows = plan_flows(session, a.realm)   # refuses before the first write
        ensure_role(session, a.realm, a.service_client)
        ensure_required_action(session, a.realm)
        apply_flows(session, a.realm, flows)
        if a.drop_legacy_scram_attributes:
            drop_legacy_scram_attributes(session, a.realm)
    except RuntimeError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
