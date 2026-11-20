#!/usr/bin/env python3
"""Idempotent set-up of a Keycloak realm for the IRC credentials SPI.  Standard library only.

    irc_realm_setup.py --url U --realm R --admin-user A --admin-pass-env VAR [--service-client CLIENT]

Creates the realm role `irc-read-credentials` that GET /realms/R/irc/credentials/{username}
requires and, with --service-client, grants it to that client's service account.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

ROLE = "irc-read-credentials"


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


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", required=True)
    p.add_argument("--realm", required=True)
    p.add_argument("--admin-user", required=True)
    p.add_argument("--admin-pass-env", required=True, help="name of the environment variable holding the admin password")
    p.add_argument("--service-client", help="client whose service account gets the role")
    a = p.parse_args(argv)
    password = os.environ.get(a.admin_pass_env)
    if password is None:
        print("environment variable %s is not set" % a.admin_pass_env, file=sys.stderr)
        return 2
    try:
        session = Session(a.url, login(a.url, a.admin_user, password))
        ensure_role(session, a.realm, a.service_client)
    except RuntimeError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
