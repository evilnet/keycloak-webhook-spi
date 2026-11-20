#!/usr/bin/env python3
"""Load the password hashes of an LDAP directory (an LDIF export) into Keycloak.  Standard library only.

    import_ldap_hashes.py --ldif FILE --url U --realm R --admin-user A --admin-pass-env VAR [--uid-attr uid]
                          [--apply] [--allow-linked]

For each entry of the LDIF file, finds the Keycloak user of that name and, when the entry's
`userPassword` is a {MD5} or {SSHA} hash and the user has no password yet, loads it through the admin
API in the form the jar's `x3-md5` and `ldap-ssha` hash providers verify; the user logs in with the
original password, and Keycloak re-hashes it to the realm's policy at that first login.

Without --apply nothing is changed: the tool only reports what it would do.  Run it that way first.

Run it after the users are unlinked from the LDAP provider (Keycloak's "Unlink users", which keeps the
accounts and their ids) and the provider is removed.  A user still linked to a user-storage provider is
not loaded (outcome `linked`) unless --allow-linked is given.  Loading a linked user freezes their
password: Keycloak asks the directory only for a user with no local password, so from then on a
password changed in the directory is refused and the old one still logs in; a password reset through
Keycloak answers 204, yet the new password is refused and the old one still logs in; a later run
reports `already-has-password`, so it cannot refresh the hash; and the user's SCRAM verifier is not
served until their next password login.

Prints one line per outcome with its count:
  loaded (would-load without --apply)   the hash was loaded
  linked                                the user is still linked to a user-storage provider (LDAP);
                                        not loaded (see --allow-linked)
  already-has-password                  the user has a password credential; left alone
  no-such-user                          no Keycloak user of that name
  no-password                           the entry has no userPassword
  unsupported:<scheme>                  another scheme, no scheme, a malformed {MD5}/{SSHA} value
                                        (unsupported:{MD5}(malformed)), or several values
                                        (unsupported:(several values))
  failed                                the admin API refused this user; the reason is printed on
                                        standard error, by user name, and the run goes on

Exit status: 0 when no user failed; 1 when at least one user failed; 2 on a usage error or when the
admin login or the connection fails (the counts of what was done until then are printed first).
The admin token is renewed during the run, so a large file is not cut off by the token's lifespan.
A hash is never printed, and the admin password is read from the environment variable named by
--admin-pass-env.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import sys
import urllib.parse
from typing import Optional

from irc_realm_setup import Session

NO_SCHEME = "(no scheme prefix)"
LABEL = "ldap-import"
_SCHEME = re.compile(r"^\{[^}]*\}")
_SHA1_LEN = 20


class _Several(str):
    """The password of an entry with several userPassword values: never a hash, never guessed at."""


SEVERAL = _Several("(several values)")


def _unfold(text: str) -> list:
    lines = []
    for line in re.split(r"\r\n|\n|\r", text.lstrip("﻿")):
        if line.startswith(" ") and lines:
            lines[-1] += line[1:]
        else:
            lines.append(line)
    return lines


def parse_ldif(text: str, uid_attr: str = "uid") -> list:
    """[(username, decoded userPassword or None)] of the entries that have `uid_attr`, in file order.

    Handles `name: value` and base64 `name:: value`, folded lines, comments, CRLF and a version line;
    attribute names are case-insensitive.  An entry with several userPassword values gets SEVERAL.
    """
    uid_attr = uid_attr.lower()
    out = []
    entries = [[]]
    for line in _unfold(text):
        if line.startswith("#"):
            continue
        if line.strip() == "":
            entries.append([])
        else:
            entries[-1].append(line)
    for lines in entries:
        uids, passwords = [], []
        for line in lines:
            name, sep, rest = line.partition(":")
            if not sep:
                continue
            name = name.split(";", 1)[0].strip().lower()
            if name not in (uid_attr, "userpassword"):
                continue
            if rest.startswith(":"):
                try:
                    raw = base64.b64decode(rest[1:].strip())
                except (binascii.Error, ValueError):
                    continue
                try:
                    value = raw.decode("utf-8")
                except UnicodeDecodeError:
                    value = raw.decode("latin-1")
            elif rest.startswith("<"):
                continue    # a URL value: not something to load
            else:
                value = rest.lstrip(" ")
            (uids if name == uid_attr else passwords).append(value)
        if not uids:
            continue
        out.append((uids[0], SEVERAL if len(passwords) > 1 else (passwords[0] if passwords else None)))
    return out


def scheme_of(user_password: str) -> str:
    """"{MD5}", "{SSHA}" (any case), another {...} verbatim, "(several values)", or "(no scheme prefix)"."""
    if isinstance(user_password, _Several):
        return str(SEVERAL)
    m = _SCHEME.match(user_password)
    if not m:
        return NO_SCHEME
    s = m.group(0)
    return s.upper() if s.upper() in ("{MD5}", "{SSHA}") else s


def _b64(s: str) -> Optional[bytes]:
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def to_credential(user_password: str) -> Optional[dict]:
    """The admin-API credential of a well-formed {MD5} or {SSHA} value, else None."""
    scheme = scheme_of(user_password)
    if scheme not in ("{MD5}", "{SSHA}"):
        return None
    body = user_password[len(scheme):]
    raw = _b64(body)
    if scheme == "{MD5}":
        if raw is None or len(raw) != 16:
            return None
        algorithm, secret = "x3-md5", {"value": body, "salt": ""}
    else:
        if raw is None or len(raw) <= _SHA1_LEN:
            return None
        algorithm = "ldap-ssha"
        secret = {"value": base64.b64encode(raw[:_SHA1_LEN]).decode(),
                  "salt": base64.b64encode(raw[_SHA1_LEN:]).decode()}
    return {"type": "password", "userLabel": LABEL,
            "credentialData": json.dumps({"hashIterations": 1, "algorithm": algorithm}),
            "secretData": json.dumps(secret)}


def classify(user_password: Optional[str]) -> Optional[str]:
    """The outcome that needs no Keycloak lookup (no-password, unsupported:...), None when loadable."""
    if user_password is None:
        return "no-password"
    if to_credential(user_password) is None:
        scheme = scheme_of(user_password)
        return "unsupported:" + scheme + ("(malformed)" if scheme in ("{MD5}", "{SSHA}") else "")
    return None


def process_user(session, realm, name, user_password, apply, allow_linked=False):
    """The outcome for one LDIF entry; loads the hash when `apply`.  Raises RuntimeError on an API refusal.

    A user linked to a user-storage provider (a non-empty `federationLink`) is `linked` and left alone
    unless `allow_linked`.
    """
    r = urllib.parse.quote(realm, safe="")
    _, users = session.request("GET", "/admin/realms/%s/users?username=%s&exact=true"
                               % (r, urllib.parse.quote(name, safe="")))
    user = next((u for u in users if u.get("username", "").lower() == name.lower()), None)
    if user is None:
        return "no-such-user"
    early = classify(user_password)
    if early:
        return early
    if user.get("federationLink") and not allow_linked:
        return "linked"
    _, creds = session.request("GET", "/admin/realms/%s/users/%s/credentials" % (r, user["id"]))
    if any(c.get("type") == "password" and c.get("credentialData") for c in creds):
        return "already-has-password"
    if not apply:
        return "would-load"
    session.request("PUT", "/admin/realms/%s/users/%s" % (r, user["id"]),
                    dict(user, credentials=[to_credential(user_password)]))
    return "loaded"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ldif", required=True, help="LDIF export of the directory")
    p.add_argument("--url", required=True)
    p.add_argument("--realm", required=True)
    p.add_argument("--admin-user", required=True)
    p.add_argument("--admin-pass-env", required=True, help="name of the environment variable holding the admin password")
    p.add_argument("--uid-attr", default="uid", help="the LDIF attribute holding the user name (default uid)")
    p.add_argument("--apply", action="store_true", help="load the hashes (without it nothing is changed)")
    p.add_argument("--allow-linked", action="store_true",
                   help="also load users still linked to a user-storage provider (LDAP); this freezes their "
                        "password: changes made in the directory or through Keycloak no longer take effect, "
                        "and a later run cannot refresh the hash")
    a = p.parse_args(argv)
    password = os.environ.get(a.admin_pass_env)
    if password is None:
        print("environment variable %s is not set" % a.admin_pass_env, file=sys.stderr)
        return 2
    try:
        with open(a.ldif, encoding="utf-8") as f:
            entries = parse_ldif(f.read(), a.uid_attr)
    except (OSError, UnicodeDecodeError) as e:
        print("error: cannot read %s: %s" % (a.ldif, e.__class__.__name__), file=sys.stderr)
        return 2
    counts = {}
    done = "loaded" if a.apply else "would-load"

    def summary():
        counts.setdefault(done, 0)
        for outcome in sorted(counts):
            print("%s %d" % (outcome, counts[outcome]))

    try:
        session = Session(a.url, a.admin_user, password)
        for name, user_password in entries:
            try:
                outcome = process_user(session, a.realm, name, user_password, a.apply, a.allow_linked)
            except (RuntimeError, ValueError, KeyError) as e:
                print("error: user %s: %s" % (name, e), file=sys.stderr)
                outcome = "failed"
            counts[outcome] = counts.get(outcome, 0) + 1
    except (RuntimeError, OSError) as e:   # the admin login, or the connection (urllib's URLError is an OSError)
        print("error: %s" % (e,), file=sys.stderr)
        if counts:
            print("stopped after %d of %d entries; counts so far:" % (sum(counts.values()), len(entries)))
            summary()
        return 2
    summary()
    return 1 if counts.get("failed") else 0


if __name__ == "__main__":
    sys.exit(main())
