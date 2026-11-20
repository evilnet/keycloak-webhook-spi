import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from import_ldap_hashes import parse_ldif, scheme_of, to_credential  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
