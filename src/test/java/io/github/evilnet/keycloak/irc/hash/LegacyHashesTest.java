package io.github.evilnet.keycloak.irc.hash;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Base64;
import org.junit.jupiter.api.Test;

class LegacyHashesTest {

    private static byte[] b64(String s) {
        return Base64.getDecoder().decode(s);
    }

    @Test void x3Md5() {
        assertTrue(LegacyHashes.verifyX3Md5("secret", b64("Xr4ilOzQ4PCOq3aQ0qbuaQ==")));
        assertFalse(LegacyHashes.verifyX3Md5("Secret", b64("Xr4ilOzQ4PCOq3aQ0qbuaQ==")));
    }

    @Test void x3Md5Latin1Password() {   // hashed from the ISO-8859-1 bytes of "pässword"
        assertTrue(LegacyHashes.verifyX3Md5("pässword", b64("ASbPH24NuiQK9MVTfKUdDg==")));
    }

    @Test void x3Md5Utf8Password() {
        assertTrue(LegacyHashes.verifyX3Md5("pässword", b64("jhhDAzoPbuUuL2GKqOu+9A==")));
    }

    @Test void aCharacterOutsideLatin1IsNotTriedAsLatin1() {
        // "p?ssword" hashed; "pěssword" would encode to the same Latin-1 bytes ('ě' becomes '?').
        assertTrue(LegacyHashes.verifyX3Md5("p?ssword", b64("wAYIWeJNIwZxIg0j5LIstw==")));
        assertFalse(LegacyHashes.verifyX3Md5("pěssword", b64("wAYIWeJNIwZxIg0j5LIstw==")));
        assertFalse(LegacyHashes.verifySsha("pěssword", sshaLatin1("p?ssword", new byte[] {1, 2, 3, 4}), new byte[] {1, 2, 3, 4}));
    }

    @Test void aLatin1PasswordTypedInUtf8StillVerifies() {   // "pässword" stored as Latin-1 bytes, typed as a Java (UTF-16) string
        assertTrue(LegacyHashes.verifySsha("pässword", sshaLatin1("pässword", new byte[] {9, 8}), new byte[] {9, 8}));
    }

    private static byte[] sshaLatin1(String password, byte[] salt) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-1");
            md.update(password.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
            md.update(salt);
            return md.digest();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test void ssha() {
        assertTrue(LegacyHashes.verifySsha("secret", b64("uJDd0BIdJ9Z7yDCZNWdgYeb33+c="), b64("AQIDBA==")));
        assertFalse(LegacyHashes.verifySsha("secret", b64("uJDd0BIdJ9Z7yDCZNWdgYeb33+c="), b64("AQIDBQ==")));
    }
}
