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

    @Test void ssha() {
        assertTrue(LegacyHashes.verifySsha("secret", b64("uJDd0BIdJ9Z7yDCZNWdgYeb33+c="), b64("AQIDBA==")));
        assertFalse(LegacyHashes.verifySsha("secret", b64("uJDd0BIdJ9Z7yDCZNWdgYeb33+c="), b64("AQIDBQ==")));
    }
}
