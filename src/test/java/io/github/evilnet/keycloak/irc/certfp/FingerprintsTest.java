package io.github.evilnet.keycloak.irc.certfp;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class FingerprintsTest {

    @Test void fingerprints() {
        assertTrue(Fingerprints.wellFormedSha256("A".repeat(64)));
        assertFalse(Fingerprints.wellFormedSha256("a".repeat(64)));
        assertFalse(Fingerprints.wellFormedSha256("AA:".repeat(31) + "AA"));
        assertFalse(Fingerprints.wellFormedSha256("A".repeat(128)));
        assertTrue(Fingerprints.wellFormedSha512("B".repeat(128)));
        assertFalse(Fingerprints.wellFormedSha512("B".repeat(64)));
        assertFalse(Fingerprints.wellFormedSha512(null));
    }

    @Test void names() {
        assertTrue(Fingerprints.acceptableName("senpai on linux!! 😊"));
        assertFalse(Fingerprints.acceptableName(""));
        assertFalse(Fingerprints.acceptableName("x".repeat(65)));
        assertFalse(Fingerprints.acceptableName("bad\nname"));
    }

    @Test void nameLimitsAreInUtf8Bytes() {
        assertTrue(Fingerprints.acceptableName("x".repeat(64)));
        assertTrue(Fingerprints.acceptableName("é".repeat(32)));    // 64 bytes
        assertFalse(Fingerprints.acceptableName("é".repeat(33)));   // 66 bytes, 33 characters
        assertFalse(Fingerprints.acceptableName(null));
        assertFalse(Fingerprints.acceptableName("tab\there"));
        assertFalse(Fingerprints.acceptableName("del\u007f"));
        assertFalse(Fingerprints.acceptableName("c1\u0085"));
        assertFalse(Fingerprints.acceptableName("lone \uD83D surrogate"));
    }
}
