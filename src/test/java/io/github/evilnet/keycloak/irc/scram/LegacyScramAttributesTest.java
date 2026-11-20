package io.github.evilnet.keycloak.irc.scram;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class LegacyScramAttributesTest {

    // RFC 7677 vector: password "pencil", salt W22ZaJ0SNY7soEsUEjb6gQ==, 4096 iterations.
    private static Map<String, String> pencil(String family) {
        Map<String, String> m = new HashMap<>();
        m.put(family + "salt", "W22ZaJ0SNY7soEsUEjb6gQ==");
        m.put(family + "iterations", "4096");
        m.put(family + "stored_key", "WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=");
        m.put(family + "server_key", "wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=");
        return m;
    }

    @Test void aVerifierOfThePasswordMatches() {
        assertTrue(LegacyScramAttributes.matches(pencil("scram_sha256_"), "scram_sha256_", "pencil"));
    }

    @Test void anotherPasswordDoesNotMatch() {
        assertFalse(LegacyScramAttributes.matches(pencil("scram_sha256_"), "scram_sha256_", "crayon"));
    }

    @Test void aWrongServerKeyDoesNotMatch() {
        Map<String, String> m = pencil("scram_sha256_");
        m.put("scram_sha256_server_key", "WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=");
        assertFalse(LegacyScramAttributes.matches(m, "scram_sha256_", "pencil"));
    }

    @Test void unparsableOrIncompleteSetsDoNotMatch() {
        for (String[] bad : new String[][] {
                {"scram_sha256_iterations", "many"}, {"scram_sha256_iterations", "0"},
                {"scram_sha256_iterations", "100000000"}, {"scram_sha256_salt", "!!not base64"},
                {"scram_sha256_salt", ""}, {"scram_sha256_stored_key", "%%"}}) {
            Map<String, String> m = pencil("scram_sha256_");
            m.put(bad[0], bad[1]);
            assertFalse(LegacyScramAttributes.matches(m, "scram_sha256_", "pencil"), bad[0] + "=" + bad[1]);
        }
        Map<String, String> missing = pencil("scram_sha256_");
        missing.remove("scram_sha256_server_key");
        assertFalse(LegacyScramAttributes.matches(missing, "scram_sha256_", "pencil"));
    }

    @Test void aLoginRemovesOnlyTheFamiliesThatAreNotVerifiersOfThePassword() {
        Map<String, String> m = pencil("scram_sha256_");
        m.putAll(pencil("x3_scram_sha256_"));
        Map<String, String> other = pencil("x3_scram_");
        other.put("x3_scram_stored_key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        m.putAll(other);
        m.put("x3_scram_salt_partial_only_family_member", "ignored");   // not a name any server reads
        List<String> stale = LegacyScramAttributes.staleAfterLogin(m, "pencil");
        assertEquals(List.of("x3_scram_salt", "x3_scram_iterations", "x3_scram_stored_key", "x3_scram_server_key"), stale);
        assertEquals(12, LegacyScramAttributes.staleAfterLogin(m, "crayon").size());   // all three families
    }

    @Test void anIncompleteFamilyIsRemovedOnLogin() {
        Map<String, String> m = new HashMap<>();
        m.put("scram_sha256_salt", "W22ZaJ0SNY7soEsUEjb6gQ==");
        assertEquals(List.of("scram_sha256_salt"), LegacyScramAttributes.staleAfterLogin(m, "pencil"));
    }

    @Test void passwordSetRemovesEveryLegacyName() {
        assertTrue(LegacyScramAttributes.isLegacy("scram_sha256_stored_key"));
        assertTrue(LegacyScramAttributes.isLegacy("x3_scram_salt"));
        assertTrue(LegacyScramAttributes.isLegacy("x3_scram_sha256_server_key"));
        assertFalse(LegacyScramAttributes.isLegacy("scram_sha256_other"));
        assertFalse(LegacyScramAttributes.isLegacy("x3_opserv_level"));
    }
}
