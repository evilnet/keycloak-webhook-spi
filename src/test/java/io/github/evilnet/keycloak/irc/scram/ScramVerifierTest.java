package io.github.evilnet.keycloak.irc.scram;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Base64;
import org.junit.jupiter.api.Test;

class ScramVerifierTest {

    private static byte[] b64(String s) {
        return Base64.getDecoder().decode(s);
    }

    private static String enc(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    @Test void rfc7677Vector() {   // password "pencil", salt W22ZaJ0SNY7soEsUEjb6gQ==, 4096
        ScramVerifier v = ScramVerifier.derive("pencil", b64("W22ZaJ0SNY7soEsUEjb6gQ=="), 4096);
        assertEquals("WG5d8oPm3OtcPnkdi4Uo7BkeZkBFzpcXkuLmtbsT4qY=", enc(v.storedKey()));
        assertEquals("wfPLwcE6nTWhTAmQ7tl2KeoiWGPlZqQxSrmfPwDl2dU=", enc(v.serverKey()));
    }

    @Test void randomUsesLockstepParameters() {
        ScramVerifier v = ScramVerifier.deriveRandom("x");
        assertEquals(16, v.salt().length);
        assertEquals(4096, v.iterations());
    }
}
