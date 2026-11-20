package io.github.evilnet.keycloak.irc.login;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.evilnet.keycloak.irc.scram.ScramVerifier;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class IrcCredentialSyncAuthenticatorTest {

    @Test void noCurrentVerifierNeedsOne() {
        assertTrue(IrcCredentialSyncAuthenticator.needsNewVerifier(Optional.empty(), "pencil"));
    }

    @Test void aVerifierOfThePasswordJustProvenIsKept() {
        ScramVerifier v = ScramVerifier.deriveRandom("pencil");
        assertFalse(IrcCredentialSyncAuthenticator.needsNewVerifier(Optional.of(v), "pencil"));
    }

    @Test void aVerifierOfAnotherPasswordIsReplaced() {
        ScramVerifier v = ScramVerifier.deriveRandom("pencil");
        assertTrue(IrcCredentialSyncAuthenticator.needsNewVerifier(Optional.of(v), "crayon"));
    }
}
