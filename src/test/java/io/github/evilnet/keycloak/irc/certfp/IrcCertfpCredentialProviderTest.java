package io.github.evilnet.keycloak.irc.certfp;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

class IrcCertfpCredentialProviderTest {

    @Test void storedValuesInAnotherOrderNeedNoRewrite() {
        assertTrue(IrcCertfpCredentialProvider.sameValues(List.of("A", "B"), List.of("B", "A")));
        assertTrue(IrcCertfpCredentialProvider.sameValues(List.of(), List.of()));
    }

    @Test void anyOtherDifferenceNeedsARewrite() {
        assertFalse(IrcCertfpCredentialProvider.sameValues(List.of("A", "B"), List.of("A")));
        assertFalse(IrcCertfpCredentialProvider.sameValues(List.of("A"), List.of("A", "C")));
        assertFalse(IrcCertfpCredentialProvider.sameValues(List.of("A"), List.of("A", "A")));   // a duplicate is dropped
        assertFalse(IrcCertfpCredentialProvider.sameValues(List.of(), List.of("A")));
    }
}
