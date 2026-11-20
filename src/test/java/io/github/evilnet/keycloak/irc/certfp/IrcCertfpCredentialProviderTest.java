package io.github.evilnet.keycloak.irc.certfp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.evilnet.keycloak.irc.certfp.IrcCertfpCredentialProvider.Certificate;
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

    @Test void aCertificateStoredTwiceIsListedOnceUnderItsOldestName() {
        Certificate a1 = new Certificate("1", "A256", "A512", "first", 1L);
        Certificate b = new Certificate("2", "B256", "B512", "other", 2L);
        Certificate a2 = new Certificate("3", "A256", "A512", "second", 3L);
        assertEquals(List.of(a1, b), IrcCertfpCredentialProvider.oncePerCertificate(List.of(a1, b, a2)));
    }
}
