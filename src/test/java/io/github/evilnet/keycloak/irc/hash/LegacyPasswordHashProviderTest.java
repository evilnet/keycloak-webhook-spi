package io.github.evilnet.keycloak.irc.hash;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.keycloak.models.credential.PasswordCredentialModel;

class LegacyPasswordHashProviderTest {

    private final LegacyPasswordHashProvider md5 = (LegacyPasswordHashProvider) new X3Md5PasswordHashProviderFactory().create(null);

    private static PasswordCredentialModel stored(String value) {
        return PasswordCredentialModel.createFromValues(X3Md5PasswordHashProviderFactory.PROVIDER_ID, new byte[0], 1, value);
    }

    @Test void aGoodHashVerifies() {
        assertTrue(md5.verify("secret", stored("Xr4ilOzQ4PCOq3aQ0qbuaQ==")));
        assertFalse(md5.verify("Secret", stored("Xr4ilOzQ4PCOq3aQ0qbuaQ==")));
    }

    @Test void aGarbageStoredValueDoesNotMatch() {
        assertFalse(md5.verify("secret", stored("%%% not base64 %%%")));
        assertFalse(md5.verify("secret", stored(null)));   // no value at all: decoding it fails with a NullPointerException
    }
}
