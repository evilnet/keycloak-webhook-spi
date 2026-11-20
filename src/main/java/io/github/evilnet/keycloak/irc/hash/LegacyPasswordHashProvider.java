package io.github.evilnet.keycloak.irc.hash;

import java.util.Base64;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

/**
 * Verify-only hash provider for a legacy algorithm.  It never produces hashes:
 * {@link #policyCheck} is always false, so Keycloak re-hashes the password to the
 * realm's policy after the first successful login.
 *
 * <p>Stored form: {@code secretData.value} is the base64 digest, {@code salt} the
 * base64 salt (empty for X3 MD5).</p>
 */
public class LegacyPasswordHashProvider implements PasswordHashProvider {

    /** Verifies a raw password against the digest and salt bytes. */
    @FunctionalInterface
    public interface Verifier {
        boolean verify(String rawPassword, byte[] digest, byte[] salt);
    }

    private final String algorithm;
    private final Verifier verifier;

    public LegacyPasswordHashProvider(String algorithm, Verifier verifier) {
        this.algorithm = algorithm;
        this.verifier = verifier;
    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
        return false;
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        throw new UnsupportedOperationException(algorithm + " is verify-only");
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        try {
            byte[] digest = Base64.getDecoder().decode(credential.getPasswordSecretData().getValue());
            byte[] salt = credential.getPasswordSecretData().getSalt();   // Keycloak decodes the base64 salt
            return verifier.verify(rawPassword, digest, salt == null ? new byte[0] : salt);
        } catch (RuntimeException e) {
            return false;   // a stored value that cannot be decoded (malformed base64, no value): does not match
        }
    }

    @Override
    public void close() {
    }
}
