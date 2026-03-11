package net.afternet.keycloak.webhook;

import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.stream.Stream;

/**
 * Credential provider that generates SCRAM-SHA-256 credentials when passwords change.
 *
 * <p>This provider intercepts password updates (via CredentialInputUpdater) and
 * generates SCRAM credentials, storing them in user attributes. The webhook
 * listener can then include these in credential change events.</p>
 *
 * <p>User attributes stored:</p>
 * <ul>
 *   <li>x3_scram_salt - Base64-encoded salt</li>
 *   <li>x3_scram_iterations - Iteration count (4096)</li>
 *   <li>x3_scram_stored_key - Base64-encoded StoredKey</li>
 *   <li>x3_scram_server_key - Base64-encoded ServerKey</li>
 * </ul>
 *
 * <p>These attributes are NOT visible to users (configured as internal)
 * but can be read by the webhook listener.</p>
 */
public class ScramCredentialProvider implements CredentialProvider<CredentialModel>, CredentialInputUpdater {

    private static final Logger LOG = Logger.getLogger(ScramCredentialProvider.class);

    // SCRAM-SHA-256 parameters (RFC 7677)
    private static final int SCRAM_ITERATIONS = 4096;
    private static final int SALT_LENGTH = 16;  // 128 bits
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int HASH_LENGTH = 32;  // SHA-256 output

    // User attribute names
    public static final String ATTR_SCRAM_SALT = "x3_scram_salt";
    public static final String ATTR_SCRAM_ITERATIONS = "x3_scram_iterations";
    public static final String ATTR_SCRAM_STORED_KEY = "x3_scram_stored_key";
    public static final String ATTR_SCRAM_SERVER_KEY = "x3_scram_server_key";

    private final KeycloakSession session;

    public ScramCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getType() {
        // Return our own type ID - NOT "password"!
        // By returning "password" we were interfering with credential imports via Admin API.
        // We only want to intercept password CHANGES via CredentialInputUpdater,
        // not manage password credentials directly.
        return ScramCredentialProviderFactory.PROVIDER_ID;  // "x3-scram-sha256"
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext context) {
        // Return null - we don't provide our own credential type UI
        return null;
    }

    // ========== CredentialInputUpdater interface ==========

    @Override
    public boolean supportsCredentialType(String credentialType) {
        // We want to intercept password updates
        return PasswordCredentialModel.TYPE.equals(credentialType);
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        // This is called when a password is being set/updated
        if (!supportsCredentialType(input.getType())) {
            return false;
        }

        // Get the raw password from the input
        String rawPassword = input.getChallengeResponse();
        if (rawPassword == null || rawPassword.isEmpty()) {
            LOG.debug("No password in credential input, skipping SCRAM generation");
            return false;  // Don't consume - let default handler process
        }

        try {
            // Generate SCRAM credentials
            ScramCredentials scram = generateScramSha256(rawPassword);

            // Store in user attributes
            user.setSingleAttribute(ATTR_SCRAM_SALT, scram.saltBase64);
            user.setSingleAttribute(ATTR_SCRAM_ITERATIONS, String.valueOf(scram.iterations));
            user.setSingleAttribute(ATTR_SCRAM_STORED_KEY, scram.storedKeyBase64);
            user.setSingleAttribute(ATTR_SCRAM_SERVER_KEY, scram.serverKeyBase64);

            LOG.infof("Generated SCRAM-SHA-256 credentials for user %s", user.getUsername());
        } catch (Exception e) {
            LOG.warnf("Failed to generate SCRAM credentials for user %s: %s",
                user.getUsername(), e.getMessage());
            // Don't fail the password change - SCRAM is optional enhancement
        }

        // Return false to NOT consume the input - let the default password provider handle storage
        return false;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        if (PasswordCredentialModel.TYPE.equals(credentialType)) {
            // Remove SCRAM attributes when password is disabled
            user.removeAttribute(ATTR_SCRAM_SALT);
            user.removeAttribute(ATTR_SCRAM_ITERATIONS);
            user.removeAttribute(ATTR_SCRAM_STORED_KEY);
            user.removeAttribute(ATTR_SCRAM_SERVER_KEY);
            LOG.debugf("Removed SCRAM credentials for user %s", user.getUsername());
        }
    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream(RealmModel realm, UserModel user) {
        // We don't manage disableable credential types
        return Stream.empty();
    }

    // ========== CredentialProvider interface (minimal implementation) ==========
    // These methods are required by the interface but we don't manage credentials directly.
    // Our type is "x3-scram-sha256" so these won't be called for password operations.

    @Override
    public CredentialModel getCredentialFromModel(CredentialModel model) {
        return null;  // We don't manage credentials directly
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, CredentialModel credential) {
        return null;  // We don't create credentials directly - x3-scram-sha256 type is never imported
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        return false;  // We don't delete credentials directly
    }

    // ========== SCRAM Generation ==========

    /**
     * Generate SCRAM-SHA-256 credentials from a password.
     *
     * <p>Implements RFC 5802 (SCRAM) and RFC 7677 (SCRAM-SHA-256):</p>
     * <pre>
     * SaltedPassword := PBKDF2(password, salt, iterations, hash_length)
     * ClientKey := HMAC(SaltedPassword, "Client Key")
     * StoredKey := H(ClientKey)
     * ServerKey := HMAC(SaltedPassword, "Server Key")
     * </pre>
     */
    private ScramCredentials generateScramSha256(String password) throws Exception {
        // Generate random salt
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);

        // Derive SaltedPassword using PBKDF2
        byte[] saltedPassword = pbkdf2(password, salt, SCRAM_ITERATIONS, HASH_LENGTH);

        // Compute ClientKey and StoredKey
        byte[] clientKey = hmacSha256(saltedPassword, "Client Key".getBytes(StandardCharsets.UTF_8));
        byte[] storedKey = sha256(clientKey);

        // Compute ServerKey
        byte[] serverKey = hmacSha256(saltedPassword, "Server Key".getBytes(StandardCharsets.UTF_8));

        return new ScramCredentials(
            Base64.getEncoder().encodeToString(salt),
            SCRAM_ITERATIONS,
            Base64.getEncoder().encodeToString(storedKey),
            Base64.getEncoder().encodeToString(serverKey)
        );
    }

    /**
     * PBKDF2 key derivation.
     */
    private byte[] pbkdf2(String password, byte[] salt, int iterations, int keyLength)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(
            password.toCharArray(),
            salt,
            iterations,
            keyLength * 8  // bits
        );
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        return factory.generateSecret(spec).getEncoded();
    }

    /**
     * HMAC-SHA-256.
     */
    private byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
        return mac.doFinal(data);
    }

    /**
     * SHA-256 hash.
     */
    private byte[] sha256(byte[] data) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    /**
     * Container for SCRAM credential components.
     */
    private static class ScramCredentials {
        final String saltBase64;
        final int iterations;
        final String storedKeyBase64;
        final String serverKeyBase64;

        ScramCredentials(String saltBase64, int iterations,
                        String storedKeyBase64, String serverKeyBase64) {
            this.saltBase64 = saltBase64;
            this.iterations = iterations;
            this.storedKeyBase64 = storedKeyBase64;
            this.serverKeyBase64 = serverKeyBase64;
        }
    }

    @Override
    public void close() {
        // Nothing to close
    }
}
