package net.afternet.keycloak.webhook;

import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PolicyError;

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

/**
 * Password policy provider that generates SCRAM-SHA-256 credentials.
 *
 * <p>This provider hooks into the password validation flow to generate
 * SCRAM credentials when passwords are set through Keycloak's UI/API.
 * Unlike CredentialProvider, password policies only run during interactive
 * password changes, NOT during Admin API credential imports with pre-hashed
 * values. This makes it safe to use alongside X3's PBKDF2 credential sync.</p>
 *
 * <p>The generated SCRAM credentials are stored in user attributes:</p>
 * <ul>
 *   <li>x3_scram_salt - Base64-encoded salt</li>
 *   <li>x3_scram_iterations - Iteration count (4096)</li>
 *   <li>x3_scram_stored_key - Base64-encoded StoredKey</li>
 *   <li>x3_scram_server_key - Base64-encoded ServerKey</li>
 * </ul>
 *
 * <p>The WebhookEventListener then includes these in password change events
 * so X3 can update its SCRAM cache.</p>
 */
public class ScramPasswordPolicyProvider implements PasswordPolicyProvider {

    private static final Logger LOG = Logger.getLogger(ScramPasswordPolicyProvider.class);

    // SCRAM-SHA-256 parameters (RFC 7677)
    private static final int SCRAM_ITERATIONS = 4096;
    private static final int SALT_LENGTH = 16;  // 128 bits
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int HASH_LENGTH = 32;  // SHA-256 output

    // User attribute names (same as ScramCredentialProvider for compatibility)
    public static final String ATTR_SCRAM_SALT = "x3_scram_salt";
    public static final String ATTR_SCRAM_ITERATIONS = "x3_scram_iterations";
    public static final String ATTR_SCRAM_STORED_KEY = "x3_scram_stored_key";
    public static final String ATTR_SCRAM_SERVER_KEY = "x3_scram_server_key";

    private final KeycloakSession session;

    public ScramPasswordPolicyProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
        // Always return null (no error) - we're not validating, just generating SCRAM
        // Generate SCRAM credentials as a side effect of "validation"

        if (password == null || password.isEmpty()) {
            return null;
        }

        try {
            generateAndStoreScram(user, password);
            LOG.infof("Generated SCRAM-SHA-256 credentials for user %s", user.getUsername());
        } catch (Exception e) {
            // Don't fail the password change - SCRAM is optional enhancement
            LOG.warnf("Failed to generate SCRAM credentials for user %s: %s",
                user.getUsername(), e.getMessage());
        }

        return null;  // No policy error - password is valid
    }

    @Override
    public PolicyError validate(String user, String password) {
        // This overload is called when we don't have a UserModel
        // Can't store attributes without the user, so just pass
        return null;
    }

    @Override
    public Object parseConfig(String value) {
        // No configuration needed
        return null;
    }

    @Override
    public void close() {
        // Nothing to close
    }

    /**
     * Generate SCRAM credentials and store in user attributes.
     */
    private void generateAndStoreScram(UserModel user, String password) throws Exception {
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

        // Store in user attributes
        user.setSingleAttribute(ATTR_SCRAM_SALT, Base64.getEncoder().encodeToString(salt));
        user.setSingleAttribute(ATTR_SCRAM_ITERATIONS, String.valueOf(SCRAM_ITERATIONS));
        user.setSingleAttribute(ATTR_SCRAM_STORED_KEY, Base64.getEncoder().encodeToString(storedKey));
        user.setSingleAttribute(ATTR_SCRAM_SERVER_KEY, Base64.getEncoder().encodeToString(serverKey));
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
}
