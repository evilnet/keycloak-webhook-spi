package io.github.evilnet.keycloak.irc.scram;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A SCRAM-SHA-256 verifier (RFC 5802 / RFC 7677): the salt and iteration count the
 * client needs, plus the StoredKey and ServerKey the server verifies against.
 *
 * <p>The parameters used by {@link #deriveRandom} (SHA-256, 4096 iterations, 16-byte
 * salt) are in lockstep with {@code nefarious/ircd/kc/kc_cred_derive.c}: change one,
 * change both.</p>
 */
public record ScramVerifier(byte[] salt, int iterations, byte[] storedKey, byte[] serverKey) {

    public static final int ITERATIONS = 4096;
    public static final int SALT_LENGTH = 16;
    private static final int HASH_LENGTH = 32;   // SHA-256 output

    private static final SecureRandom RANDOM = new SecureRandom();

    /** SaltedPassword = PBKDF2(password, salt, i); StoredKey = H(HMAC(SP, "Client Key")); ServerKey = HMAC(SP, "Server Key"). */
    public static ScramVerifier derive(String password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, HASH_LENGTH * 8);
        try {
            byte[] salted = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
            byte[] clientKey = hmac(salted, "Client Key");
            byte[] storedKey = MessageDigest.getInstance("SHA-256").digest(clientKey);
            byte[] serverKey = hmac(salted, "Server Key");
            return new ScramVerifier(salt.clone(), iterations, storedKey, serverKey);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SCRAM derivation unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }

    public static ScramVerifier deriveRandom(String password) {
        byte[] salt = new byte[SALT_LENGTH];
        RANDOM.nextBytes(salt);
        return derive(password, salt, ITERATIONS);
    }

    private static byte[] hmac(byte[] key, String data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
    }
}
