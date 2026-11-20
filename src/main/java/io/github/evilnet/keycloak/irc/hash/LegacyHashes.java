package io.github.evilnet.keycloak.irc.hash;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Verification of the password hashes of the retired directories: X3's unsalted
 * MD5 and OpenLDAP's salted SHA-1 ({SSHA}).  Pure logic, no Keycloak types.
 *
 * <p>A legacy password with non-ASCII characters may have been hashed from its
 * ISO-8859-1 bytes or its UTF-8 bytes, so both are tried.  Digests are compared
 * in constant time.</p>
 */
public final class LegacyHashes {

    private static final Charset[] CHARSETS = { StandardCharsets.UTF_8, StandardCharsets.ISO_8859_1 };

    private LegacyHashes() {
    }

    /** MD5 over the raw password bytes, no salt. */
    public static boolean verifyX3Md5(String rawPassword, byte[] digest) {
        return verify("MD5", rawPassword, digest, new byte[0]);
    }

    /** SHA-1 over the password bytes followed by the salt bytes. */
    public static boolean verifySsha(String rawPassword, byte[] digest, byte[] salt) {
        return verify("SHA-1", rawPassword, digest, salt == null ? new byte[0] : salt);
    }

    private static boolean verify(String algorithm, String rawPassword, byte[] digest, byte[] salt) {
        if (rawPassword == null || digest == null) {
            return false;
        }
        boolean ok = false;
        for (Charset cs : CHARSETS) {
            try {
                MessageDigest md = MessageDigest.getInstance(algorithm);
                md.update(rawPassword.getBytes(cs));
                md.update(salt);
                // No short-circuit: both charsets are always evaluated.
                ok |= MessageDigest.isEqual(md.digest(), digest);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(algorithm + " is not available", e);
            }
        }
        return ok;
    }
}
