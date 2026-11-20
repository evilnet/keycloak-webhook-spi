package io.github.evilnet.keycloak.irc.certfp;

import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * The forms a certificate credential accepts: a certificate's SHA-256 and SHA-512 (of its DER),
 * uppercase hex without separators, and the name a user gives it.  Pure validation, no Keycloak types.
 */
public final class Fingerprints {

    /** Longest name, in bytes of UTF-8. */
    public static final int MAX_NAME_BYTES = 64;

    private static final Pattern SHA256 = Pattern.compile("[0-9A-F]{64}");
    private static final Pattern SHA512 = Pattern.compile("[0-9A-F]{128}");

    private Fingerprints() {
    }

    /** 64 uppercase hex characters. */
    public static boolean wellFormedSha256(String v) {
        return v != null && SHA256.matcher(v).matches();
    }

    /** 128 uppercase hex characters. */
    public static boolean wellFormedSha512(String v) {
        return v != null && SHA512.matcher(v).matches();
    }

    /** 1 to {@value #MAX_NAME_BYTES} bytes of UTF-8 (a lone surrogate is not UTF-8), no control characters (C0, DEL, C1). */
    public static boolean acceptableName(String v) {
        if (v == null || v.isEmpty() || v.length() > MAX_NAME_BYTES) {
            return false;   // every character is at least one byte
        }
        if (v.chars().anyMatch(Character::isISOControl)) {
            return false;
        }
        try {
            int bytes = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(v)).remaining();
            return bytes <= MAX_NAME_BYTES;
        } catch (CharacterCodingException e) {
            return false;
        }
    }
}
