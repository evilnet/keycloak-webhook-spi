package io.github.evilnet.keycloak.irc.ecdsa;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

/**
 * Normalises a user's ECDSA P-256 public key (the key of SASL ECDSA-NIST256P-CHALLENGE) to one
 * canonical PEM, the form the ircd's {@code PEM_read_bio_PUBKEY} reads.
 *
 * <p>Accepted, with surrounding whitespace ignored: a PEM {@code PUBLIC KEY} block; base64 of the
 * DER SubjectPublicKeyInfo; base64 of the raw point, compressed (33 bytes) or uncompressed
 * (65 bytes), as {@code ecdsatool pubkey} prints it.  Anything else is refused, a valid key on
 * another curve and a point that is not on P-256 included.  Pure key handling, no Keycloak types.</p>
 */
public final class EcdsaPublicKeys {

    /** Longest input looked at; a P-256 key in any accepted form is under 200 characters. */
    public static final int MAX_INPUT = 1024;

    private static final String BEGIN = "-----BEGIN PUBLIC KEY-----";
    private static final String END = "-----END PUBLIC KEY-----";
    private static final int COORDINATE = 32;   // bytes in a P-256 coordinate
    /** DER header of a named-curve P-256 SubjectPublicKeyInfo whose BIT STRING holds an uncompressed point. */
    private static final byte[] SPKI_PREFIX = HexFormat.of().parseHex("3059301306072a8648ce3d020106082a8648ce3d030107034200");
    private static final ECParameterSpec P256 = p256();

    private EcdsaPublicKeys() {
    }

    /** The canonical PEM of the P-256 public key in {@code input}; {@link IllegalArgumentException} for anything else. */
    public static String toPem(String input) {
        if (input == null) {
            throw new IllegalArgumentException("no key");
        }
        if (input.length() > MAX_INPUT) {
            throw new IllegalArgumentException("input too long for a P-256 public key");
        }
        String s = input.strip();
        byte[] der;
        if (s.startsWith(BEGIN)) {
            if (s.length() < BEGIN.length() + END.length() || !s.endsWith(END)) {
                throw new IllegalArgumentException("unterminated PEM block");
            }
            der = base64(s.substring(BEGIN.length(), s.length() - END.length()).replaceAll("\\s", ""));
        } else {
            byte[] bytes = base64(s);
            der = isRawPoint(bytes) ? concat(SPKI_PREFIX, uncompressed(bytes)) : bytes;
        }
        byte[] canonical = validate(der);
        return BEGIN + "\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(canonical)
                + "\n" + END + "\n";
    }

    private static boolean isRawPoint(byte[] b) {
        return (b.length == 1 + COORDINATE && (b[0] == 0x02 || b[0] == 0x03))
                || (b.length == 1 + 2 * COORDINATE && b[0] == 0x04);
    }

    /** The uncompressed form of a raw point; a compressed one gets its Y from the curve equation. */
    private static byte[] uncompressed(byte[] point) {
        if (point[0] == 0x04) {
            return point;
        }
        BigInteger p = prime();
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(point, 1, point.length));
        if (x.compareTo(p) >= 0) {
            throw new IllegalArgumentException("coordinate out of range");
        }
        BigInteger rhs = rightHandSide(x);
        BigInteger y = rhs.modPow(p.add(BigInteger.ONE).shiftRight(2), p);   // p = 3 (mod 4)
        if (!y.multiply(y).mod(p).equals(rhs)) {
            throw new IllegalArgumentException("no point on P-256 with this X");
        }
        if (y.testBit(0) != (point[0] == 0x03)) {
            y = p.subtract(y).mod(p);
        }
        return concat(new byte[] {0x04}, concat(fixed(x), fixed(y)));
    }

    /**
     * Decodes the SubjectPublicKeyInfo with the JDK, then checks it is a P-256 key whose point is on
     * the curve and that the input was exactly its DER (no trailing bytes); returns that DER.
     */
    private static byte[] validate(byte[] der) {
        PublicKey key;
        try {
            key = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));
        } catch (GeneralSecurityException | RuntimeException e) {
            throw new IllegalArgumentException("not an EC public key");
        }
        if (!(key instanceof ECPublicKey ec) || !isP256(ec.getParams())) {
            throw new IllegalArgumentException("not a P-256 public key");
        }
        if (!onCurve(ec.getW())) {
            throw new IllegalArgumentException("point not on P-256");
        }
        byte[] canonical = ec.getEncoded();
        if (!Arrays.equals(canonical, der)) {
            throw new IllegalArgumentException("not a canonical P-256 SubjectPublicKeyInfo");
        }
        return canonical;
    }

    private static boolean isP256(ECParameterSpec spec) {
        return spec != null
                && spec.getCurve().equals(P256.getCurve())
                && spec.getGenerator().equals(P256.getGenerator())
                && spec.getOrder().equals(P256.getOrder())
                && spec.getCofactor() == P256.getCofactor();
    }

    /** y^2 = x^3 + ax + b (mod p), with both coordinates in [0, p); the point at infinity is not a key. */
    private static boolean onCurve(ECPoint w) {
        if (w == null || ECPoint.POINT_INFINITY.equals(w)) {
            return false;
        }
        BigInteger p = prime();
        BigInteger x = w.getAffineX();
        BigInteger y = w.getAffineY();
        if (x.signum() < 0 || y.signum() < 0 || x.compareTo(p) >= 0 || y.compareTo(p) >= 0) {
            return false;
        }
        return y.multiply(y).mod(p).equals(rightHandSide(x));
    }

    private static BigInteger rightHandSide(BigInteger x) {
        BigInteger p = prime();
        return x.pow(3).add(P256.getCurve().getA().multiply(x)).add(P256.getCurve().getB()).mod(p);
    }

    private static BigInteger prime() {
        return ((ECFieldFp) P256.getCurve().getField()).getP();
    }

    /** {@code v} as exactly {@value #COORDINATE} big-endian bytes. */
    private static byte[] fixed(BigInteger v) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[COORDINATE];
        int n = Math.min(raw.length, COORDINATE);
        System.arraycopy(raw, raw.length - n, out, COORDINATE - n, n);
        return out;
    }

    private static byte[] base64(String s) {
        try {
            return Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("not base64");
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static ECParameterSpec p256() {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            return params.getParameterSpec(ECParameterSpec.class);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("P-256 unavailable", e);
        }
    }
}
