package io.github.evilnet.keycloak.irc.ecdsa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class EcdsaPublicKeysTest {

    static final String DER_B64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKLJJ+AMaKqWkklSdBPtg5g1EYjOD/2p3sm6m0kt/Ee1JscEYSXbnvNeAup3/FHS4Sdndi9gGVr/TmpAXadV43Q==";
    static final String POINT_B64 = "AyiySfgDGiqlpJJUnQT7YOYNRGIzg/9qd7JuptJLfxHt";
    static final String PEM = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKLJJ+AMaKqWkklSdBPtg5g1EYjOD\n/2p3sm6m0kt/Ee1JscEYSXbnvNeAup3/FHS4Sdndi9gGVr/TmpAXadV43Q==\n-----END PUBLIC KEY-----\n";

    @Test void allThreeFormsGiveTheSamePem() {
        assertEquals(PEM, EcdsaPublicKeys.toPem(PEM));
        assertEquals(PEM, EcdsaPublicKeys.toPem("  " + DER_B64 + "\n"));
        assertEquals(PEM, EcdsaPublicKeys.toPem(POINT_B64));
    }

    @Test void rejectsOtherKeys() {
        assertThrows(IllegalArgumentException.class, () -> EcdsaPublicKeys.toPem("not a key"));
        assertThrows(IllegalArgumentException.class, () -> EcdsaPublicKeys.toPem(p384SpkiBase64()));
        assertThrows(IllegalArgumentException.class, () -> EcdsaPublicKeys.toPem(rsaSpkiBase64()));
        assertThrows(IllegalArgumentException.class, () -> EcdsaPublicKeys.toPem(""));
    }

    @Test void uncompressedPointAndCrlfPemGiveTheSamePem() {
        byte[] der = Base64.getDecoder().decode(DER_B64);
        byte[] point = java.util.Arrays.copyOfRange(der, der.length - 65, der.length);   // 0x04 || X || Y
        assertEquals(PEM, EcdsaPublicKeys.toPem(Base64.getEncoder().encodeToString(point)));
        assertEquals(PEM, EcdsaPublicKeys.toPem(PEM.replace("\n", "\r\n")));
    }

    @Test void rejectsPointsOffTheCurve() {
        byte[] der = Base64.getDecoder().decode(DER_B64);
        der[der.length - 1] ^= 1;   // Y changed: the point is no longer on P-256
        String offDer = Base64.getEncoder().encodeToString(der);
        byte[] point = java.util.Arrays.copyOfRange(der, der.length - 65, der.length);
        assertThrows(IllegalArgumentException.class, () -> EcdsaPublicKeys.toPem(offDer));
        assertThrows(IllegalArgumentException.class, () -> EcdsaPublicKeys.toPem(Base64.getEncoder().encodeToString(point)));
        // A compressed point whose X has no Y on the curve (x^3 - 3x + b is not a square mod p for X = 1).
        byte[] compressed = new byte[33];
        compressed[0] = 0x02;
        compressed[32] = 0x01;
        assertThrows(IllegalArgumentException.class, () -> EcdsaPublicKeys.toPem(Base64.getEncoder().encodeToString(compressed)));
    }

    @Test void rejectsMalformedInput() {
        assertThrows(IllegalArgumentException.class, () -> EcdsaPublicKeys.toPem(null));
        assertThrows(IllegalArgumentException.class, () -> EcdsaPublicKeys.toPem("   \n"));
        assertThrows(IllegalArgumentException.class, () -> EcdsaPublicKeys.toPem(PEM.replace("PUBLIC KEY", "EC PUBLIC KEY")));
        assertThrows(IllegalArgumentException.class, () -> EcdsaPublicKeys.toPem(PEM.replace("-----END PUBLIC KEY-----\n", "")));
        byte[] point = Base64.getDecoder().decode(POINT_B64);
        point[0] = 0x05;   // no such point format
        assertThrows(IllegalArgumentException.class, () -> EcdsaPublicKeys.toPem(Base64.getEncoder().encodeToString(point)));
        byte[] der = Base64.getDecoder().decode(DER_B64);
        byte[] trailing = java.util.Arrays.copyOf(der, der.length + 1);   // a valid key followed by a stray byte
        assertThrows(IllegalArgumentException.class, () -> EcdsaPublicKeys.toPem(Base64.getEncoder().encodeToString(trailing)));
    }

    @Test void rejectsOverLongInput() {
        assertThrows(IllegalArgumentException.class, () -> EcdsaPublicKeys.toPem("A".repeat(EcdsaPublicKeys.MAX_INPUT + 4)));
        assertThrows(IllegalArgumentException.class,
                () -> EcdsaPublicKeys.toPem(" ".repeat(EcdsaPublicKeys.MAX_INPUT) + DER_B64));
    }

    private static String p384SpkiBase64() {
        return generated("EC", new ECGenParameterSpec("secp384r1"));
    }

    private static String rsaSpkiBase64() {
        return generated("RSA", null);
    }

    private static String generated(String algorithm, ECGenParameterSpec spec) {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance(algorithm);
            if (spec != null) {
                g.initialize(spec);
            } else {
                g.initialize(2048);
            }
            return Base64.getEncoder().encodeToString(g.generateKeyPair().getPublic().getEncoded());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
