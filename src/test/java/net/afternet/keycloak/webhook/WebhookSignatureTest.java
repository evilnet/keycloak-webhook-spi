package net.afternet.keycloak.webhook;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

class WebhookSignatureTest {
    /* Vector shared with the ircd's cmocka suite (kc_webhook_sig_cmocka.c). */
    static final String SECRET = "x3-webhook-secret";
    static final long T = 1790200000L;
    static final String BODY = "{\"id\":\"e1\",\"resourceType\":\"USER\",\"operationType\":\"DELETE\","
        + "\"resourcePath\":\"users/0b4a2f0e-1d4c-4c4a-9a1e-000000000001\",\"realmName\":\"testnet\"}";

    @Test
    void signsTimestampDotBodyWithHmacSha256() {
        assertEquals("b8eb25dedf41b9e88b658f97537f5ec2cce9dcbd7c1915edbaf01e1b5e15e4f6",
            WebhookEventListenerProvider.sign(SECRET, T, BODY));
    }

    @Test
    void headerValueCarriesTimestampAndVersionedDigest() {
        assertEquals("t=1790200000,v1=b8eb25dedf41b9e88b658f97537f5ec2cce9dcbd7c1915edbaf01e1b5e15e4f6",
            WebhookEventListenerProvider.signatureHeader(SECRET, T, BODY));
    }
}
