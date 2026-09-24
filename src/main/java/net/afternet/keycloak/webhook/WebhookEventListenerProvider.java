package net.afternet.keycloak.webhook;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

/**
 * Keycloak Event Listener that sends events to configured webhook endpoints.
 *
 * <p>This provider handles both User Events (authentication-related) and
 * Admin Events (management operations) and forwards them as JSON to
 * configurable HTTP endpoints.</p>
 *
 * <p>Configuration is done via environment variables or keycloak.conf:</p>
 * <ul>
 *   <li>KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_URL - Target webhook URL</li>
 *   <li>KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_SECRET - Shared secret for X-Webhook-Secret header</li>
 *   <li>KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_RETRY_COUNT - Number of retries (default: 3)</li>
 * </ul>
 */
public class WebhookEventListenerProvider implements EventListenerProvider {

    private static final Logger LOG = Logger.getLogger(WebhookEventListenerProvider.class);

    private final KeycloakSession session;
    private final WebhookConfig config;
    private final HttpClient httpClient;
    private final Gson gson;

    // Resource types relevant to watching account/services consumers
    private static final Set<ResourceType> WATCHED_RESOURCE_TYPES = Set.of(
        ResourceType.USER,
        ResourceType.GROUP,
        ResourceType.GROUP_MEMBERSHIP,
        ResourceType.REALM_ROLE_MAPPING
    );

    // User events worth watching (credential changes affect SASL/SCRAM caches)
    private static final Set<EventType> WATCHED_USER_EVENTS = Set.of(
        EventType.UPDATE_CREDENTIAL,
        EventType.REMOVE_CREDENTIAL,
        EventType.UPDATE_PASSWORD,
        EventType.RESET_PASSWORD
    );

    public WebhookEventListenerProvider(KeycloakSession session, WebhookConfig config) {
        this.session = session;
        this.config = config;
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();
        this.gson = new GsonBuilder()
            .setPrettyPrinting()
            .create();
    }

    /**
     * Handle User Events (authentication, credential changes, etc.)
     */
    @Override
    public void onEvent(Event event) {
        if (config.getWebhookUrls().isEmpty()) {
            return;
        }

        // Filter to only watched events unless configured to send all
        if (!config.isSendAllEvents() && !WATCHED_USER_EVENTS.contains(event.getType())) {
            LOG.debugf("Skipping user event type: %s", event.getType());
            return;
        }

        String payload = formatUserEvent(event);
        LOG.infof("Sending user event webhook to %d endpoint(s): type=%s, userId=%s",
            config.getWebhookUrls().size(), event.getType(), event.getUserId());

        sendWebhookAsync(payload);
    }

    /**
     * Handle Admin Events (user management, group membership, etc.)
     */
    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        if (config.getWebhookUrls().isEmpty()) {
            return;
        }

        // Filter to only watched resource types unless configured to send all
        if (!config.isSendAllEvents() && !WATCHED_RESOURCE_TYPES.contains(event.getResourceType())) {
            LOG.debugf("Skipping admin event resource type: %s", event.getResourceType());
            return;
        }

        String payload = formatAdminEvent(event);
        LOG.infof("Sending admin event webhook to %d endpoint(s): resourceType=%s, operationType=%s, path=%s",
            config.getWebhookUrls().size(), event.getResourceType(), event.getOperationType(), event.getResourcePath());

        sendWebhookAsync(payload);
    }

    /**
     * Format a User Event as JSON in the shape the Nefarious ircd's kc_webhook
     * parser reads.
     *
     * <p>For credential change events (UPDATE_PASSWORD, RESET_PASSWORD, etc.),
     * this method also adds the user's username (the ircd purges its auth
     * caches by that name) and, when the realm's password policy stores them,
     * the SCRAM-SHA-256 verifier attributes.</p>
     */
    private String formatUserEvent(Event event) {
        JsonObject json = new JsonObject();
        json.addProperty("id", event.getId());
        json.addProperty("time", event.getTime());
        json.addProperty("realmId", event.getRealmId());
        String realmName = realmName(event.getRealmId());
        if (realmName != null) {
            json.addProperty("realmName", realmName);
        }
        json.addProperty("type", event.getType().name());
        json.addProperty("userId", event.getUserId());
        json.addProperty("clientId", event.getClientId());
        json.addProperty("ipAddress", event.getIpAddress());
        json.addProperty("sessionId", event.getSessionId());

        // The ircd reads resourceType/operationType; map the user event type onto them
        json.addProperty("resourceType", mapEventTypeToResourceType(event.getType()));
        json.addProperty("operationType", mapEventTypeToOperationType(event.getType()));

        // Include event details if present
        if (event.getDetails() != null && !event.getDetails().isEmpty()) {
            JsonObject details = new JsonObject();
            event.getDetails().forEach(details::addProperty);
            json.add("details", details);
        }

        // For credential change events, include SCRAM credentials and username
        if (isCredentialChangeEvent(event.getType()) && event.getUserId() != null) {
            try {
                addUserScramCredentials(json, event.getRealmId(), event.getUserId());
            } catch (Exception e) {
                LOG.warnf("Failed to fetch SCRAM credentials for user %s: %s",
                    event.getUserId(), e.getMessage());
            }
        }

        return gson.toJson(json);
    }

    /**
     * Check if this event type represents a credential change.
     */
    private boolean isCredentialChangeEvent(EventType type) {
        return type == EventType.UPDATE_PASSWORD ||
               type == EventType.RESET_PASSWORD ||
               type == EventType.UPDATE_CREDENTIAL;
    }

    /**
     * Fetch user's SCRAM credentials from attributes and add to JSON payload.
     *
     * <p>Looks for attributes set by ScramPasswordPolicyProvider (the live
     * producer of these attributes — ScramCredentialProvider is disabled;
     * see its META-INF/services registration):</p>
     * <ul>
     *   <li>scram_sha256_salt - Base64-encoded salt</li>
     *   <li>scram_sha256_iterations - Iteration count</li>
     *   <li>scram_sha256_stored_key - Base64-encoded StoredKey</li>
     *   <li>scram_sha256_server_key - Base64-encoded ServerKey</li>
     * </ul>
     *
     * <p>The Nefarious ircd's SASL SCRAM-SHA-256 path consumes these same
     * attributes via an admin-REST user fetch, not via this webhook payload;
     * the derivation parameters (SHA-256, 4096 iterations, 16-byte salt) are
     * in lockstep with {@code nefarious/ircd/kc/kc_cred_derive.c} — change
     * one, change both. This webhook payload additionally carries the
     * attributes for cache-invalidation consumers, but is currently
     * unconsumed on the ircd side: its credential-event handler
     * ({@code sasl_webhook.c: handle_credential_event}) only invalidates
     * caches and does not read these fields out of the payload.</p>
     */
    private void addUserScramCredentials(JsonObject json, String realmId, String userId) {
        RealmModel realm = session.realms().getRealm(realmId);
        if (realm == null) {
            LOG.warnf("Realm not found: %s", realmId);
            return;
        }

        UserModel user = session.users().getUserById(realm, userId);
        if (user == null) {
            LOG.warnf("User not found: %s", userId);
            return;
        }

        // The ircd purges its auth caches by this name
        json.addProperty("username", user.getUsername());

        // Fetch SCRAM attributes (generated by ScramPasswordPolicyProvider)
        String salt = getFirstAttribute(user, ScramPasswordPolicyProvider.ATTR_SCRAM_SALT);
        String iterations = getFirstAttribute(user, ScramPasswordPolicyProvider.ATTR_SCRAM_ITERATIONS);
        String storedKey = getFirstAttribute(user, ScramPasswordPolicyProvider.ATTR_SCRAM_STORED_KEY);
        String serverKey = getFirstAttribute(user, ScramPasswordPolicyProvider.ATTR_SCRAM_SERVER_KEY);

        // Only include SCRAM object if all credentials are present
        if (salt != null && iterations != null && storedKey != null && serverKey != null) {
            JsonObject scram = new JsonObject();
            scram.addProperty("salt", salt);
            scram.addProperty("iterations", Integer.parseInt(iterations));
            scram.addProperty("storedKey", storedKey);
            scram.addProperty("serverKey", serverKey);
            json.add("scram", scram);

            LOG.infof("Including SCRAM credentials in webhook for user %s", user.getUsername());
        } else {
            LOG.debugf("SCRAM credentials not available for user %s (salt=%s, iter=%s, stored=%s, server=%s)",
                user.getUsername(),
                salt != null ? "present" : "missing",
                iterations != null ? "present" : "missing",
                storedKey != null ? "present" : "missing",
                serverKey != null ? "present" : "missing");
        }
    }

    /**
     * Get first value of a user attribute, or null if not present.
     */
    private String getFirstAttribute(UserModel user, String name) {
        List<String> values = user.getAttributeStream(name).toList();
        return values.isEmpty() ? null : values.get(0);
    }

    /**
     * Format an Admin Event as JSON, as Keycloak recorded it.
     *
     * <p>The consumer is the Nefarious ircd, which resolves the subject of a
     * USER event by the uuid in resourcePath; nothing is added.  The shape:</p>
     * <pre>
     * {
     *   "id": "event-uuid",
     *   "time": 1234567890000,
     *   "realmId": "realm-uuid",
     *   "resourceType": "USER" | "GROUP_MEMBERSHIP" | "GROUP" | ...,
     *   "operationType": "CREATE" | "UPDATE" | "DELETE" | "ACTION",
     *   "resourcePath": "users/user-uuid[/reset-password]",
     *   "representation": "{...}",          // when Keycloak recorded one
     *   "authDetails": { "userId": "acting admin", "ipAddress": "...", "realmId": "...", "clientId": "..." }
     * }
     * </pre>
     * <p>authDetails names the acting admin, never the subject.</p>
     */
    private String formatAdminEvent(AdminEvent event) {
        JsonObject json = new JsonObject();
        json.addProperty("id", event.getId());
        json.addProperty("time", event.getTime());
        json.addProperty("realmId", event.getRealmId());
        String realmName = realmName(event.getRealmId());
        if (realmName != null) {
            json.addProperty("realmName", realmName);
        }
        json.addProperty("resourceType", event.getResourceType().name());
        json.addProperty("operationType", event.getOperationType().name());
        json.addProperty("resourcePath", event.getResourcePath());

        // Include representation if available (contains the actual entity data)
        if (event.getRepresentation() != null) {
            json.addProperty("representation", event.getRepresentation());
        }

        // Include auth details for audit trail
        if (event.getAuthDetails() != null) {
            JsonObject auth = new JsonObject();
            auth.addProperty("userId", event.getAuthDetails().getUserId());
            auth.addProperty("ipAddress", event.getAuthDetails().getIpAddress());
            auth.addProperty("realmId", event.getAuthDetails().getRealmId());
            auth.addProperty("clientId", event.getAuthDetails().getClientId());
            json.add("authDetails", auth);
        }

        return gson.toJson(json);
    }

    /**
     * Map EventType to resourceType string for the ircd's parser.
     */
    private String mapEventTypeToResourceType(EventType type) {
        return switch (type) {
            case UPDATE_CREDENTIAL, REMOVE_CREDENTIAL, UPDATE_PASSWORD, RESET_PASSWORD -> "CREDENTIAL";
            case LOGIN, LOGOUT, LOGIN_ERROR -> "USER_SESSION";
            case REGISTER, UPDATE_PROFILE -> "USER";
            default -> "USER";
        };
    }

    /**
     * Map EventType to operationType string for the ircd's parser.
     */
    private String mapEventTypeToOperationType(EventType type) {
        return switch (type) {
            case UPDATE_CREDENTIAL, UPDATE_PASSWORD, RESET_PASSWORD, UPDATE_PROFILE -> "UPDATE";
            case REMOVE_CREDENTIAL -> "DELETE";
            case REGISTER -> "CREATE";
            case LOGIN, LOGOUT, LOGIN_ERROR -> "ACTION";
            default -> "ACTION";
        };
    }

    /**
     * Send webhook asynchronously to all configured URLs with retry logic.
     */
    /** HMAC-SHA256 over "<t>.<body>", lowercase hex; the ircd verifies the same bytes. */
    static String sign(String secret, long t, String body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] d = mac.doFinal((t + "." + body).getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }

    /** The X-Webhook-Signature value: t=<unix seconds>,v1=<hex digest>. */
    static String signatureHeader(String secret, long t, String body) {
        return "t=" + t + ",v1=" + sign(secret, t, body);
    }

    /** The realm's name (events carry only its uuid); null when it cannot be resolved. */
    private String realmName(String realmId) {
        try {
            RealmModel realm = session.realms().getRealm(realmId);
            if (realm == null) {
                LOG.warnf("Realm %s not found; the event goes out without realmName, which a "
                          + "consumer that checks the realm accepts but counts", realmId);
                return null;
            }
            return realm.getName();
        } catch (Exception e) {
            LOG.warnf("Realm %s could not be resolved (%s); the event goes out without realmName",
                      realmId, e.toString());
            return null;
        }
    }

    private void sendWebhookAsync(String payload) {
        for (String url : config.getWebhookUrls()) {
            CompletableFuture.runAsync(() -> sendWithRetry(url, payload, config.getRetryCount()));
        }
    }

    /**
     * Send webhook to a single URL with exponential backoff retry.
     */
    private void sendWithRetry(String url, String payload, int maxRetries) {
        int delay = 1000; // Start with 1 second

        for (int attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                sendWebhook(url, payload);
                return; // Success
            } catch (Exception e) {
                if (attempt == maxRetries) {
                    LOG.errorf("Webhook to %s failed after %d attempts: %s",
                        url, maxRetries + 1, e.getMessage());
                    return;
                }
                LOG.warnf("Webhook to %s attempt %d failed, retrying in %dms: %s",
                    url, attempt + 1, delay, e.getMessage());
                try {
                    Thread.sleep(delay);
                    delay = Math.min(delay * 2, 30000); // Cap at 30 seconds
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }

    /**
     * Send a single webhook request to one URL.
     */
    private void sendWebhook(String url, String payload) throws Exception {
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("Content-Type", "application/json")
            .timeout(Duration.ofSeconds(10))
            .POST(HttpRequest.BodyPublishers.ofString(payload));

        // Add secret header if configured (the ircd's X-Webhook-Secret)
        if (config.getWebhookSecret() != null && !config.getWebhookSecret().isEmpty()) {
            requestBuilder.header("X-Webhook-Secret", config.getWebhookSecret());
            // The ircd refuses unsigned, stale or replayed deliveries: sign the body with the same secret.
            requestBuilder.header("X-Webhook-Signature",
                signatureHeader(config.getWebhookSecret(), Instant.now().getEpochSecond(), payload));
        }

        HttpResponse<String> response = httpClient.send(
            requestBuilder.build(),
            HttpResponse.BodyHandlers.ofString()
        );

        if (response.statusCode() >= 400) {
            throw new RuntimeException(String.format(
                "Webhook to %s returned error: %d %s", url, response.statusCode(), response.body()));
        }

        LOG.debugf("Webhook delivered to %s: %d", url, response.statusCode());
    }

    @Override
    public void close() {
        // HttpClient doesn't need explicit cleanup
    }
}
