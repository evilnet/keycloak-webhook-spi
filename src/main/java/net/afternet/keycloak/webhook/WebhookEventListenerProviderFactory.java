package net.afternet.keycloak.webhook;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory for creating WebhookEventListenerProvider instances.
 *
 * <p>This factory reads configuration from Keycloak's config system and
 * creates provider instances for each session.</p>
 *
 * <h2>Configuration</h2>
 *
 * <p>Via keycloak.conf:</p>
 * <pre>
 * spi-events-listener-webhook-events-url=http://x3:9080/keycloak-webhook,http://nefarious:9090/keycloak-webhook
 * spi-events-listener-webhook-events-secret=your-shared-secret
 * spi-events-listener-webhook-events-retry-count=3
 * spi-events-listener-webhook-events-send-all-events=false
 * </pre>
 *
 * <p>Via environment variables:</p>
 * <pre>
 * KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_URL=http://x3:9080/keycloak-webhook,http://nefarious:9090/keycloak-webhook
 * KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_SECRET=your-shared-secret
 * KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_RETRY_COUNT=3
 * KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_SEND_ALL_EVENTS=false
 * </pre>
 *
 * <p>The URL parameter accepts comma-separated values to send events to multiple
 * endpoints (e.g., both X3 services and Nefarious IRCd). Each endpoint receives
 * all events independently with its own retry logic.</p>
 *
 * <h2>Enabling the Listener</h2>
 *
 * <p>After deploying the JAR and running `kc.sh build`, enable via:</p>
 * <ul>
 *   <li>Admin Console: Realm Settings &gt; Events &gt; Event Listeners &gt; Add "webhook-events"</li>
 *   <li>Or CLI: Add to realm JSON export/import</li>
 * </ul>
 */
public class WebhookEventListenerProviderFactory implements EventListenerProviderFactory {

    private static final Logger LOG = Logger.getLogger(WebhookEventListenerProviderFactory.class);

    public static final String PROVIDER_ID = "webhook-events";

    private WebhookConfig config;

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new WebhookEventListenerProvider(session, config);
    }

    @Override
    public void init(Config.Scope configScope) {
        // Read configuration from Keycloak config system
        // These map to spi-events-listener-webhook-events-* properties
        // or KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_* environment variables

        String url = configScope.get("url");
        String secret = configScope.get("secret");
        int retryCount = configScope.getInt("retry-count", 3);
        boolean sendAllEvents = configScope.getBoolean("send-all-events", false);

        // Allow environment variable override (for Docker deployments)
        if (url == null || url.isEmpty()) {
            url = System.getenv("WEBHOOK_URL");
        }
        if (secret == null || secret.isEmpty()) {
            secret = System.getenv("WEBHOOK_SECRET");
        }

        this.config = new WebhookConfig(url, secret, retryCount, sendAllEvents);

        if (!config.getWebhookUrls().isEmpty()) {
            LOG.infof("Webhook event listener initialized: urls=%s, retryCount=%d, sendAllEvents=%b",
                config.getWebhookUrls(), retryCount, sendAllEvents);
        } else {
            LOG.warn("Webhook event listener initialized but URL not configured - events will not be sent");
        }
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // No post-initialization needed
    }

    @Override
    public void close() {
        // No cleanup needed
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
