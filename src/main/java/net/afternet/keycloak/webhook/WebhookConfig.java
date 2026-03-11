package net.afternet.keycloak.webhook;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Configuration holder for webhook settings.
 *
 * <p>Immutable configuration object created by the factory and shared
 * across all provider instances.</p>
 */
public class WebhookConfig {

    private final List<String> webhookUrls;
    private final String webhookSecret;
    private final int retryCount;
    private final boolean sendAllEvents;

    public WebhookConfig(String webhookUrl, String webhookSecret, int retryCount, boolean sendAllEvents) {
        this.webhookUrls = parseUrls(webhookUrl);
        this.webhookSecret = webhookSecret;
        this.retryCount = retryCount;
        this.sendAllEvents = sendAllEvents;
    }

    /**
     * Parse a comma-separated URL string into a list of trimmed, non-empty URLs.
     */
    private static List<String> parseUrls(String urlString) {
        if (urlString == null || urlString.isBlank()) {
            return Collections.emptyList();
        }
        List<String> urls = new ArrayList<>();
        for (String part : urlString.split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                urls.add(trimmed);
            }
        }
        return Collections.unmodifiableList(urls);
    }

    /**
     * Get the target webhook URLs.
     *
     * @return unmodifiable list of webhook URLs (may be empty)
     */
    public List<String> getWebhookUrls() {
        return webhookUrls;
    }

    /**
     * Get the first webhook URL for backwards compatibility.
     *
     * @return the first webhook URL, or null if not configured
     */
    public String getWebhookUrl() {
        return webhookUrls.isEmpty() ? null : webhookUrls.get(0);
    }

    /**
     * Get the shared secret for authentication.
     *
     * <p>This is sent as the X-Webhook-Secret header to match X3's expectations.</p>
     *
     * @return the webhook secret, or null if not configured
     */
    public String getWebhookSecret() {
        return webhookSecret;
    }

    /**
     * Get the number of retry attempts for failed webhooks.
     *
     * @return the retry count (default: 3)
     */
    public int getRetryCount() {
        return retryCount;
    }

    /**
     * Check if all events should be sent.
     *
     * <p>If false (default), only X3-relevant events are sent (GROUP_MEMBERSHIP,
     * CREDENTIAL, USER, etc.). If true, all events are forwarded.</p>
     *
     * @return true if all events should be sent
     */
    public boolean isSendAllEvents() {
        return sendAllEvents;
    }
}
