# Keycloak Webhook Event Listener SPI

A reusable Keycloak extension that sends admin and user events to configurable webhook endpoints.

## Features

- Sends Admin Events (user management, group membership, credentials) via HTTP POST
- Sends User Events (login, credential changes) via HTTP POST
- Configurable event filtering (X3-relevant events by default, or all events)
- Shared secret authentication via `X-Webhook-Secret` header
- Exponential backoff retry on failures
- Async delivery to avoid blocking Keycloak operations

## Quick Start

### Build

```bash
mvn clean package
```

### Deploy

```bash
# Copy JAR to Keycloak providers directory
cp target/keycloak-webhook-spi-1.0.0-SNAPSHOT.jar /opt/keycloak/providers/

# Rebuild Keycloak (required for new providers)
/opt/keycloak/bin/kc.sh build

# Restart Keycloak
```

### Configure

Via environment variables:
```bash
KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_URL=http://x3:9080/keycloak-webhook
KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_SECRET=your-shared-secret
KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_RETRY_COUNT=3
KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_SEND_ALL_EVENTS=false
```

Or via keycloak.conf:
```properties
spi-events-listener-webhook-events-url=http://x3:9080/keycloak-webhook
spi-events-listener-webhook-events-secret=your-shared-secret
spi-events-listener-webhook-events-retry-count=3
spi-events-listener-webhook-events-send-all-events=false
```

### Enable

In Keycloak Admin Console:
1. Go to Realm Settings > Events > Event Listeners
2. Add `webhook-events` to the list

## Configuration Options

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| url | KC_SPI_...URL | (none) | Target webhook URL |
| secret | KC_SPI_...SECRET | (none) | Shared secret for X-Webhook-Secret header |
| retry-count | KC_SPI_...RETRY_COUNT | 3 | Number of retry attempts |
| send-all-events | KC_SPI_...SEND_ALL_EVENTS | false | Send all events (vs X3-relevant only) |

## Event Formats

### Admin Events

Sent for: USER, GROUP, GROUP_MEMBERSHIP, CREDENTIAL operations

```json
{
  "id": "event-uuid",
  "time": 1234567890000,
  "realmId": "realm-uuid",
  "resourceType": "GROUP_MEMBERSHIP",
  "operationType": "CREATE",
  "resourcePath": "users/user-uuid/groups/group-uuid",
  "representation": "{...}",
  "authDetails": {
    "userId": "admin-uuid",
    "ipAddress": "192.168.1.1",
    "realmId": "master",
    "clientId": "admin-cli"
  }
}
```

### User Events

Sent for: UPDATE_CREDENTIAL, REMOVE_CREDENTIAL, UPDATE_PASSWORD, RESET_PASSWORD

```json
{
  "id": "event-uuid",
  "time": 1234567890000,
  "realmId": "realm-uuid",
  "type": "UPDATE_CREDENTIAL",
  "resourceType": "CREDENTIAL",
  "operationType": "UPDATE",
  "userId": "user-uuid",
  "clientId": "account",
  "ipAddress": "192.168.1.1",
  "sessionId": "session-uuid",
  "details": {
    "credential_type": "password"
  }
}
```

## X3 IRC Services Integration

This SPI is designed to work with X3's webhook handler (`keycloak_webhook.c`). X3 uses webhooks to:

- Invalidate SCRAM/password caches on credential changes
- Trigger channel sync on GROUP_MEMBERSHIP changes
- Clear user sessions on USER_SESSION delete
- Pre-warm fingerprint cache on x509 credential creation

Configure X3 in x3.conf:
```
"keycloak_webhook_port" "9080";
"keycloak_webhook_secret" "your-shared-secret";
```

## Docker Integration

### Custom Keycloak Image

```dockerfile
FROM quay.io/keycloak/keycloak:26.0.0

COPY keycloak-webhook-spi-1.0.0-SNAPSHOT.jar /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build
```

### Docker Compose with Build

```yaml
services:
  keycloak-spi-build:
    image: maven:3.9-eclipse-temurin-17
    volumes:
      - ./keycloak-webhook-spi:/build
      - keycloak_providers:/providers
    command: >
      sh -c "cd /build && mvn -q package -DskipTests &&
             cp target/*.jar /providers/"

  keycloak:
    image: quay.io/keycloak/keycloak:26.0.0
    depends_on:
      keycloak-spi-build:
        condition: service_completed_successfully
    volumes:
      - keycloak_providers:/opt/keycloak/providers
    environment:
      - KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_URL=http://x3:9080/keycloak-webhook
      - KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_SECRET=x3-webhook-secret
    command: start-dev

volumes:
  keycloak_providers:
```

## Broader Use Cases

While designed for X3, this SPI can be used for:

- **Audit/SIEM**: Forward all events to security monitoring systems
- **User Provisioning**: Trigger external workflows on user creation
- **Analytics**: Track authentication patterns and usage metrics
- **Alerting**: Send login failures to Slack/Discord/PagerDuty

Set `send-all-events=true` and configure multiple webhook targets by deploying separate instances with different configurations.

## Development

### Requirements

- Java 17+
- Maven 3.8+
- Keycloak 26.x (for runtime testing)

### Running Tests

```bash
mvn test
```

### Local Development

1. Start Keycloak in dev mode
2. Deploy the JAR to providers/
3. Rebuild: `kc.sh build`
4. Enable the listener in Admin Console
5. Use a tool like webhook.site or ngrok to test webhook delivery

## License

MIT License - see LICENSE file for details.
