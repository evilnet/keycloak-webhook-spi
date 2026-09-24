# Keycloak Webhook Event Listener SPI

A reusable Keycloak extension that sends admin and user events to configurable webhook endpoints.

## Features

- Sends Admin Events (user management, group membership, credentials) via HTTP POST
- Sends User Events (login, credential changes) via HTTP POST
- Configurable event filtering (the events the Nefarious ircd acts on by default, or all events)
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
KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_URL=http://nefarious:9090/keycloak-webhook
KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_SECRET=your-shared-secret
KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_RETRY_COUNT=3
KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_SEND_ALL_EVENTS=false
```

The URL setting is a comma-separated list, and every event is posted to every URL with
its own retries.  List every ircd of the network: each verifies the signature and dedupes
by the event id on its own, and relays the event to the peers the SPI could not reach.

Or via keycloak.conf:
```properties
spi-events-listener-webhook-events-url=http://nefarious:9090/keycloak-webhook
spi-events-listener-webhook-events-secret=your-shared-secret
spi-events-listener-webhook-events-retry-count=3
spi-events-listener-webhook-events-send-all-events=false
```

The URL parameter accepts comma-separated values to deliver events to multiple endpoints independently.

### Enable

In Keycloak Admin Console:
1. Go to Realm Settings > Events > Event Listeners
2. Add `webhook-events` to the list

## Configuration Options

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| url | KC_SPI_...URL | (none) | Target webhook URL(s), comma-separated for multi-endpoint |
| secret | KC_SPI_...SECRET | (none) | Shared secret for X-Webhook-Secret header |
| retry-count | KC_SPI_...RETRY_COUNT | 3 | Number of retry attempts |
| send-all-events | KC_SPI_...SEND_ALL_EVENTS | false | Send all events (vs the ones the ircd acts on) |

## Event Formats

### Admin Events

Keycloak admin events are forwarded as they are, plus nothing: the subject of a
`USER` event is named only by the uuid in `resourcePath`.

```json
{
  "id": "event-uuid",
  "time": 1234567890000,
  "realmId": "realm-uuid",
  "resourceType": "USER",
  "operationType": "DELETE",
  "resourcePath": "users/<user-uuid>",
  "representation": "{...}",
  "authDetails": {
    "userId": "<acting admin uuid>",
    "ipAddress": "192.168.1.1",
    "realmId": "master",
    "clientId": "admin-cli"
  }
}
```

`representation` is present when Keycloak recorded one (create: the full user;
update: the fields that changed, so `enabled` appears only when it changed;
delete and actions: absent).  `authDetails` names the acting admin, never the
subject; consumers must not read it as the subject.

### User Events

Sent for: UPDATE_CREDENTIAL, REMOVE_CREDENTIAL, UPDATE_PASSWORD, RESET_PASSWORD

User events are forwarded with the event's own fields, mapped onto
`resourceType`/`operationType` like an admin event; credential-change events
additionally carry the user's `username` at the root and, when the realm's
password policy stores them, the SCRAM-SHA-256 verifier attributes.

```json
{
  "id": "event-uuid",
  "time": 1234567890000,
  "realmId": "realm-uuid",
  "type": "UPDATE_CREDENTIAL",
  "resourceType": "CREDENTIAL",
  "operationType": "UPDATE",
  "userId": "user-uuid",
  "username": "alice",
  "clientId": "account",
  "ipAddress": "192.168.1.1",
  "sessionId": "session-uuid",
  "details": {
    "credential_type": "password"
  }
}
```

## Consumer contract: the Nefarious ircd

The only consumer is the Nefarious ircd (`ircd/sasl_webhook.c`, via the vendored
`kc_webhook` parser).  What it needs per event:

| Event | Subject | What the ircd does |
|---|---|---|
| `USER` / `DELETE` on `users/<uuid>` | `resourcePath` uuid | purges its auth caches by id, deauths the sessions it can name (below), or disconnects local sockets when `WEBHOOK_KILL_ON_DELETE` is on |
| `USER` / `UPDATE` on `users/<uuid>` with `enabled:false` | uuid (and `representation.username` when full) | same, as a disable (`WEBHOOK_KILL_ON_DISABLE`) |
| `USER` / `ACTION` `users/<uuid>/reset-password` | uuid | purges its auth caches by id |
| `USER` / `DELETE` or `ACTION` on `users/<uuid>/credentials/<id>` | uuid | purges its auth caches by id |
| `USER` / `DELETE` or `UPDATE` on any other sub-resource of the user (federated identity, consent, ...) | -- | nothing: it is not the user |
| credential change user events | root `username` | purges its auth caches by name |
| everything else | -- | logged, ignored |

The ircd resolves the uuid against the Keycloak id it stores for every client
that logged in through its own Keycloak SASL and every positive-cache entry (the
ID token's `sub`, compact form), so no username is needed on admin events.  A
session is deauthed when something names its account: the payload's own
`username` (synthetic events, a full representation), the account of a client
carrying the id, or the account of a cache entry the id purge dropped.  A session
that was authenticated through X3, or behind a legacy hop, or restored from the
bouncer database carries no id; a real (nameless) event does not reach it, and
the ircd logs a warning naming the id.

Every delivery carries `X-Webhook-Signature: t=<unix seconds>,v1=<hex>` (HMAC-SHA256 over
`<t>.<body>` with the shared secret) beside `X-Webhook-Secret`, and every payload carries
`realmName`.  A consumer that checks them (the Nefarious ircd does) refuses an unsigned,
stale (outside its window, 300 s by default) or other-realm delivery, and a played-back
copy of an accepted event (same event id, a signature no newer than the last accepted
one); this SPI's own retry of an accepted event, signed again with a newer `t`, is
answered 200 and not acted on again, so a lost answer never applies an event twice.

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
      - KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_URL=http://nefarious:9090/keycloak-webhook
      - KC_SPI_EVENTS_LISTENER_WEBHOOK_EVENTS_SECRET=your-shared-secret
    command: start-dev

volumes:
  keycloak_providers:
```

## Broader Use Cases

While written for the Nefarious ircd, this SPI can be used for:

- **Audit/SIEM**: Forward all events to security monitoring systems
- **User Provisioning**: Trigger external workflows on user creation
- **Analytics**: Track authentication patterns and usage metrics
- **Alerting**: Send login failures to Slack/Discord/PagerDuty

Set `send-all-events=true` and configure multiple webhook targets via comma-separated URLs.

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
