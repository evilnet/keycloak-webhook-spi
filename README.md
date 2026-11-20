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
its own retries.  One reachable ircd is enough: each receiver verifies the signature,
dedupes by the event id, relays the event to every server linked to it, and catches a
server up on the events it missed when it links back.  Listing a hub (or a few) covers
that hub being down; listing every ircd is the most reliable, not a requirement.

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
additionally carry the user's `username` at the root.  No payload carries the
SCRAM-SHA-256 verifier: an IRC server reads it from the read endpoint (below).

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

## Legacy password hashes

When an LDAP directory is retired, its password hashes can be loaded into Keycloak
and still verify, so nobody needs a password reset.  Two verify-only password hash
providers are registered:

| Algorithm id | Source | `secretData.value` | `secretData.salt` |
|---|---|---|---|
| `x3-md5` | X3's unsalted `{MD5}` | base64 of the 16-byte MD5 | `""` |
| `ldap-ssha` | OpenLDAP `{SSHA}` | base64 of the 20-byte SHA-1 | base64 of the salt bytes |

Both use `hashIterations` 1.  Load them as a pre-hashed credential on an existing
user (the user id is kept):

```json
{"type": "password",
 "secretData": "{\"value\":\"Xr4ilOzQ4PCOq3aQ0qbuaQ==\",\"salt\":\"\"}",
 "credentialData": "{\"hashIterations\":1,\"algorithm\":\"x3-md5\"}"}
```

A password that contains non-ASCII characters may have been hashed from its
ISO-8859-1 or its UTF-8 bytes, so both are tried.  The providers never produce
hashes: after the first successful login Keycloak re-hashes the password to the
realm's hashing policy, and the legacy hash is gone.

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

## Account state

An IRC account is reported as `ok`, `incomplete` or `disabled`, with reason codes.
A disabled user is `disabled` (reasons `["disabled"]`) whatever else is pending.
Otherwise the reasons, in this order, are: `verify_email`, `update_password`, `configure_totp`,
`update_profile`, `verify_profile`, `terms_and_conditions` (from the user's stored required
actions), any other stored action as `action:<alias lowercased>`, `email_missing`, `email_unverified`.
No reasons means `ok`.

Two realm attributes switch the email rules on (both default `false`):
`irc.requireEmail` (the user must have an email) and `irc.requireVerifiedEmail`
(the user must have a verified email).  A user with no email (null or empty) gets
`email_missing` when either is on; a user with an unverified email gets `email_unverified`
when `irc.requireVerifiedEmail` is on.  The two email reasons never appear together.

## Read endpoint

`GET /realms/{realm}/irc/credentials/{username}` returns what an IRC server needs for a login.
The caller sends a bearer token whose realm roles include `irc-read-credentials`:
no token is 401, a token without the role is 403.  The username is matched case-insensitively
and the path segment is percent-decoded.  An unknown user is 404 with body
`{"error": "user_not_found"}`.  The response is sent with `Cache-Control: no-store`.

```json
{"id": "<uuid>", "username": "alice", "state": "ok", "reasons": [],
 "scram": {"salt": "<b64>", "iterations": 4096, "storedKey": "<b64>", "serverKey": "<b64>"},
 "certFingerprints": ["<64 uppercase hex>"]}
```

`scram` is left out when the user has no SCRAM verifier or when the verifier no longer matches
the user's current password.  `ecdsaPublicKey` (the user's ECDSA key as canonical PEM, see
"ECDSA keys" below) is present only when the user has one.  `certFingerprints` is always
present: the SHA-256 of each of the user's certificates (see "Certificates" below), `[]` when
there are none.  The response carries the StoredKey and ServerKey by design; the endpoint never
logs them.

Create the roles (and give them to the IRC server's service account), and put the login steps in
the realm's flows (see "Password grant: why an account was refused" and "SCRAM verifier" below),
with the realm set-up tool, which is idempotent
and uses only the Python standard library:

```bash
SETUP_PASS=... tools/irc_realm_setup.py --url https://kc.example --realm myrealm \
    --admin-user admin --admin-pass-env SETUP_PASS --service-client ircd
```

## Password grant: why an account was refused

Keycloak refuses the password grant of an enabled account with pending required actions with
HTTP 400 and one fixed message, whatever is pending.  The authenticator `irc-account-state`
("IRC account state"), placed at the end of the direct-grant flow, refuses such an account
itself, with Keycloak's own two fields and the account state (see "Account state" above):

```json
{"error": "invalid_grant", "error_description": "Account is not fully set up",
 "irc_state": "incomplete", "irc_reasons": ["verify_email"]}
```

`error` and `error_description` are exactly Keycloak's, so an IRC server that does not know the
two new fields behaves as before.  `irc_reasons` is in the order "Account state" gives.

- It runs only once every factor the flow demands is satisfied, at the point where Keycloak
  applies its own required-action check.  A wrong password gets Keycloak's
  `Invalid user credentials` and no reason.  An account with a second factor (OTP) gets
  Keycloak's own answer until that factor is supplied: the right password without the code is
  refused exactly as a wrong password is, with no reason; the reasons come only with the
  password and a valid code.
- A disabled account is refused before the password step by Keycloak's own username step
  (`Account disabled`), with or without the right password; that is unchanged and carries no
  `irc_*` fields.
- Before applying the rule it evaluates the realm's required-action triggers for the user, as the
  password grant itself does after the flow, so an action Keycloak adds at login is named too:
  for example `verify_profile` for a user whose profile the realm's user profile finds incomplete
  (such as a user without an email when the profile requires one).
- The email rules (`email_missing`, `email_unverified`) apply only when the realm turns them on.
- The refusal records the login event error Keycloak records (`resolve_required_actions`), and
  like Keycloak's own refusal it does not count as a failed login for brute-force detection.
- A complete account gets its token as before.

The realm set-up tool makes `irc-account-state` and then `irc-credential-sync` the last two
top-level steps of `irc direct grant`, REQUIRED, after every other step of the flow (the
conditional OTP sub-flow, and anything a custom flow adds), so an account refused here does not
reach the verifier sync.  The step is not put in `irc browser`: a browser login shows Keycloak's
own required-action screens.  A realm an earlier version of the tool set up is brought to this
layout on the next run.

## SCRAM verifier

The verifier is a credential of type `irc-scram-sha256` (SHA-256, 4096 iterations, 16-byte
salt), bound to the password it was derived from.  Keycloak sees a plaintext password at two
moments, and the verifier is made at both:

- **Password set through Keycloak** (admin reset, account console, required action,
  registration) when the realm's password policy includes `scramSha256`.  The policy never
  rejects a password.  The verifier is stored once the new password is saved: for a user with
  a local password, when that password changed; for an LDAP-linked user, when the new password
  validates against the directory.  Nothing is stored when the change is refused or fails, and
  an existing verifier stays as it was.
- **Password login**, by the authenticator `irc-credential-sync` ("IRC credential sync"):
  last in the direct-grant flow (after any second factor, so it runs only for a complete
  login), and directly after the username/password form in the browser flow (only that form's
  request carries the password).  It derives a verifier when the user has none for
  the current password, or when the stored one is not a verifier of the password just proven
  (this is what repairs an LDAP-linked user whose password changed in the directory).  It
  never fails a login, and a login that proved no password changes nothing.

A password loaded pre-hashed through the admin API has no verifier until the user's first
password login.  An LDAP-linked user has no local password for the verifier to follow, so after
a password change made in the directory alone the old verifier is still served until the user
next logs in through Keycloak.  The same holds for a password change made through Keycloak
when the LDAP provider's "Validate password policy" switch is off (Keycloak's default): the
change goes to the directory without reaching any password policy, so the verifier is refreshed
only at the user's next password login.  Turn the switch on to refresh it at once.

The realm set-up tool also puts `irc-credential-sync` in place: it copies the flows the realm
has bound for direct grant and browser logins (the built-in ones or custom ones) to
`irc direct grant` and `irc browser`, adds the step as REQUIRED (in `irc direct grant` last,
after `irc-account-state`; in `irc browser` directly after the username/password form, in the
same sub-flow), and binds both copies to the realm.  If a
bound flow has no password step, the tool exits 1 and changes nothing.  The step is also what
makes the account page list the IRC login entry (read-only).

### Legacy attribute verifiers

Earlier versions kept the verifier in user attributes, and IRC servers deployed before the
credential still read them: `scram_sha256_{salt,iterations,stored_key,server_key}`, then X3's
`x3_scram_*` and `x3_scram_sha256_*` with the same suffixes.  The jar never leaves one it knows
is for a different password:

- a password set through Keycloak removes every legacy attribute when it stores the new
  verifier;
- a password login checks each family present against the password just proven and removes the
  ones that do not match or cannot be read, keeping the ones that match (servers that still read
  attributes need them).

The removal runs after the verifier is stored, in a transaction of its own, so a failed removal
never undoes or prevents the verifier or the password change.  It writes to Keycloak's own
database, where these attributes live, so it also works for a user linked to a READ_ONLY LDAP
provider.

Run `--drop-legacy-scram-attributes` (it removes those attributes from every user and prints how
many users it changed) only after every IRC server has stopped reading them.  It needs the
realm's unmanaged attribute policy to let an admin edit them (`ENABLED` or `ADMIN_EDIT`).

## ECDSA keys

A user can log in on IRC with an ECDSA P-256 key (SASL ECDSA-NIST256P-CHALLENGE).  The public
key is a credential of type `irc-ecdsa-pubkey`, at most one per user: storing a key replaces the
one there was.  It holds no secret; its `credentialData` is `{"publicKey": "<PEM>"}`, and the
read endpoint returns the same PEM as `ecdsaPublicKey`.

A key is accepted in any of three forms, with surrounding whitespace ignored: a PEM
`PUBLIC KEY` block, the base64 of the DER SubjectPublicKeyInfo, or the base64 of the raw point
(33-byte compressed, as `ecdsatool` prints it, or 65-byte uncompressed).  It is stored as one
canonical PEM (`-----BEGIN PUBLIC KEY-----`, base64 in 64-character lines, trailing newline),
the form OpenSSL's `PEM_read_bio_PUBKEY` reads.  Anything else is refused: a key on another
curve, a point that is not on P-256, input longer than 1024 characters, and anything that is not
a key.

- **The user** adds a key from the account page, which lists "IRC login (ECDSA key)" with a
  set-up action, the required action `irc-ecdsa-enroll` ("IRC: add an ECDSA key"): a form with
  one field, `publicKey`.  A key that is not accepted shows the form again with
  `irc-ecdsa-invalid-key`; the submitted text is not shown back.  As for any action started from
  the account page, Keycloak first asks a user whose login is older than the action's maximum
  authentication age (5 minutes by default) to log in again.  The user can remove the key there
  too.
- **An admin** can load a key through the admin API as a credential
  (`{"type": "irc-ecdsa-pubkey", "credentialData": "{\"publicKey\": \"...\"}"}`, any accepted
  form); a value that is not accepted is answered 400 and leaves the user's key as it was.

The realm set-up tool registers `irc-ecdsa-enroll` and enables it (it is not a default action, so
no user is asked for a key at login).  The account page lists the type only because
`irc-credential-sync` (in the flows the tool binds) names it as an optional reference category;
without that step in an enabled flow the entry is not shown.

## Certificates

A user can log in on IRC with a TLS client certificate (SASL EXTERNAL).  Each certificate is a
credential of type `irc-certfp`, one per certificate, named by two digests of its DER in
uppercase hex without separators: the SHA-512, its name in IRCv3 `draft/client-cert`, and the
SHA-256, by which the ircd and X3 look a certificate up.  It holds no secret: `credentialData` is
`{"sha256": "<64 hex>", "sha512": "<128 hex>"}` and `userLabel` is the name the user gave the
certificate (1 to 64 bytes of UTF-8, no control characters).  Nobody types a fingerprint: only the
IRC server, which saw the user connect with the certificate, adds one.

The IRC server manages them with a bearer token whose realm roles include `irc-manage-certfp`
(no token is 401, a token without the role is 403, checked before the user is looked up; an
unknown user is 404 `{"error": "user_not_found"}`; replies are sent with `Cache-Control: no-store`):

- `PUT /realms/{realm}/irc/certfp/{username}` with `{"sha256": "...", "sha512": "...", "name": "..."}`:
  201 added; 200 already present (both digests match one of the user's certificates; its name is
  kept, a repeated add never renames); 409 `{"error": "taken"}` when another user of the realm
  holds the SHA-256; 400 `{"error": "bad_fingerprint"}` for a digest that is not uppercase hex of
  its length, or when exactly one of the two digests matches a certificate the user already has;
  400 `{"error": "bad_name"}`.  A success carries the entry, as in the list below.
- `DELETE /realms/{realm}/irc/certfp/{username}/{sha512}`: 204, or 404 `{"error": "not_found"}`
  (also for a value that is not a well-formed SHA-512).
- `GET /realms/{realm}/irc/certfp/{username}`:
  `{"certificates": [{"sha512": "...", "sha256": "...", "name": "...", "createdDate": <ms>}]}`, oldest first.

An admin can also load one through the admin API as a credential
(`{"type": "irc-certfp", "userLabel": "<name>", "credentialData": "{\"sha256\": ..., \"sha512\": ...}"}`);
it goes through the same checks (400 for a malformed pair or name, 409 for a certificate another
user holds, nothing changed for one the user already has).

The user sees the certificates on the account page ("IRC login (certificate)") and can remove
them there; there is no set-up action, so the entry is shown only to a user who has one.  Adding
one from the account page (a required action reading the certificate the browser presented and
calling the same code) is a possible later addition.

**The attribute `x509_fingerprints` is an index derived from the credentials.**  After every add
and removal it is rewritten to exactly the SHA-256 values of the user's `irc-certfp` credentials
(one value each, 64 uppercase hex); the ircd's login lookup searches it.  The rewrite is part of
the same transaction as the change: if it fails, the change is undone too.  It is written through
Keycloak's own user storage, so it also works for a user linked to a READ_ONLY LDAP provider.

- Removal through the IRC endpoint rewrites it directly.  Removal on the account page (the
  account REST API and the account console's `delete_credential` action) and through the admin
  API (`DELETE /admin/realms/{realm}/users/{id}/credentials/{credentialId}`) does not reach this
  code, so the event listener **`irc-certfp-mirror`** rewrites it, in the same transaction, when
  those removals send their event.  It reconciles on any credential removal of the user.  If the
  rewrite fails it marks the transaction for rollback, so the removal is undone; the page may still
  report success.  The set-up tool adds the listener to the realm's event listeners, keeping the
  others, and **it must stay enabled**: without it those removals leave the removed certificate's
  SHA-256 in the attribute until the user's next add or removal through the IRC endpoint.
- **An IRC server must check `certFingerprints` in the read endpoint**, which is computed from the
  credentials, never from the attribute: accept a certificate login only when the presented SHA-256
  is in that list.  A value that is ever stale in the attribute then fails closed.
- **Values already in the attribute are overwritten**, including values with no credential behind
  them: the attribute is derived, never typed.  Before deploying, check for existing
  `x509_fingerprints` values (for example certificates set by hand) and enrol them as credentials,
  or they disappear at that user's next credential change.
- Users cannot edit it (the account REST API refuses with `error-user-attribute-read-only`); they
  can see it.  Admins can edit it, as the User Profile declaration below says, but a value an admin
  types is overwritten at the next change and never appears in `certFingerprints`.
- A certificate is `taken` when another user's attribute holds its SHA-256.  There is no unique
  constraint behind that check: two different users adding the same certificate at the same moment
  can both succeed, after which the ircd's lookup finds two users for it (and should refuse the login).

The set-up tool creates `irc-manage-certfp` beside `irc-read-credentials` (and grants both to
`--service-client`), declares `x509_fingerprints` in the realm's User Profile (multivalued, view
for `user` and `admin`, edit for `admin` only; the rest of the profile is left as it is), and adds
the `irc-certfp-mirror` listener.  The declaration is what lets the admin user representation show
the attribute in a realm whose unmanaged-attribute policy is off; the admin search by
`x509_fingerprints:<sha256>` finds the user either way.

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
