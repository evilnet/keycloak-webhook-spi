package io.github.evilnet.keycloak.irc.certfp;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import jakarta.ws.rs.core.Response;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Stream;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.cache.UserCache;
import org.keycloak.services.ErrorResponse;

/**
 * Keeps the TLS client certificates a user logs in to IRC with (SASL EXTERNAL) as Keycloak
 * credentials of type {@value #TYPE}, one per certificate.  A certificate is named by two digests
 * of its DER, uppercase hex: the SHA-512 (its name on the wire in IRCv3 {@code draft/client-cert})
 * and the SHA-256 (what the ircd and the rest of the network look a certificate up by).
 * {@code credentialData} = {@code {"sha256": "...", "sha512": "..."}}, no {@code secretData}, and
 * {@code userLabel} = the name the user gave the certificate.
 *
 * <p>{@link #add} and {@link #remove} are the only ways in, whatever the source (the IRC server
 * through {@code /realms/{realm}/irc/certfp}, an admin-API load through {@link #createCredential}).
 * Only the IRC server, which saw the user connect with the certificate, can add one; there is no
 * typed fingerprint anywhere.  The extension point for adding one from the account page is a
 * required action that reads the certificate the browser presented and calls {@link #add}; the
 * metadata then names it as the create action.</p>
 *
 * <p>The user attribute {@value #ATTRIBUTE} is an index derived from these credentials: after every
 * change it holds exactly the SHA-256 values of the user's certificates ({@link #reconcile}).
 * The ircd's login lookup searches it.  Keycloak's own removals (account page, account console,
 * admin API) never call {@link #deleteCredential}; {@link IrcCertfpMirrorListener} reconciles after
 * them.</p>
 */
public class IrcCertfpCredentialProvider implements CredentialProvider<CredentialModel> {

    public static final String TYPE = "irc-certfp";
    public static final String ATTRIBUTE = "x509_fingerprints";

    public enum AddResult { ADDED, ALREADY_PRESENT, TAKEN, BAD_FINGERPRINT, BAD_NAME }

    /** One stored certificate. */
    public record Certificate(String credentialId, String sha256, String sha512, String name, Long createdDate) {
    }

    private static final Gson GSON = new Gson();

    private final KeycloakSession session;

    public IrcCertfpCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getType() {
        return TYPE;
    }

    /** No create action: a certificate is added from IRC.  Keycloak lists the type on the account page only for a user who has one. */
    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext context) {
        return CredentialTypeMetadata.builder()
                .type(TYPE)
                .category(CredentialTypeMetadata.Category.BASIC_AUTHENTICATION)
                .displayName("irc-certfp-display-name")
                .helpText("irc-certfp-help-text")
                .removeable(true)
                .build(session);
    }

    @Override
    public CredentialModel getCredentialFromModel(CredentialModel model) {
        return model;
    }

    /**
     * Adds a certificate the IRC server saw the user present.
     *
     * <ul>
     *   <li>{@code BAD_FINGERPRINT}: a digest is not uppercase hex of its length, or exactly one of the two
     *       matches a certificate the user already has (never two credentials sharing a digest);</li>
     *   <li>{@code BAD_NAME}: see {@link Fingerprints#acceptableName};</li>
     *   <li>{@code ALREADY_PRESENT}: both digests match one of the user's certificates, whose name is kept;</li>
     *   <li>{@code TAKEN}: another user of the realm holds the SHA-256 (looked up through {@value #ATTRIBUTE});</li>
     *   <li>{@code ADDED}: stored, and {@value #ATTRIBUTE} rewritten.</li>
     * </ul>
     * A failure to write the attribute throws, so the request's transaction rolls the credential back too.
     */
    public AddResult add(RealmModel realm, UserModel user, String sha256, String sha512, String name) {
        if (!Fingerprints.wellFormedSha256(sha256) || !Fingerprints.wellFormedSha512(sha512)) {
            return AddResult.BAD_FINGERPRINT;
        }
        if (!Fingerprints.acceptableName(name)) {
            return AddResult.BAD_NAME;
        }
        for (Certificate c : certificates(user)) {
            boolean same256 = c.sha256().equals(sha256);
            boolean same512 = c.sha512().equals(sha512);
            if (same256 && same512) {
                return AddResult.ALREADY_PRESENT;
            }
            if (same256 || same512) {
                return AddResult.BAD_FINGERPRINT;
            }
        }
        if (heldByAnother(realm, user, sha256)) {
            return AddResult.TAKEN;
        }
        JsonObject data = new JsonObject();
        data.addProperty("sha256", sha256);
        data.addProperty("sha512", sha512);
        CredentialModel model = new CredentialModel();
        model.setType(TYPE);
        model.setUserLabel(name);
        model.setCredentialData(GSON.toJson(data));
        model.setSecretData(null);
        model.setCreatedDate(Time.currentTimeMillis());
        user.credentialManager().createStoredCredential(model);
        reconcile(session, realm, user.getId());
        return AddResult.ADDED;
    }

    /**
     * Removes the user's certificate with this SHA-512, every credential that holds it (concurrent adds can
     * store one certificate twice), and rewrites {@value #ATTRIBUTE}; false when there is none (or the value
     * is malformed).
     */
    public boolean remove(RealmModel realm, UserModel user, String sha512) {
        if (!Fingerprints.wellFormedSha512(sha512)) {
            return false;
        }
        List<String> ids = stored(user).filter(c -> c.sha512().equals(sha512)).map(Certificate::credentialId).toList();
        if (ids.isEmpty()) {
            return false;
        }
        ids.forEach(id -> user.credentialManager().removeStoredCredentialById(id));
        reconcile(session, realm, user.getId());
        return true;
    }

    /**
     * The user's certificates, oldest first, each once: a certificate stored more than once (concurrent adds)
     * is listed under its oldest credential.  A credential whose data is not a well-formed pair is left out.
     */
    public List<Certificate> certificates(UserModel user) {
        return oncePerCertificate(stored(user)
                .sorted(Comparator.comparing(Certificate::createdDate, Comparator.nullsFirst(Comparator.naturalOrder())))
                .toList());
    }

    /** Keeps the first entry of each SHA-512, in order. */
    static List<Certificate> oncePerCertificate(List<Certificate> oldestFirst) {
        Map<String, Certificate> first = new LinkedHashMap<>();
        oldestFirst.forEach(c -> first.putIfAbsent(c.sha512(), c));
        return List.copyOf(first.values());
    }

    /** Every well-formed certificate credential of the user, duplicates included, in no particular order. */
    private static Stream<Certificate> stored(UserModel user) {
        return user.credentialManager().getStoredCredentialsByTypeStream(TYPE)
                .map(IrcCertfpCredentialProvider::certificateOf)
                .filter(Objects::nonNull);
    }

    /** The SHA-256 values of the user's certificates, oldest first: what {@value #ATTRIBUTE} must hold. */
    public List<String> sha256s(UserModel user) {
        return certificates(user).stream().map(Certificate::sha256).toList();
    }

    /**
     * Admin-API load ({@code {"type": "irc-certfp", "userLabel": name, "credentialData": "{\"sha256\":…,\"sha512\":…}"}}):
     * goes through {@link #add}.  A malformed pair or name is answered 400, a certificate another user holds 409;
     * one the user already has is kept as it is.
     */
    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, CredentialModel credential) {
        JsonObject data = jsonObject(credential.getCredentialData());
        String sha256 = stringField(data, "sha256");
        String sha512 = stringField(data, "sha512");
        switch (add(realm, user, sha256, sha512, credential.getUserLabel())) {
            case ADDED, ALREADY_PRESENT:
                return user.credentialManager().getStoredCredentialsByTypeStream(TYPE)
                        .filter(c -> {
                            Certificate cert = certificateOf(c);
                            return cert != null && cert.sha512().equals(sha512);
                        })
                        .findFirst().orElseThrow();
            case TAKEN:
                throw ErrorResponse.error(TYPE + ": certificate held by another user", Response.Status.CONFLICT);
            case BAD_NAME:
                throw ErrorResponse.error(TYPE + ": userLabel must be 1 to 64 bytes of UTF-8 without control characters",
                        Response.Status.BAD_REQUEST);
            default:
                throw ErrorResponse.error(TYPE + ": credentialData must be {\"sha256\": 64 uppercase hex, \"sha512\": 128 uppercase hex}",
                        Response.Status.BAD_REQUEST);
        }
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        boolean removed = user.credentialManager().removeStoredCredentialById(credentialId);
        reconcile(session, realm, user.getId());
        return removed;
    }

    /**
     * Rewrites the user's {@value #ATTRIBUTE} to exactly the SHA-256 values of their certificates, when it
     * differs ({@link #sameValues}: the stored values have no defined order).  Values with no certificate
     * behind them are dropped.  Writes through Keycloak's local
     * (database) user model and then evicts the user from the cache: the federated model of a READ_ONLY
     * LDAP provider refuses every attribute write ({@code ReadOnlyException}), while the attribute lives in
     * Keycloak's own database for an imported LDAP user as for any other.  A user with no local record (an
     * LDAP provider without import) is written through the normal model.  Errors propagate to the caller.
     *
     * @return true when the attribute was rewritten
     */
    public static boolean reconcile(KeycloakSession session, RealmModel realm, String userId) {
        UserModel local = session.getProvider(UserProvider.class).getUserById(realm, userId);
        UserModel user = local != null ? local : session.users().getUserById(realm, userId);
        if (user == null) {
            return false;
        }
        List<String> want = new IrcCertfpCredentialProvider(session).sha256s(user);
        List<String> have = user.getAttributeStream(ATTRIBUTE).toList();
        if (sameValues(want, have)) {
            return false;
        }
        if (want.isEmpty()) {
            user.removeAttribute(ATTRIBUTE);
        } else {
            user.setAttribute(ATTRIBUTE, want);
        }
        UserCache cache = session.getProvider(UserCache.class);
        if (local != null && cache != null) {
            cache.evict(realm, local);
        }
        return true;
    }

    /** True when {@code stored} holds exactly the values of {@code wanted} (distinct), in any order and each once. */
    static boolean sameValues(List<String> wanted, List<String> stored) {
        return wanted.size() == stored.size() && new HashSet<>(wanted).equals(new HashSet<>(stored));
    }

    /** True when a user of the realm other than {@code user} has {@code sha256} in {@value #ATTRIBUTE}. */
    private boolean heldByAnother(RealmModel realm, UserModel user, String sha256) {
        return session.getProvider(UserProvider.class).searchForUserByUserAttributeStream(realm, ATTRIBUTE, sha256)
                .anyMatch(u -> !u.getId().equals(user.getId()));
    }

    private static Certificate certificateOf(CredentialModel c) {
        JsonObject data = jsonObject(c.getCredentialData());
        String sha256 = stringField(data, "sha256");
        String sha512 = stringField(data, "sha512");
        if (!Fingerprints.wellFormedSha256(sha256) || !Fingerprints.wellFormedSha512(sha512)) {
            return null;
        }
        return new Certificate(c.getId(), sha256, sha512, c.getUserLabel(), c.getCreatedDate());
    }

    private static JsonObject jsonObject(String json) {
        try {
            JsonElement e = json == null ? null : GSON.fromJson(json, JsonElement.class);
            return e != null && e.isJsonObject() ? e.getAsJsonObject() : null;
        } catch (RuntimeException e) {   // not JSON
            return null;
        }
    }

    private static String stringField(JsonObject o, String name) {
        if (o == null || !o.has(name)) {
            return null;
        }
        JsonElement v = o.get(name);
        return v.isJsonPrimitive() && v.getAsJsonPrimitive().isString() ? v.getAsString() : null;
    }

    @Override
    public void close() {
    }
}
