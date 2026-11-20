package io.github.evilnet.keycloak.irc.ecdsa;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import jakarta.ws.rs.core.Response;
import java.util.Optional;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ErrorResponse;

/**
 * Keeps a user's ECDSA P-256 public key for SASL ECDSA-NIST256P-CHALLENGE logins on IRC as a
 * Keycloak credential of type {@value #TYPE}, one per user: storing a key replaces the one
 * there was.  A public key is not a secret, so there is no {@code secretData};
 * {@code credentialData} = {@code {"publicKey": "<canonical PEM>"}} (see {@link EcdsaPublicKeys}).
 *
 * <p>The user adds it from the account page ({@value IrcEcdsaEnrollActionFactory#PROVIDER_ID})
 * and may remove it there; an admin may load one through the admin API, where a value that is
 * not a P-256 public key is answered 400.</p>
 */
public class IrcEcdsaCredentialProvider implements CredentialProvider<CredentialModel> {

    public static final String TYPE = "irc-ecdsa-pubkey";

    private static final Gson GSON = new Gson();

    private final KeycloakSession session;

    public IrcEcdsaCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public String getType() {
        return TYPE;
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext context) {
        return CredentialTypeMetadata.builder()
                .type(TYPE)
                .category(CredentialTypeMetadata.Category.BASIC_AUTHENTICATION)
                .displayName("irc-ecdsa-display-name")
                .helpText("irc-ecdsa-help-text")
                .createAction(IrcEcdsaEnrollActionFactory.PROVIDER_ID)
                .removeable(true)
                .build(session);
    }

    @Override
    public CredentialModel getCredentialFromModel(CredentialModel model) {
        return model;
    }

    /** Normalises the key to the canonical PEM and replaces any key the user has; a bad key is refused with 400. */
    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, CredentialModel credential) {
        String pem;
        try {
            pem = EcdsaPublicKeys.toPem(publicKeyOf(credential.getCredentialData()));
        } catch (IllegalArgumentException e) {
            throw ErrorResponse.error(TYPE + ": not an ECDSA P-256 public key", Response.Status.BAD_REQUEST);
        }
        JsonObject data = new JsonObject();
        data.addProperty("publicKey", pem);
        credential.setType(TYPE);
        credential.setCredentialData(GSON.toJson(data));
        credential.setSecretData(null);
        if (credential.getCreatedDate() == null) {
            credential.setCreatedDate(Time.currentTimeMillis());
        }
        removeExisting(user);
        return user.credentialManager().createStoredCredential(credential);
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        return user.credentialManager().removeStoredCredentialById(credentialId);
    }

    /** Stores {@code publicKey} (any form {@link EcdsaPublicKeys#toPem} accepts) as the user's key, replacing any other. */
    public void store(RealmModel realm, UserModel user, String publicKey) {
        JsonObject data = new JsonObject();
        data.addProperty("publicKey", publicKey);
        CredentialModel model = new CredentialModel();
        model.setCredentialData(GSON.toJson(data));
        createCredential(realm, user, model);
    }

    /** The user's key as canonical PEM; empty when absent or not a P-256 public key. */
    public Optional<String> current(UserModel user) {
        return user.credentialManager().getStoredCredentialsByTypeStream(TYPE).findFirst().flatMap(c -> {
            try {
                return Optional.of(EcdsaPublicKeys.toPem(publicKeyOf(c.getCredentialData())));
            } catch (IllegalArgumentException e) {
                return Optional.empty();
            }
        });
    }

    private void removeExisting(UserModel user) {
        user.credentialManager().getStoredCredentialsByTypeStream(TYPE)
                .map(CredentialModel::getId).toList()
                .forEach(id -> user.credentialManager().removeStoredCredentialById(id));
    }

    /** The {@code publicKey} string of a credentialData JSON; null when there is none. */
    private static String publicKeyOf(String credentialData) {
        try {
            JsonObject o = credentialData == null ? null : GSON.fromJson(credentialData, JsonObject.class);
            return o == null || !o.has("publicKey") || !o.get("publicKey").isJsonPrimitive()
                    ? null : o.get("publicKey").getAsString();
        } catch (RuntimeException e) {   // not JSON, or not an object
            return null;
        }
    }

    @Override
    public void close() {
    }
}
