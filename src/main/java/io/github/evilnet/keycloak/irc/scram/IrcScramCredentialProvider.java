package io.github.evilnet.keycloak.irc.scram;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;

/**
 * Keeps a user's SCRAM-SHA-256 verifier as a Keycloak credential of type
 * {@value #TYPE}, instead of plain user attributes.  Keycloak never returns a
 * credential's {@code secretData} through the admin API, so the StoredKey and ServerKey
 * stay unreadable to anything that can only read users.
 *
 * <p>Stored form: {@code secretData} = {@code {"storedKey": b64, "serverKey": b64}};
 * {@code credentialData} = {@code {"salt": b64, "iterations": n, "passwordFingerprint": hex}}.</p>
 *
 * <p>The fingerprint binds the verifier to the password it was derived from: it is a
 * SHA-256 over the stored password credentials' secret data, so it changes whenever the
 * password does and a stale verifier can be told apart.</p>
 */
public class IrcScramCredentialProvider implements CredentialProvider<CredentialModel> {

    public static final String TYPE = "irc-scram-sha256";

    private static final Gson GSON = new Gson();

    private final KeycloakSession session;

    public IrcScramCredentialProvider(KeycloakSession session) {
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
                .displayName("irc-scram-display-name")
                .helpText("irc-scram-help-text")
                .removeable(false)
                .build(session);
    }

    @Override
    public CredentialModel getCredentialFromModel(CredentialModel model) {
        return model;
    }

    /** The admin API path: stores what it is given and binds it to the fingerprint at this moment. */
    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, CredentialModel credential) {
        JsonObject data = parse(credential.getCredentialData());
        data.addProperty("passwordFingerprint", passwordFingerprint(user));
        credential.setType(TYPE);
        credential.setCredentialData(GSON.toJson(data));
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

    /** Replaces any existing verifier of the user and binds the new one to the current password. */
    public void store(RealmModel realm, UserModel user, ScramVerifier v) {
        Base64.Encoder b64 = Base64.getEncoder();
        JsonObject secret = new JsonObject();
        secret.addProperty("storedKey", b64.encodeToString(v.storedKey()));
        secret.addProperty("serverKey", b64.encodeToString(v.serverKey()));
        JsonObject data = new JsonObject();
        data.addProperty("salt", b64.encodeToString(v.salt()));
        data.addProperty("iterations", v.iterations());
        CredentialModel model = new CredentialModel();
        model.setSecretData(GSON.toJson(secret));
        model.setCredentialData(GSON.toJson(data));
        createCredential(realm, user, model);
    }

    /** The user's verifier; empty when absent, malformed, or bound to a password that is no longer the current one. */
    public Optional<ScramVerifier> current(UserModel user) {
        Optional<CredentialModel> stored = user.credentialManager().getStoredCredentialsByTypeStream(TYPE).findFirst();
        if (stored.isEmpty()) {
            return Optional.empty();
        }
        try {
            JsonObject data = parse(stored.get().getCredentialData());
            JsonObject secret = parse(stored.get().getSecretData());
            if (!passwordFingerprint(user).equals(data.get("passwordFingerprint").getAsString())) {
                return Optional.empty();
            }
            Base64.Decoder b64 = Base64.getDecoder();
            return Optional.of(new ScramVerifier(
                    b64.decode(data.get("salt").getAsString()),
                    data.get("iterations").getAsInt(),
                    b64.decode(secret.get("storedKey").getAsString()),
                    b64.decode(secret.get("serverKey").getAsString())));
        } catch (RuntimeException e) {   // missing field, bad base64, bad JSON: no usable verifier
            return Optional.empty();
        }
    }

    /**
     * Lowercase hex SHA-256 over the secret data of the user's stored password credentials,
     * ordered by credential id; {@code ""} when the user has none.
     */
    public static String passwordFingerprint(UserModel user) {
        List<CredentialModel> passwords = user.credentialManager()
                .getStoredCredentialsByTypeStream(PasswordCredentialModel.TYPE)
                .sorted(Comparator.comparing(CredentialModel::getId))
                .toList();
        if (passwords.isEmpty()) {
            return "";
        }
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            for (CredentialModel c : passwords) {
                sha.update(c.getSecretData().getBytes(StandardCharsets.UTF_8));
            }
            return HexFormat.of().formatHex(sha.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private void removeExisting(UserModel user) {
        user.credentialManager().getStoredCredentialsByTypeStream(TYPE)
                .map(CredentialModel::getId).toList()
                .forEach(id -> user.credentialManager().removeStoredCredentialById(id));
    }

    private static JsonObject parse(String json) {
        try {
            JsonObject o = json == null ? null : GSON.fromJson(json, JsonObject.class);
            return o == null ? new JsonObject() : o;
        } catch (JsonParseException e) {
            return new JsonObject();
        }
    }

    @Override
    public void close() {
    }
}
