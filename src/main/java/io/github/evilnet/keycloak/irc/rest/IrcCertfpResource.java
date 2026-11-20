package io.github.evilnet.keycloak.irc.rest;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import io.github.evilnet.keycloak.irc.certfp.Fingerprints;
import io.github.evilnet.keycloak.irc.certfp.IrcCertfpCredentialProvider;
import io.github.evilnet.keycloak.irc.certfp.IrcCertfpCredentialProvider.AddResult;
import io.github.evilnet.keycloak.irc.certfp.IrcCertfpCredentialProvider.Certificate;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.LinkedHashMap;
import java.util.Map;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * {@code /realms/{realm}/irc/certfp/{username}}: the IRC server adds, lists and removes a user's
 * certificates (IRCv3 {@code draft/client-cert}).  The caller needs a bearer token carrying the realm
 * role {@value #ROLE}.  This class only translates HTTP to {@link IrcCertfpCredentialProvider#add} and
 * {@link IrcCertfpCredentialProvider#remove} and back.
 *
 * <ul>
 *   <li>{@code PUT} with {@code {"sha256", "sha512", "name"}}: 201 added, 200 already present (name kept),
 *       409 {@code taken}, 400 {@code bad_fingerprint} or {@code bad_name}; a success carries the entry.</li>
 *   <li>{@code DELETE .../{sha512}}: 204, or 404 {@code not_found} (also for a malformed value).</li>
 *   <li>{@code GET}: 200 {@code {"certificates": [{"sha512", "sha256", "name", "createdDate"}]}}, oldest first.</li>
 * </ul>
 * A {@code name} is replied only when {@link Fingerprints#acceptableName} accepts it, otherwise as
 * {@value Fingerprints#INVALID_NAME}: Keycloak's own label routes can store any name.
 * An unknown user is 404 {@code user_not_found}.
 */
public class IrcCertfpResource {

    public static final String ROLE = "irc-manage-certfp";

    private static final Gson GSON = new Gson();

    private final KeycloakSession session;

    public IrcCertfpResource(KeycloakSession session) {
        this.session = session;
    }

    @PUT
    @Path("{username}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response add(@PathParam("username") String username, String body) {
        Response refused = RoleGate.refusal(session, ROLE);
        if (refused != null) {
            return refused;
        }
        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserByUsername(realm, username);
        if (user == null) {
            return RoleGate.userNotFound();
        }
        JsonObject o = jsonObject(body);
        String sha512 = stringField(o, "sha512");
        IrcCertfpCredentialProvider certs = new IrcCertfpCredentialProvider(session);
        AddResult result = certs.add(realm, user, stringField(o, "sha256"), sha512, stringField(o, "name"));
        return switch (result) {
            case ADDED -> RoleGate.reply(Response.Status.CREATED, entry(certs, user, sha512));
            case ALREADY_PRESENT -> RoleGate.reply(Response.Status.OK, entry(certs, user, sha512));
            case TAKEN -> RoleGate.reply(Response.Status.CONFLICT, Map.of("error", "taken"));
            case BAD_NAME -> RoleGate.reply(Response.Status.BAD_REQUEST, Map.of("error", "bad_name"));
            case BAD_FINGERPRINT -> RoleGate.reply(Response.Status.BAD_REQUEST, Map.of("error", "bad_fingerprint"));
        };
    }

    @DELETE
    @Path("{username}/{sha512}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response remove(@PathParam("username") String username, @PathParam("sha512") String sha512) {
        Response refused = RoleGate.refusal(session, ROLE);
        if (refused != null) {
            return refused;
        }
        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserByUsername(realm, username);
        if (user == null) {
            return RoleGate.userNotFound();
        }
        if (!new IrcCertfpCredentialProvider(session).remove(realm, user, sha512)) {
            return RoleGate.reply(Response.Status.NOT_FOUND, Map.of("error", "not_found"));
        }
        return Response.noContent().header("Cache-Control", "no-store").build();
    }

    @GET
    @Path("{username}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response list(@PathParam("username") String username) {
        Response refused = RoleGate.refusal(session, ROLE);
        if (refused != null) {
            return refused;
        }
        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserByUsername(realm, username);
        if (user == null) {
            return RoleGate.userNotFound();
        }
        return RoleGate.reply(Response.Status.OK, Map.of("certificates",
                new IrcCertfpCredentialProvider(session).certificates(user).stream().map(IrcCertfpResource::entry).toList()));
    }

    private static Map<String, Object> entry(IrcCertfpCredentialProvider certs, UserModel user, String sha512) {
        return certs.certificates(user).stream().filter(c -> c.sha512().equals(sha512))
                .findFirst().map(IrcCertfpResource::entry).orElseThrow();
    }

    private static Map<String, Object> entry(Certificate c) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("sha512", c.sha512());
        m.put("sha256", c.sha256());
        m.put("name", Fingerprints.nameForReply(c.name()));
        m.put("createdDate", c.createdDate());
        return m;
    }

    private static JsonObject jsonObject(String json) {
        try {
            JsonElement e = json == null ? null : GSON.fromJson(json, JsonElement.class);
            return e != null && e.isJsonObject() ? e.getAsJsonObject() : null;
        } catch (RuntimeException e) {   // not JSON: no field is well formed
            return null;
        }
    }

    private static String stringField(JsonObject o, String name) {
        JsonElement v = o == null ? null : o.get(name);
        return v != null && v.isJsonPrimitive() && v.getAsJsonPrimitive().isString() ? v.getAsString() : null;
    }
}
