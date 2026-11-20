package io.github.evilnet.keycloak.irc.rest;

import io.github.evilnet.keycloak.irc.ecdsa.IrcEcdsaCredentialProvider;
import io.github.evilnet.keycloak.irc.scram.IrcScramCredentialProvider;
import io.github.evilnet.keycloak.irc.scram.ScramVerifier;
import io.github.evilnet.keycloak.irc.state.AccountState;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;

/**
 * {@code GET /realms/{realm}/irc/credentials/{username}}: the credentials an IRC server verifies
 * itself and whether the account may log in.  The caller needs a bearer token carrying the realm
 * role {@value #ROLE}.  The response holds the SCRAM StoredKey/ServerKey, so it is never cached
 * and never logged.
 */
public class IrcCredentialsResource {

    public static final String ROLE = "irc-read-credentials";

    private final KeycloakSession session;

    public IrcCredentialsResource(KeycloakSession session) {
        this.session = session;
    }

    @GET
    @Path("credentials/{username}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response credentials(@PathParam("username") String username) {
        RealmModel realm = session.getContext().getRealm();
        AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session)
                .setRealm(realm)
                .setConnection(session.getContext().getConnection())
                .setHeaders(session.getContext().getRequestHeaders())
                .authenticate();
        if (auth == null) {
            return reply(Response.Status.UNAUTHORIZED, Map.of("error", "unauthorized"));
        }
        AccessToken.Access access = auth.getToken().getRealmAccess();
        if (access == null || !access.isUserInRole(ROLE)) {
            return reply(Response.Status.FORBIDDEN, Map.of("error", "forbidden"));
        }
        UserModel user = session.users().getUserByUsername(realm, username);
        if (user == null) {
            return reply(Response.Status.NOT_FOUND, Map.of("error", "user_not_found"));
        }

        AccountState state = AccountState.forUser(realm, user);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", user.getId());
        body.put("username", user.getUsername());
        body.put("state", state.state());
        body.put("reasons", state.reasons());
        Optional<ScramVerifier> scram = new IrcScramCredentialProvider(session).current(user);
        scram.ifPresent(v -> body.put("scram", scramBody(v)));
        new IrcEcdsaCredentialProvider(session).current(user).ifPresent(pem -> body.put("ecdsaPublicKey", pem));
        return reply(Response.Status.OK, body);
    }

    private static Map<String, Object> scramBody(ScramVerifier v) {
        Base64.Encoder b64 = Base64.getEncoder();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("salt", b64.encodeToString(v.salt()));
        m.put("iterations", v.iterations());
        m.put("storedKey", b64.encodeToString(v.storedKey()));
        m.put("serverKey", b64.encodeToString(v.serverKey()));
        return m;
    }

    private static Response reply(Response.Status status, Object body) {
        return Response.status(status).entity(body).type(MediaType.APPLICATION_JSON)
                .header("Cache-Control", "no-store").build();
    }
}
