package io.github.evilnet.keycloak.irc.rest;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Map;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager.AuthResult;

/**
 * What every IRC resource does first: a bearer token valid for this realm (else 401) that carries a
 * realm role (else 403), checked before any user is looked up, so a caller without the role learns
 * nothing about whether a user exists.  Replies are JSON and never cached.
 */
final class RoleGate {

    private RoleGate() {
    }

    /** Null when the request's bearer token is valid for the realm and has the realm role {@code role}; otherwise the 401 or 403 reply. */
    static Response refusal(KeycloakSession session, String role) {
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
        if (access == null || !access.isUserInRole(role)) {
            return reply(Response.Status.FORBIDDEN, Map.of("error", "forbidden"));
        }
        return null;
    }

    static Response userNotFound() {
        return reply(Response.Status.NOT_FOUND, Map.of("error", "user_not_found"));
    }

    static Response reply(Response.Status status, Object body) {
        return Response.status(status).entity(body).type(MediaType.APPLICATION_JSON)
                .header("Cache-Control", "no-store").build();
    }
}
