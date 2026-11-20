package io.github.evilnet.keycloak.irc.rest;

import io.github.evilnet.keycloak.irc.certfp.IrcCertfpCredentialProvider;
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

/**
 * {@code GET /realms/{realm}/irc/credentials/{username}}: the credentials an IRC server verifies
 * itself and whether the account may log in.  The caller needs a bearer token carrying the realm
 * role {@value #ROLE}.  The response holds the SCRAM StoredKey/ServerKey, so it is never cached
 * and never logged.
 *
 * <p>{@code certFingerprints} lists the SHA-256 of each of the user's certificates, computed from the
 * {@code irc-certfp} credentials (never from the {@code x509_fingerprints} attribute, which is only the
 * search index): an IRC server accepts a certificate login only when the presented SHA-256 is in it.</p>
 */
public class IrcCredentialsResource {

    public static final String ROLE = "irc-read-credentials";

    private final KeycloakSession session;

    public IrcCredentialsResource(KeycloakSession session) {
        this.session = session;
    }

    @GET
    @Path("{username}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response credentials(@PathParam("username") String username) {
        Response refused = RoleGate.refusal(session, ROLE);
        if (refused != null) {
            return refused;
        }
        RealmModel realm = session.getContext().getRealm();
        UserModel user = session.users().getUserByUsername(realm, username);
        if (user == null) {
            return RoleGate.userNotFound();
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
        body.put("certFingerprints", new IrcCertfpCredentialProvider(session).sha256s(user));
        return RoleGate.reply(Response.Status.OK, body);
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
}
