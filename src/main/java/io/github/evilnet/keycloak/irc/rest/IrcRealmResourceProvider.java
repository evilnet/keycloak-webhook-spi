package io.github.evilnet.keycloak.irc.rest;

import jakarta.ws.rs.Path;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

/**
 * Serves the IRC resources under {@code /realms/{realm}/irc/}: {@code credentials/{username}}
 * ({@link IrcCredentialsResource}) and {@code certfp/{username}} ({@link IrcCertfpResource}).
 */
public class IrcRealmResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public IrcRealmResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Path("credentials")
    public IrcCredentialsResource credentials() {
        return new IrcCredentialsResource(session);
    }

    @Path("certfp")
    public IrcCertfpResource certfp() {
        return new IrcCertfpResource(session);
    }

    @Override
    public void close() {
    }
}
