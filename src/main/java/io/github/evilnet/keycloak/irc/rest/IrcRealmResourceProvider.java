package io.github.evilnet.keycloak.irc.rest;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

/** Serves the IRC resources under {@code /realms/{realm}/irc/}. */
public class IrcRealmResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public IrcRealmResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        return new IrcCredentialsResource(session);
    }

    @Override
    public void close() {
    }
}
