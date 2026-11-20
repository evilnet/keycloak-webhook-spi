package io.github.evilnet.keycloak.irc.rest;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/** Registers the realm resource {@value #ID}. */
public class IrcRealmResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String ID = "irc";

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        return new IrcRealmResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }
}
