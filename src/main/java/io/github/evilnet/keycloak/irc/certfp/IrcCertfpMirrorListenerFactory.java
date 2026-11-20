package io.github.evilnet.keycloak.irc.certfp;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/** Registers the event listener {@value #ID}; a realm enables it in its {@code eventsListeners}. */
public class IrcCertfpMirrorListenerFactory implements EventListenerProviderFactory {

    public static final String ID = "irc-certfp-mirror";

    @Override
    public EventListenerProvider create(KeycloakSession session) {
        return new IrcCertfpMirrorListener(session);
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
