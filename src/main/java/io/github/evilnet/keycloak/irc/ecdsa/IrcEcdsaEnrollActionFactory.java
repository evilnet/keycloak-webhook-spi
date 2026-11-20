package io.github.evilnet.keycloak.irc.ecdsa;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Registers the {@value #PROVIDER_ID} required action.  A realm has it once it is registered and
 * enabled there (tools/irc_realm_setup.py does both, and leaves it off the default actions).
 */
public class IrcEcdsaEnrollActionFactory implements RequiredActionFactory {

    public static final String PROVIDER_ID = "irc-ecdsa-enroll";

    private static final IrcEcdsaEnrollAction SINGLETON = new IrcEcdsaEnrollAction();

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayText() {
        return "IRC: add an ECDSA key";
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
}
