package io.github.evilnet.keycloak.irc.ecdsa;

import org.keycloak.Config;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/** Registers the {@code irc-ecdsa-pubkey} credential type. */
public class IrcEcdsaCredentialProviderFactory implements CredentialProviderFactory<IrcEcdsaCredentialProvider> {

    @Override
    public IrcEcdsaCredentialProvider create(KeycloakSession session) {
        return new IrcEcdsaCredentialProvider(session);
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
        return IrcEcdsaCredentialProvider.TYPE;
    }
}
