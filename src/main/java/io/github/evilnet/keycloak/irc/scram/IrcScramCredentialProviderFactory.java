package io.github.evilnet.keycloak.irc.scram;

import org.keycloak.Config;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/** Registers the {@code irc-scram-sha256} credential type. */
public class IrcScramCredentialProviderFactory implements CredentialProviderFactory<IrcScramCredentialProvider> {

    @Override
    public IrcScramCredentialProvider create(KeycloakSession session) {
        return new IrcScramCredentialProvider(session);
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
        return IrcScramCredentialProvider.TYPE;
    }
}
