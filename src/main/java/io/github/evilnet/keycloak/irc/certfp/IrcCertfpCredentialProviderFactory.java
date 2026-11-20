package io.github.evilnet.keycloak.irc.certfp;

import org.keycloak.Config;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/** Registers the {@code irc-certfp} credential type. */
public class IrcCertfpCredentialProviderFactory implements CredentialProviderFactory<IrcCertfpCredentialProvider> {

    @Override
    public IrcCertfpCredentialProvider create(KeycloakSession session) {
        return new IrcCertfpCredentialProvider(session);
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
        return IrcCertfpCredentialProvider.TYPE;
    }
}
