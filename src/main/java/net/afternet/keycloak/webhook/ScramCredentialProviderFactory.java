package net.afternet.keycloak.webhook;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory for ScramCredentialProvider.
 *
 * <p>This factory creates ScramCredentialProvider instances that intercept
 * password updates and generate SCRAM-SHA-256 credentials alongside the
 * standard password hash.</p>
 *
 * <p>The provider is registered via META-INF/services and automatically
 * loaded by Keycloak's SPI mechanism.</p>
 */
public class ScramCredentialProviderFactory implements CredentialProviderFactory<ScramCredentialProvider> {

    private static final Logger LOG = Logger.getLogger(ScramCredentialProviderFactory.class);

    public static final String PROVIDER_ID = "x3-scram-sha256";

    @Override
    public ScramCredentialProvider create(KeycloakSession session) {
        return new ScramCredentialProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        LOG.info("ScramCredentialProviderFactory initialized - SCRAM-SHA-256 credentials will be generated on password changes");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Nothing to do
    }

    @Override
    public void close() {
        // Nothing to close
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
