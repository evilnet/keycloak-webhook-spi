package net.afternet.keycloak.webhook;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PasswordPolicyProviderFactory;

/**
 * Factory for ScramPasswordPolicyProvider.
 *
 * <p>This factory creates password policy providers that generate SCRAM-SHA-256
 * credentials when passwords are set through Keycloak's interactive flows.</p>
 *
 * <p>To enable this policy, add "x3Scram" to the realm's password policy:</p>
 * <pre>
 *   Realm Settings -> Authentication -> Password Policy -> Add Policy -> x3Scram
 * </pre>
 *
 * <p>Or via Admin API:</p>
 * <pre>
 *   PUT /admin/realms/{realm}
 *   { "passwordPolicy": "x3Scram and length(8) and ..." }
 * </pre>
 */
public class ScramPasswordPolicyProviderFactory implements PasswordPolicyProviderFactory {

    private static final Logger LOG = Logger.getLogger(ScramPasswordPolicyProviderFactory.class);

    public static final String PROVIDER_ID = "x3Scram";
    public static final String DISPLAY_NAME = "X3 SCRAM-SHA-256";

    @Override
    public PasswordPolicyProvider create(KeycloakSession session) {
        return new ScramPasswordPolicyProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        LOG.info("ScramPasswordPolicyProviderFactory initialized - SCRAM-SHA-256 credentials will be generated when this policy is enabled");
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

    @Override
    public String getDisplayName() {
        return DISPLAY_NAME;
    }

    @Override
    public String getConfigType() {
        // No configuration needed - return null for policies without config
        return null;
    }

    @Override
    public String getDefaultConfigValue() {
        return null;
    }

    @Override
    public boolean isMultiplSupported() {
        // Only one instance needed
        return false;
    }
}
