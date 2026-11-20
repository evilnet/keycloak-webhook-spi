package io.github.evilnet.keycloak.irc.login;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/** Registers the {@value #PROVIDER_ID} authenticator, for direct-grant flows. */
public class IrcAccountStateAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "irc-account-state";

    private static final IrcAccountStateAuthenticator SINGLETON = new IrcAccountStateAuthenticator();
    private static final Requirement[] CHOICES = {Requirement.REQUIRED, Requirement.DISABLED};

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "IRC account state";
    }

    @Override
    public String getHelpText() {
        return "Direct grant only; place last, after the password step and every other factor. Refuses an account that is not fully "
                + "set up as Keycloak would, adding irc_state and irc_reasons to the error response.";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
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
