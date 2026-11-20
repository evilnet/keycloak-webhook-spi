package io.github.evilnet.keycloak.irc.login;

import io.github.evilnet.keycloak.irc.certfp.IrcCertfpCredentialProvider;
import io.github.evilnet.keycloak.irc.ecdsa.IrcEcdsaCredentialProvider;
import io.github.evilnet.keycloak.irc.scram.IrcScramCredentialProvider;
import java.util.List;
import java.util.Set;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Registers the {@value #PROVIDER_ID} authenticator.  Its reference category is the
 * {@code irc-scram-sha256} credential type, and {@code irc-ecdsa-pubkey} and {@code irc-certfp} optional ones:
 * Keycloak's account page lists a credential type only when an enabled execution in one of the
 * realm's flows names it this way.
 */
public class IrcCredentialSyncAuthenticatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "irc-credential-sync";

    private static final IrcCredentialSyncAuthenticator SINGLETON = new IrcCredentialSyncAuthenticator();
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
        return "IRC credential sync";
    }

    @Override
    public String getHelpText() {
        return "Place after the password step: last in a direct-grant flow, directly after the password form "
                + "in a browser flow. Keeps the user's SCRAM-SHA-256 verifier for IRC logins "
                + "in step with the password just proven. Never fails a login.";
    }

    @Override
    public String getReferenceCategory() {
        return IrcScramCredentialProvider.TYPE;
    }

    /** The ECDSA key and certificate types are listed on the account page through this step too; no flow step of their own reads them. */
    @Override
    public Set<String> getOptionalReferenceCategories(KeycloakSession session) {
        return Set.of(IrcEcdsaCredentialProvider.TYPE, IrcCertfpCredentialProvider.TYPE);
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
