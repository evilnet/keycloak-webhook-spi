package io.github.evilnet.keycloak.irc.ecdsa;

import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * The {@value IrcEcdsaEnrollActionFactory#PROVIDER_ID} required action: a form with one textarea,
 * {@code publicKey}.  A key {@link EcdsaPublicKeys#toPem} accepts is stored as the user's
 * {@code irc-ecdsa-pubkey} credential, replacing any other, and the action completes; anything
 * else shows the form again with {@code irc-ecdsa-invalid-key}.  The submitted text is never
 * shown back.  Started from the account page (an application-initiated action), under
 * Keycloak's usual maximum authentication age.
 */
public class IrcEcdsaEnrollAction implements RequiredActionProvider, CredentialRegistrator {

    static final String FORM = "irc-ecdsa-enroll.ftl";
    static final String FIELD = "publicKey";

    @Override
    public InitiatedActionSupport initiatedActionSupport() {
        return InitiatedActionSupport.SUPPORTED;
    }

    @Override
    public String getCredentialType(KeycloakSession session, AuthenticationSessionModel authenticationSession) {
        return IrcEcdsaCredentialProvider.TYPE;
    }

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        context.challenge(context.form().createForm(FORM));
    }

    @Override
    public void processAction(RequiredActionContext context) {
        context.getEvent().event(EventType.UPDATE_CREDENTIAL).detail(Details.CREDENTIAL_TYPE, IrcEcdsaCredentialProvider.TYPE);
        String pem;
        try {
            pem = EcdsaPublicKeys.toPem(context.getHttpRequest().getDecodedFormParameters().getFirst(FIELD));
        } catch (IllegalArgumentException e) {
            context.challenge(context.form().setError("irc-ecdsa-invalid-key").createForm(FORM));
            return;
        }
        new IrcEcdsaCredentialProvider(context.getSession()).store(context.getRealm(), context.getUser(), pem);
        context.success();
    }

    @Override
    public void close() {
    }
}
