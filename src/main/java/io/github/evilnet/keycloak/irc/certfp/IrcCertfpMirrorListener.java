package io.github.evilnet.keycloak.irc.certfp;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Keeps {@value IrcCertfpCredentialProvider#ATTRIBUTE} equal to the user's certificates after Keycloak's
 * own credential removals, which go straight to the credential store and never reach
 * {@link IrcCertfpCredentialProvider#deleteCredential}: the account REST API and the account console's
 * {@code delete_credential} action (user event {@code REMOVE_CREDENTIAL}), and the admin API
 * ({@code DELETE users/{id}/credentials/{credentialId}}, recorded as an admin event of operation
 * {@code ACTION} on that path, naming no credential type).
 *
 * <p>Each of those removes the credential before it sends its event, and listeners run in the request's
 * transaction, so the listener reconciles there ({@link IrcCertfpCredentialProvider#reconcile}: recompute,
 * write only when it differs).  It does so for any credential removal of the user, which costs a read when
 * nothing differs.  Keycloak catches a listener's exception, so a failed write marks the transaction
 * rollback-only instead: the removal is undone with it, and the credential and its index value stay
 * together.  The listener works only for a realm that lists it in {@code eventsListeners}.</p>
 */
public class IrcCertfpMirrorListener implements EventListenerProvider {

    private static final Logger LOG = Logger.getLogger(IrcCertfpMirrorListener.class);
    private static final Pattern CREDENTIAL_PATH = Pattern.compile("users/([^/]+)/credentials/[^/]+");

    private final KeycloakSession session;

    public IrcCertfpMirrorListener(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public void onEvent(Event event) {
        if (event.getType() == EventType.REMOVE_CREDENTIAL && event.getUserId() != null) {
            reconcile(event.getRealmId(), event.getUserId());
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        // Keycloak 26 records the admin removal as ACTION; DELETE is accepted too, should that change.
        OperationType op = event.getOperationType();
        if ((op != OperationType.ACTION && op != OperationType.DELETE) || event.getResourceType() != ResourceType.USER
                || event.getResourcePath() == null) {
            return;
        }
        Matcher m = CREDENTIAL_PATH.matcher(event.getResourcePath());
        if (m.matches()) {
            reconcile(event.getRealmId(), m.group(1));
        }
    }

    private void reconcile(String realmId, String userId) {
        try {
            RealmModel realm = session.realms().getRealm(realmId);
            if (realm != null) {
                IrcCertfpCredentialProvider.reconcile(session, realm, userId);
            }
        } catch (RuntimeException e) {
            LOG.errorf("%s: could not rewrite %s for user %s (%s); rolling the removal back",
                    IrcCertfpMirrorListenerFactory.ID, IrcCertfpCredentialProvider.ATTRIBUTE, userId, e.getClass().getName());
            session.getTransactionManager().setRollbackOnly();
        }
    }

    @Override
    public void close() {
    }
}
