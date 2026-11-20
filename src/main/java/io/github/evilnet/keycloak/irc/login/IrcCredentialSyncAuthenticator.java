package io.github.evilnet.keycloak.irc.login;

import io.github.evilnet.keycloak.irc.AfterCommitJob;
import io.github.evilnet.keycloak.irc.scram.IrcScramCredentialProvider;
import io.github.evilnet.keycloak.irc.scram.LegacyScramAttributes;
import io.github.evilnet.keycloak.irc.scram.ScramVerifier;
import java.security.MessageDigest;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.CredentialRepresentation;

/**
 * Runs directly after the password step of a login flow and keeps the user's SCRAM-SHA-256
 * verifier in step with the password just proven.  Keycloak sees the plaintext password only
 * at password set and at login; this is the login half (the {@code scramSha256} password
 * policy is the other).
 *
 * <p>It also removes each legacy attribute verifier ({@link LegacyScramAttributes}) that is not
 * a verifier of the password just proven, and keeps the ones that are.</p>
 *
 * <p>It never fails a login: it always ends in {@code success()}, and a request without a
 * {@code password} form parameter (a login that did not prove a password) changes nothing.</p>
 *
 * <p>The work runs after the login's transaction has committed, as two {@link AfterCommitJob}s,
 * each in a transaction of its own: the verifier first, then the legacy attributes, so a failed
 * attribute removal can never undo or prevent the verifier.  Keycloak re-hashes a password whose
 * hash does not meet the realm's policy (an imported or legacy hash) in an after-completion job
 * enlisted by the password step, and the verifier is bound to the stored hash; enlisted after
 * that job, the sync sees the password as it will stay, so a re-hash on login never leaves the
 * verifier stale.</p>
 */
public class IrcCredentialSyncAuthenticator implements Authenticator {

    private static final Logger LOG = Logger.getLogger(IrcCredentialSyncAuthenticator.class);

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        try {
            String password = context.getHttpRequest().getDecodedFormParameters()
                    .getFirst(CredentialRepresentation.PASSWORD);
            if (user != null && password != null && !password.isEmpty()) {
                String realmId = context.getRealm().getId();
                String userId = user.getId();
                AfterCommitJob.enlist(context.getSession(), "IRC credential sync (verifier)", userId,
                        s -> storeVerifier(s, realmId, userId, password));
                AfterCommitJob.enlist(context.getSession(), "IRC credential sync (legacy attributes)", userId,
                        s -> LegacyScramAttributes.removeStale(s, realmId, userId, password));
            }
        } catch (RuntimeException e) {
            LOG.warnf("IRC credential sync skipped for user %s: %s",
                    user == null ? null : user.getId(), e.getClass().getName());
        }
        context.success();
    }

    private static void storeVerifier(KeycloakSession session, String realmId, String userId, String password) {
        RealmModel realm = session.realms().getRealm(realmId);
        UserModel user = realm == null ? null : session.users().getUserById(realm, userId);
        if (user == null) {
            return;
        }
        IrcScramCredentialProvider scram = new IrcScramCredentialProvider(session);
        if (needsNewVerifier(scram.current(user), password)) {
            scram.store(realm, user, ScramVerifier.deriveRandom(password));
        }
    }

    /**
     * A new verifier is needed when the user has no current one, or when the current one is not
     * a verifier of {@code password} (recomputed with its own salt and iterations).  The second
     * case repairs an LDAP-linked user, who has no local password for the fingerprint to follow.
     */
    static boolean needsNewVerifier(Optional<ScramVerifier> current, String password) {
        return current
                .map(v -> !MessageDigest.isEqual(v.storedKey(),
                        ScramVerifier.derive(password, v.salt(), v.iterations()).storedKey()))
                .orElse(true);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.success();   // never challenges, so never called back with a form
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;   // nothing for the user to set up; a missing verifier is what this step makes
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
