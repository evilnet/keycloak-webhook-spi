package io.github.evilnet.keycloak.webhook;

import io.github.evilnet.keycloak.irc.scram.IrcScramCredentialProvider;
import io.github.evilnet.keycloak.irc.scram.LegacyScramAttributes;
import io.github.evilnet.keycloak.irc.scram.ScramVerifier;
import org.jboss.logging.Logger;
import org.keycloak.models.AbstractKeycloakTransaction;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PolicyError;

/**
 * Password policy {@code scramSha256}: when a password is set through Keycloak, stores a
 * SCRAM-SHA-256 verifier of it as the user's {@code irc-scram-sha256} credential.  It never
 * rejects a password.
 *
 * <p>The policy runs before Keycloak saves the new password, so the verifier cannot be bound
 * to that password yet.  It is derived here and stored in the transaction's prepare phase,
 * after the new password is saved and before the commit, so the stored verifier is bound to
 * the new password.  The store happens only if the password was saved: for a user with a
 * local password, when the stored password credentials changed since validation; for a user
 * with none (an LDAP-linked user, whose password lives in the directory), when the new
 * password now validates for the user (for LDAP, a bind).  If the change was refused or
 * failed, nothing is stored; if the transaction rolls back, the prepare phase does not run.
 * With the store, every legacy attribute verifier of the user is removed
 * ({@link LegacyScramAttributes}): it is for the old password.</p>
 *
 * <p>Pre-hashed passwords loaded through the admin API never reach a policy; those users get
 * a verifier at their first password login ({@code irc-credential-sync}).</p>
 */
public class ScramPasswordPolicyProvider implements PasswordPolicyProvider {

    private static final Logger LOG = Logger.getLogger(ScramPasswordPolicyProvider.class);

    private final KeycloakSession session;

    public ScramPasswordPolicyProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
        if (user == null || password == null || password.isEmpty()) {
            return null;
        }
        try {
            session.getTransactionManager().enlistPrepare(new StoreWhenPasswordSaved(
                    realm, user.getId(), IrcScramCredentialProvider.passwordFingerprint(user),
                    password, ScramVerifier.deriveRandom(password)));
        } catch (RuntimeException e) {
            // Never fail the password change over the verifier; log the class name only.
            LOG.warnf("SCRAM verifier not derived for user %s: %s", user.getId(), e.getClass().getName());
        }
        return null;
    }

    @Override
    public PolicyError validate(String user, String password) {
        return null;   // no user to store a credential for
    }

    @Override
    public Object parseConfig(String value) {
        return null;
    }

    @Override
    public void close() {
    }

    /** The deferred store: runs in the prepare phase, stores only if the new password was saved. */
    private final class StoreWhenPasswordSaved extends AbstractKeycloakTransaction {

        private final RealmModel realm;
        private final String userId;
        private final String fingerprintBefore;
        private final String password;
        private final ScramVerifier verifier;

        StoreWhenPasswordSaved(RealmModel realm, String userId, String fingerprintBefore, String password,
                               ScramVerifier verifier) {
            this.realm = realm;
            this.userId = userId;
            this.fingerprintBefore = fingerprintBefore;
            this.password = password;
            this.verifier = verifier;
        }

        @Override
        protected void commitImpl() {
            try {
                UserModel user = session.users().getUserById(realm, userId);
                if (user == null || !passwordSaved(user)) {
                    return;
                }
                new IrcScramCredentialProvider(session).store(realm, user, verifier);
                LegacyScramAttributes.removeAll(user);
            } catch (RuntimeException e) {
                // A throw here would fail the commit, and with it the password change.
                LOG.warnf("SCRAM verifier not stored for user %s: %s", userId, e.getClass().getName());
            }
        }

        /** A local password: its credentials changed.  None before or after (LDAP-linked): the new password validates. */
        private boolean passwordSaved(UserModel user) {
            String after = IrcScramCredentialProvider.passwordFingerprint(user);
            if (fingerprintBefore.isEmpty() && after.isEmpty()) {
                return user.credentialManager().isValid(UserCredentialModel.password(password));
            }
            return !after.equals(fingerprintBefore);
        }

        @Override
        protected void rollbackImpl() {
        }
    }
}
