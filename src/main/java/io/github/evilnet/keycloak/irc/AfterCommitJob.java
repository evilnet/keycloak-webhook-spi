package io.github.evilnet.keycloak.irc;

import org.jboss.logging.Logger;
import org.keycloak.models.AbstractKeycloakTransaction;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionTask;
import org.keycloak.models.utils.KeycloakModelUtils;

/**
 * Runs a task once the request's transaction has committed, in a transaction of its own (the
 * pattern Keycloak uses for its own password re-hash on login).  A failure rolls back only that
 * task's transaction: it cannot undo the request's work or another job's, and it is logged with
 * the user id and the exception class only (a persistence error's message can quote the values
 * it tried to write).  Jobs run in the order they were enlisted.
 */
public final class AfterCommitJob extends AbstractKeycloakTransaction {

    private static final Logger LOG = Logger.getLogger(AfterCommitJob.class);

    private final KeycloakSession session;
    private final String what;
    private final String userId;
    private final KeycloakSessionTask task;

    private AfterCommitJob(KeycloakSession session, String what, String userId, KeycloakSessionTask task) {
        this.session = session;
        this.what = what;
        this.userId = userId;
        this.task = task;
    }

    public static void enlist(KeycloakSession session, String what, String userId, KeycloakSessionTask task) {
        session.getTransactionManager().enlistAfterCompletion(new AfterCommitJob(session, what, userId, task));
    }

    @Override
    protected void commitImpl() {
        try {
            KeycloakModelUtils.runJobInTransaction(session.getKeycloakSessionFactory(), session.getContext(), task);
        } catch (RuntimeException e) {
            LOG.warnf("%s failed for user %s: %s", what, userId, e.getClass().getName());
        }
    }

    @Override
    protected void rollbackImpl() {
    }
}
