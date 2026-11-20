package io.github.evilnet.keycloak.irc.login;

import io.github.evilnet.keycloak.irc.state.AccountState;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.LinkedHashMap;
import java.util.Map;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * Runs in a direct-grant flow directly after the password step, and refuses an account that is
 * enabled but not fully set up the way Keycloak's password grant would a moment later, with the
 * same {@code error} and {@code error_description}, plus {@code irc_state} and {@code irc_reasons}
 * ({@link AccountState}) so the IRC server can tell the user why.
 *
 * <p>Before applying the rule it evaluates the realm's required-action triggers for the user, as
 * the password grant does after the flow, so an action Keycloak adds at login (for example
 * VERIFY_PROFILE for a profile the realm's user profile finds incomplete) is named too.</p>
 *
 * <p>The refusal is a forced challenge, not a failure: a failure would count against the user in
 * brute-force detection, and neither Keycloak's own refusal of such an account nor its refusal of
 * a disabled one does.  It records the event error Keycloak records ({@code resolve_required_actions}).
 * An {@code ok} account passes.  A disabled one is Keycloak's to refuse: its username step does,
 * before the password is checked, so it never reaches this step, which would let it pass.</p>
 */
public class IrcAccountStateAuthenticator implements Authenticator {

    /** Keycloak's own {@code error_description} for an account with pending required actions. */
    static final String NOT_FULLY_SET_UP = "Account is not fully set up";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        RealmModel realm = context.getRealm();
        AuthenticationManager.evaluateRequiredActionTriggers(context.getSession(), context.getAuthenticationSession(),
                context.getHttpRequest(), context.getEvent(), realm, user);
        AccountState state = AccountState.forUser(realm, user, context.getAuthenticationSession().getRequiredActions());
        if (!"incomplete".equals(state.state())) {
            context.success();
            return;
        }
        context.getEvent().user(user).detail(Details.REASON, NOT_FULLY_SET_UP).error(Errors.RESOLVE_REQUIRED_ACTIONS);
        context.forceChallenge(Response.status(Response.Status.BAD_REQUEST)
                .entity(body(state)).type(MediaType.APPLICATION_JSON_TYPE).build());
    }

    /** The refusal's JSON body: Keycloak's two fields first, then the IRC state and reasons. */
    static Map<String, Object> body(AccountState state) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", OAuthErrorException.INVALID_GRANT);
        body.put("error_description", NOT_FULLY_SET_UP);
        body.put("irc_state", state.state());
        body.put("irc_reasons", state.reasons());
        return body;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.success();   // a direct grant is one request; never called back with a form
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
