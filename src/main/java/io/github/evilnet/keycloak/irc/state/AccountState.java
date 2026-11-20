package io.github.evilnet.keycloak.irc.state;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Whether an account may log in to IRC, with the reasons it may not.  {@code state} is
 * {@code ok}, {@code incomplete} (enabled, but something is pending) or {@code disabled}.
 */
public record AccountState(String state, List<String> reasons) {

    public static final String ATTR_REQUIRE_EMAIL = "irc.requireEmail";
    public static final String ATTR_REQUIRE_VERIFIED_EMAIL = "irc.requireVerifiedEmail";

    /** Stored required actions that get a fixed reason code, in the order the codes are reported. */
    private static final List<String> KNOWN_ACTIONS = List.of(
            "VERIFY_EMAIL", "UPDATE_PASSWORD", "CONFIGURE_TOTP",
            "UPDATE_PROFILE", "VERIFY_PROFILE", "TERMS_AND_CONDITIONS");

    public AccountState {
        reasons = List.copyOf(reasons);
    }

    /** The rule, free of Keycloak types. */
    public static AccountState of(boolean enabled, List<String> requiredActions, String email,
                                  boolean emailVerified, boolean requireEmail, boolean requireVerifiedEmail) {
        if (!enabled) {
            return new AccountState("disabled", List.of("disabled"));
        }
        List<String> reasons = new ArrayList<>();
        for (String known : KNOWN_ACTIONS) {
            if (requiredActions.stream().anyMatch(a -> a.equalsIgnoreCase(known))) {
                reasons.add(known.toLowerCase(Locale.ROOT));
            }
        }
        for (String action : requiredActions) {
            if (KNOWN_ACTIONS.stream().noneMatch(action::equalsIgnoreCase)) {
                String reason = "action:" + action.toLowerCase(Locale.ROOT);
                if (!reasons.contains(reason)) {
                    reasons.add(reason);
                }
            }
        }
        boolean hasEmail = email != null && !email.isBlank();
        if ((requireEmail || requireVerifiedEmail) && !hasEmail) {   // a verified email cannot exist without an email
            reasons.add("email_missing");
        } else if (requireVerifiedEmail && !emailVerified) {
            reasons.add("email_unverified");
        }
        return new AccountState(reasons.isEmpty() ? "ok" : "incomplete", reasons);
    }

    /** Gathers the inputs from Keycloak and applies {@link #of}. */
    public static AccountState forUser(RealmModel realm, UserModel user) {
        return forUser(realm, user, List.of());
    }

    /**
     * As {@link #forUser(RealmModel, UserModel)}, counting {@code pendingActions} (required actions
     * a login has added to its authentication session, not stored on the user) as required actions too.
     */
    public static AccountState forUser(RealmModel realm, UserModel user, Collection<String> pendingActions) {
        Set<String> actions = new LinkedHashSet<>(user.getRequiredActionsStream().toList());
        actions.addAll(pendingActions);
        return of(user.isEnabled(),
                List.copyOf(actions),
                user.getEmail(),
                user.isEmailVerified(),
                Boolean.parseBoolean(realm.getAttribute(ATTR_REQUIRE_EMAIL)),
                Boolean.parseBoolean(realm.getAttribute(ATTR_REQUIRE_VERIFIED_EMAIL)));
    }
}
