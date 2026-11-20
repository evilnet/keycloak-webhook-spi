package io.github.evilnet.keycloak.irc.state;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;

class AccountStateTest {

    @Test void complete() {
        assertEquals(new AccountState("ok", List.of()), AccountState.of(true, List.of(), "a@b", true, false, false));
    }

    @Test void disabledWins() {
        assertEquals(new AccountState("disabled", List.of("disabled")),
                AccountState.of(false, List.of("VERIFY_EMAIL"), null, false, true, true));
    }

    @Test void storedActionsInOrder() {
        assertEquals(List.of("verify_email", "update_password", "action:webauthn-register"),
                AccountState.of(true, List.of("webauthn-register", "UPDATE_PASSWORD", "VERIFY_EMAIL"), "a@b", true, false, false).reasons());
    }

    @Test void emailRulesAreOffByDefault() {
        assertEquals("ok", AccountState.of(true, List.of(), null, false, false, false).state());
    }

    @Test void emailRules() {
        assertEquals(List.of("email_missing"), AccountState.of(true, List.of(), "", false, true, true).reasons());
        assertEquals(List.of("email_unverified"), AccountState.of(true, List.of(), "a@b", false, false, true).reasons());
    }
}
