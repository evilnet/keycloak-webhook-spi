package io.github.evilnet.keycloak.irc.login;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.evilnet.keycloak.irc.state.AccountState;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class IrcAccountStateAuthenticatorTest {

    @Test void bodyIsKeycloaksErrorFirstThenTheIrcStateAndReasonsInOrder() {
        var body = IrcAccountStateAuthenticator.body(
                new AccountState("incomplete", List.of("verify_email", "email_unverified")));
        assertEquals(List.of("error", "error_description", "irc_state", "irc_reasons"), new ArrayList<>(body.keySet()));
        assertEquals("invalid_grant", body.get("error"));
        assertEquals("Account is not fully set up", body.get("error_description"));
        assertEquals("incomplete", body.get("irc_state"));
        assertEquals(List.of("verify_email", "email_unverified"), body.get("irc_reasons"));
    }
}
