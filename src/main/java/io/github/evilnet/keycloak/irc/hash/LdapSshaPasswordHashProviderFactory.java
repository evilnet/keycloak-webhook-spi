package io.github.evilnet.keycloak.irc.hash;

import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/** Verify-only provider for the `ldap-ssha` legacy password algorithm. */
public class LdapSshaPasswordHashProviderFactory implements PasswordHashProviderFactory {

    public static final String PROVIDER_ID = "ldap-ssha";

    @Override
    public PasswordHashProvider create(KeycloakSession session) {
        return new LegacyPasswordHashProvider(PROVIDER_ID, (raw, digest, salt) -> LegacyHashes.verifySsha(raw, digest, salt));
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

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
