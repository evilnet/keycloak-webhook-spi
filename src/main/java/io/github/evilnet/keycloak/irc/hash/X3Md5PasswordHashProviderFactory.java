package io.github.evilnet.keycloak.irc.hash;

import org.keycloak.Config;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.credential.hash.PasswordHashProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/** Verify-only provider for the `x3-md5` legacy password algorithm. */
public class X3Md5PasswordHashProviderFactory implements PasswordHashProviderFactory {

    public static final String PROVIDER_ID = "x3-md5";

    @Override
    public PasswordHashProvider create(KeycloakSession session) {
        return new LegacyPasswordHashProvider(PROVIDER_ID, (raw, digest, salt) -> LegacyHashes.verifyX3Md5(raw, digest));
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
