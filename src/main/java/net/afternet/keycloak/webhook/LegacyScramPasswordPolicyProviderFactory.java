package net.afternet.keycloak.webhook;

import org.jboss.logging.Logger;
import org.keycloak.Config;

/**
 * Deprecated alias of {@link ScramPasswordPolicyProviderFactory}, registered
 * under the pre-rename provider ID {@code "x3Scram"}.
 *
 * <p><b>This class exists only to survive the live cutover boot.</b> Keycloak
 * validates every existing realm's {@code passwordPolicy} string against the
 * currently-registered password-policy providers at server startup, before
 * the Admin REST API is reachable. Renaming {@link ScramPasswordPolicyProviderFactory}'s
 * provider ID from {@code "x3Scram"} to {@code "scramSha256"} in a single jar
 * (with no alias) causes Keycloak to fail to boot as soon as it's deployed,
 * because any realm still configured with the old {@code "x3Scram"} policy
 * string can no longer resolve a matching provider — and there's no live
 * admin API to fix the realm once the server won't start.</p>
 *
 * <p>Deploy sequence this alias enables: (1) deploy this jar — both
 * {@code "x3Scram"} and {@code "scramSha256"} are registered, so Keycloak
 * boots cleanly against a realm still on the old policy string; (2) flip the
 * live realm's {@code passwordPolicy} to {@code "scramSha256"} via the Admin
 * API now that the new ID is loaded; (3) once no realm references
 * {@code "x3Scram"} any more, delete this class (and its
 * {@code META-INF/services} registration) in a follow-up commit and
 * redeploy.</p>
 */
public class LegacyScramPasswordPolicyProviderFactory extends ScramPasswordPolicyProviderFactory {

    private static final Logger LOG = Logger.getLogger(LegacyScramPasswordPolicyProviderFactory.class);

    public static final String LEGACY_PROVIDER_ID = "x3Scram";
    public static final String LEGACY_DISPLAY_NAME = "X3 SCRAM-SHA-256 (deprecated alias of scramSha256)";

    @Override
    public void init(Config.Scope config) {
        LOG.warn("LegacyScramPasswordPolicyProviderFactory initialized - this is a deprecated " +
            "alias of scramSha256 kept only to let Keycloak boot while any realm still carries " +
            "the old \"x3Scram\" policy string; remove once all realms are flipped to scramSha256");
    }

    @Override
    public String getId() {
        return LEGACY_PROVIDER_ID;
    }

    @Override
    public String getDisplayName() {
        return LEGACY_DISPLAY_NAME;
    }
}
