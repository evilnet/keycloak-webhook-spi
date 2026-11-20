package io.github.evilnet.keycloak.irc.scram;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.cache.UserCache;

/**
 * The user-attribute form of a SCRAM-SHA-256 verifier that earlier versions wrote (and that IRC
 * servers deployed before the {@code irc-scram-sha256} credential still read).  Three attribute
 * families, each {@code <family>salt}, {@code <family>iterations}, {@code <family>stored_key},
 * {@code <family>server_key}: base64 salt and keys, decimal iterations.
 *
 * <p>The jar never leaves a legacy verifier it knows is for a different password: a password
 * set through Keycloak removes every legacy attribute, and a password login removes each family
 * that is not a verifier of the password just proven (keeping the ones that are, which servers
 * still reading attributes need).  {@code tools/irc_realm_setup.py} carries the same names.</p>
 */
public final class LegacyScramAttributes {

    /** In the order the ircd falls back through them. */
    public static final List<String> FAMILIES = List.of("scram_sha256_", "x3_scram_", "x3_scram_sha256_");

    private static final List<String> FIELDS = List.of("salt", "iterations", "stored_key", "server_key");

    /** More iterations than this is not a verifier the old code wrote, and would stall the login sync. */
    private static final int MAX_ITERATIONS = 65536;

    private LegacyScramAttributes() {
    }

    /** True for an attribute a password set removes: the {@code scram_sha256_} family and every {@code x3_scram_*} key. */
    public static boolean isLegacy(String name) {
        return name.startsWith("x3_scram_") || names("scram_sha256_").contains(name);
    }

    static List<String> names(String family) {
        return FIELDS.stream().map(f -> family + f).toList();
    }

    /**
     * True when the family's attributes are present, parse, and are a verifier of {@code password}
     * (StoredKey and ServerKey recomputed with the attribute salt and iterations, compared in constant time).
     */
    static boolean matches(Map<String, String> attributes, String family, String password) {
        try {
            String salt = attributes.get(family + "salt");
            String iterations = attributes.get(family + "iterations");
            String storedKey = attributes.get(family + "stored_key");
            String serverKey = attributes.get(family + "server_key");
            if (salt == null || iterations == null || storedKey == null || serverKey == null) {
                return false;
            }
            int i = Integer.parseInt(iterations.trim());
            if (i < 1 || i > MAX_ITERATIONS) {
                return false;
            }
            Base64.Decoder b64 = Base64.getDecoder();
            ScramVerifier v = ScramVerifier.derive(password, b64.decode(salt), i);
            return MessageDigest.isEqual(v.storedKey(), b64.decode(storedKey))
                    & MessageDigest.isEqual(v.serverKey(), b64.decode(serverKey));
        } catch (IllegalArgumentException e) {   // bad number or bad base64: cannot be parsed
            return false;
        }
    }

    /** The attributes to remove after a login proved {@code password}: every present one of each family that does not match. */
    static List<String> staleAfterLogin(Map<String, String> attributes, String password) {
        List<String> stale = new ArrayList<>();
        for (String family : FAMILIES) {
            List<String> present = names(family).stream().filter(attributes::containsKey).toList();
            if (!present.isEmpty() && !matches(attributes, family, password)) {
                stale.addAll(present);
            }
        }
        return stale;
    }

    /** After a password login: removes the families that are not a verifier of the password just proven. */
    public static void removeStale(KeycloakSession session, String realmId, String userId, String password) {
        withLocalUser(session, realmId, userId, user -> staleAfterLogin(firstValues(user), password));
    }

    /** After a password set: removes every legacy attribute. */
    public static void removeAll(KeycloakSession session, String realmId, String userId) {
        withLocalUser(session, realmId, userId,
                user -> user.getAttributes().keySet().stream().filter(LegacyScramAttributes::isLegacy).toList());
    }

    /**
     * Removes the named attributes through the user's local (database) model, then evicts the user
     * from the cache.  These attributes live in Keycloak's own database even for an LDAP-linked user,
     * and the federated model of a READ_ONLY provider refuses every attribute write
     * ({@code ReadOnlyException}); the local model does not.  {@code getProvider(UserProvider.class)}
     * is Keycloak's local user storage (what {@code UserStoragePrivateUtil.userLocalStorage} returns),
     * without the federation and cache layers.
     */
    private static void withLocalUser(KeycloakSession session, String realmId, String userId,
                                      Function<UserModel, List<String>> toRemove) {
        RealmModel realm = session.realms().getRealm(realmId);
        UserModel user = realm == null ? null : session.getProvider(UserProvider.class).getUserById(realm, userId);
        if (user == null) {
            return;   // no local record (an LDAP provider without import): nowhere such attributes could be
        }
        List<String> names = toRemove.apply(user);
        if (names.isEmpty()) {
            return;
        }
        names.forEach(user::removeAttribute);
        UserCache cache = session.getProvider(UserCache.class);
        if (cache != null) {
            cache.evict(realm, user);
        }
    }

    private static Map<String, String> firstValues(UserModel user) {
        Map<String, String> values = new HashMap<>();
        for (String family : FAMILIES) {
            for (String name : names(family)) {
                String v = user.getFirstAttribute(name);
                if (v != null) {
                    values.put(name, v);
                }
            }
        }
        return values;
    }
}
