package sh.vork.relay.acme;

import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory store for active HTTP-01 ACME challenge tokens.
 *
 * <p>Before triggering a challenge the ACME service writes the token →
 * key-authorization mapping here.  The {@code AcmeChallengeController} serves
 * it at {@code /.well-known/acme-challenge/{token}} (plain HTTP, port 80).
 * The mapping is removed once the challenge is resolved (pass or fail).
 *
 * <p>This store is intentionally simple: it holds at most one or two tokens
 * at a time (one per domain per order), so no eviction policy is needed.
 */
@Component
public class AcmeChallengeStore {

    private final ConcurrentHashMap<String, String> challenges = new ConcurrentHashMap<>();

    /** Create an empty in-memory challenge store. */
    public AcmeChallengeStore() {
    }

    /**
     * Register the key-authorization response for a given ACME challenge token.
     *
     * @param token ACME challenge token.
     * @param keyAuthorization key-authorization payload for the token.
     */
    public void put(String token, String keyAuthorization) {
        challenges.put(token, keyAuthorization);
    }

    /**
     * Look up the key-authorization for a token.
     *
     * @param token ACME challenge token.
     * @return the key-authorization string, or {@code null} if not present.
     */
    public String get(String token) {
        return challenges.get(token);
    }

    /**
     * Remove a token after its challenge is complete.
     *
     * @param token ACME challenge token to remove.
     */
    public void remove(String token) {
        challenges.remove(token);
    }
}
