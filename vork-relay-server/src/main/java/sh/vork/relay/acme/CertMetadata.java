package sh.vork.relay.acme;

import java.time.Instant;

/**
 * Persisted alongside the certificate in
 * {@code ${vork.relay.cert-dir}/cert-metadata.json}.
 *
 * <p>Stores the hostname and email used for initial issuance so the scheduled
 * renewal can repeat the request without prompting the user again.
 */
public record CertMetadata(
        String  hostname,
        String  email,
        boolean staging,
        Instant obtainedAt,
        Instant expiresAt) {
}
