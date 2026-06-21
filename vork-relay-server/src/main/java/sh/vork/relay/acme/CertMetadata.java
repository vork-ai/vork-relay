package sh.vork.relay.acme;

import java.time.Instant;

/**
 * Persisted alongside the certificate in
 * {@code ${vork.relay.cert-dir}/cert-metadata.json}.
 *
 * <p>Stores the hostname and email used for initial issuance so the scheduled
 * renewal can repeat the request without prompting the user again.
 *
 * @param hostname hostname used for certificate issuance and renewal.
 * @param email ACME account contact email.
 * @param staging whether issuance used Let's Encrypt staging.
 * @param obtainedAt timestamp when this certificate was obtained.
 * @param expiresAt timestamp when this certificate expires.
 */
public record CertMetadata(
        String  hostname,
        String  email,
        boolean staging,
        Instant obtainedAt,
        Instant expiresAt) {
}
