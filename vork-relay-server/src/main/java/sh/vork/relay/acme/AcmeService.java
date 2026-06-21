package sh.vork.relay.acme;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ACME (Let's Encrypt) certificate lifecycle manager.
 *
 * <h2>Initial acquisition</h2>
 * Called from {@link sh.vork.relay.controller.SetupController} after the user
 * submits the setup form.  Runs in a virtual thread so the HTTP response can
 * return immediately.  On success, writes {@code cert.pem} and
 * {@code privkey.pem} to the cert directory and calls {@code System.exit(0)}
 * — the process manager (systemd / Docker {@code restart: always}) restarts
 * with {@link sh.vork.relay.config.CertificateEnvironmentPostProcessor} picking up the new files
 * and enabling HTTPS mode.
 *
 * <h2>Renewal</h2>
 * Runs daily at 03:00.  If fewer than {@value #RENEW_DAYS} days remain, the
 * ACME flow is re-executed and the PEM files are overwritten atomically.
 * Spring Boot's {@code spring.ssl.bundle.pem.vork-relay.reload-on-update=true}
 * detects the file change and reloads the SSL context without restarting.
 *
 * <h2>HTTP-01 challenge</h2>
 * Tokens are stored in {@link AcmeChallengeStore} and served by
 * {@link sh.vork.relay.controller.AcmeChallengeController} at
 * {@code /.well-known/acme-challenge/{token}}.  The HTTP connector on port 80
 * is always active in secure mode (see {@link sh.vork.relay.config.WebServerConfig}).
 */
@Service
public class AcmeService {

    private static final Logger log = LoggerFactory.getLogger(AcmeService.class);

    private static final String LE_PRODUCTION = "acme://letsencrypt.org";
    private static final String LE_STAGING    = "acme://letsencrypt.org/staging";

    /** Renew when fewer than this many days remain on the certificate. */
    private static final int  RENEW_DAYS    = 30;
    /** Maximum poll attempts while waiting for Let's Encrypt to validate. */
    private static final int  POLL_ATTEMPTS = 20;
    /** Milliseconds between status polls. */
    private static final long POLL_DELAY_MS = 5_000L;

    private static final Pattern FIRST_CERT_PATTERN = Pattern.compile(
            "-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", Pattern.DOTALL);

    @Value("${vork.relay.cert-dir:/etc/vork/relay/certs}")
    private String certDirPath;

    @Value("${vork.relay.ssl-enabled:false}")
    private boolean sslEnabled;

    private final AcmeChallengeStore            challengeStore;
    private final ObjectMapper                  objectMapper;
    private final AtomicReference<SetupStatus>  setupStatus = new AtomicReference<>(SetupStatus.idle());

    /**
     * Create the ACME certificate service.
     *
     * @param challengeStore in-memory HTTP-01 challenge token store.
     * @param objectMapper mapper used for reading/writing metadata JSON.
     */
    @Autowired
    public AcmeService(AcmeChallengeStore challengeStore, ObjectMapper objectMapper) {
        this.challengeStore = challengeStore;
        this.objectMapper   = objectMapper;
    }

    // ── Setup status (polled by the browser's progress page) ─────────────────

    /**
     * Get current setup/acquisition status for polling clients.
     *
     * @return current setup status snapshot.
     */
    public SetupStatus getSetupStatus() {
        return setupStatus.get();
    }

    // ── Initial certificate acquisition ──────────────────────────────────────

    /**
     * Reset the setup status back to IDLE so the user can retry after an error.
     * No-op if acquisition is currently running.
     */
    public void resetStatus() {
        SetupStatus current = setupStatus.get();
        if (current.state() == SetupState.RUNNING) {
            log.warn("resetStatus called while acquisition is RUNNING — ignoring");
            return;
        }
        setupStatus.compareAndSet(current, SetupStatus.idle());
        log.info("Setup status reset to IDLE (was {})", current.state());
    }

    /**
     * Launch the ACME acquisition flow in a background virtual thread.
     *
     * @param hostname DNS hostname to request a certificate for.
     * @param email ACME account contact email.
     * @param staging whether to use the Let's Encrypt staging endpoint.
     * @throws IllegalStateException if acquisition is already running or done.
     */
    public void startAcquisitionAsync(String hostname, String email, boolean staging) {
        SetupStatus current = setupStatus.get();
        log.debug("startAcquisitionAsync: current state={}", current.state());
        if (current.state() == SetupState.RUNNING) {
            log.warn("startAcquisitionAsync rejected: already running");
            throw new IllegalStateException("Certificate acquisition is already in progress");
        }
        if (current.state() == SetupState.DONE) {
            log.warn("startAcquisitionAsync rejected: already completed");
            throw new IllegalStateException("Certificate has already been issued; the server is restarting");
        }
        // IDLE or ERROR — allow (re)start via CAS so concurrent duplicate clicks don't race
        if (!setupStatus.compareAndSet(current, SetupStatus.running("Initialising\u2026"))) {
            log.warn("startAcquisitionAsync CAS failed (concurrent duplicate request)");
            throw new IllegalStateException("Certificate acquisition is already in progress");
        }
        log.info("Starting ACME certificate acquisition for {} (email: {}, staging: {})",
                 hostname, email, staging);

        Thread.ofVirtual().name("acme-acquisition").start(() -> {
            try {
                obtainCertificate(hostname, email, staging);
                setupStatus.set(SetupStatus.done(
                        "Certificate obtained for " + hostname + ". The server is restarting…"));
                log.info("Certificate acquisition complete — restarting JVM in 3 s");
                Thread.sleep(3_000);
                System.exit(0);  // Restart triggers HTTPS mode via EnvironmentPostProcessor
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                log.error("Certificate acquisition failed: {}", e.getMessage(), e);
                setupStatus.set(SetupStatus.error(e.getMessage()));
            }
        });
    }

    // ── Core ACME flow ────────────────────────────────────────────────────────

    /**
     * Execute a complete ACME HTTP-01 certificate issuance.
     * Writes {@code cert.pem}, {@code privkey.pem}, and {@code cert-metadata.json}
     * to {@code certDirPath} on success.
        *
        * @param hostname DNS hostname to include in the issued certificate.
        * @param email ACME account contact email.
        * @param staging whether to use the Let's Encrypt staging endpoint.
        * @throws Exception on ACME, filesystem, or validation failures.
     */
    public void obtainCertificate(String hostname, String email, boolean staging) throws Exception {
        Path certDir = Paths.get(certDirPath);
        Files.createDirectories(certDir);

        // ── 1. Account key ────────────────────────────────────────────────────
        progress("Loading ACME account key…");
        KeyPair accountKey = loadOrCreateAccountKey(certDir);

        // ── 2. ACME session ───────────────────────────────────────────────────
        String serverUrl = staging ? LE_STAGING : LE_PRODUCTION;
        progress("Connecting to Let's Encrypt " + (staging ? "(staging)" : "(production)") + "…");
        Session session = new Session(serverUrl);

        // ── 3. Register or restore account ───────────────────────────────────
        progress("Authenticating ACME account for " + email + "…");
        Account account = new AccountBuilder()
                .agreeToTermsOfService()
                .addEmail(email)
                .useKeyPair(accountKey)
                .create(session);
        log.info("ACME account location: {}", account.getLocation());

        // ── 4. Order certificate ──────────────────────────────────────────────
        progress("Creating certificate order for " + hostname + "…");
        Order order = account.newOrder().domains(hostname).create();

        // ── 5. Satisfy HTTP-01 challenges ─────────────────────────────────────
        for (Authorization auth : order.getAuthorizations()) {
            if (auth.getStatus() == Status.VALID) {
                log.debug("Authorization already valid for {}", auth.getIdentifier());
                continue;
            }
            satisfyHttpChallenge(hostname, auth);
        }

        // ── 6. Generate domain key pair ───────────────────────────────────────
        progress("Generating RSA-2048 domain key pair…");
        KeyPair domainKey = KeyPairUtils.createKeyPair(2048);

        // ── 7. Build CSR and finalise order ───────────────────────────────────
        progress("Building CSR and finalising certificate order…");
        CSRBuilder csrb = new CSRBuilder();
        csrb.addDomain(hostname);
        csrb.sign(domainKey);
        order.execute(csrb.getEncoded());
        awaitOrder(order);

        // ── 8. Download and persist certificate ───────────────────────────────
        progress("Downloading certificate chain from Let's Encrypt…");
        Certificate certificate = order.getCertificate();

        progress("Writing certificate and private key to " + certDirPath + "…");
        writeCertAndKey(certDir, certificate, domainKey);
        writeCertMetadata(certDir, hostname, email, staging,
                certificate.getCertificate().getNotAfter().toInstant());

        log.info("Certificate issued for {} (expires {})",
                hostname, certificate.getCertificate().getNotAfter());
    }

    // ── Challenge handling ────────────────────────────────────────────────────

    private void satisfyHttpChallenge(String hostname, Authorization auth) throws Exception {
        Http01Challenge challenge = auth.findChallenge(Http01Challenge.class)
                .orElseThrow(() -> new IllegalStateException(
                        "HTTP-01 challenge not available for " + hostname
                        + ". Ensure port 80 is reachable from the internet."));

        String token  = challenge.getToken();
        String keyAuth = challenge.getAuthorization();

        challengeStore.put(token, keyAuth);
        log.info("HTTP-01 challenge active: GET /.well-known/acme-challenge/{}", token);
        progress("Serving HTTP-01 challenge token for " + hostname
                + " — waiting for Let's Encrypt to validate…");

        try {
            challenge.trigger();

            for (int i = 1; i <= POLL_ATTEMPTS; i++) {
                Thread.sleep(POLL_DELAY_MS);
                auth.update();
                Status status = auth.getStatus();
                log.debug("Authorization status [{}]: {}", hostname, status);

                if (status == Status.VALID) {
                    progress("Challenge validated for " + hostname + " ✓");
                    return;
                }
                if (status == Status.INVALID || status == Status.REVOKED
                        || status == Status.EXPIRED) {
                    throw new IllegalStateException(
                            "HTTP-01 challenge failed for " + hostname
                            + " (status=" + status + "). "
                            + "Ensure /.well-known/acme-challenge/ is reachable on port 80.");
                }
                progress("Waiting for validation… attempt " + i + "/" + POLL_ATTEMPTS);
            }
            throw new IllegalStateException(
                    "Timed out waiting for challenge validation for " + hostname);
        } finally {
            challengeStore.remove(token);
        }
    }

    private void awaitOrder(Order order) throws Exception {
        for (int i = 1; i <= POLL_ATTEMPTS; i++) {
            Thread.sleep(POLL_DELAY_MS);
            order.update();
            Status status = order.getStatus();
            log.debug("Order status: {}", status);

            if (status == Status.VALID) return;
            if (status == Status.INVALID) {
                throw new IllegalStateException(
                        "Certificate order rejected by Let's Encrypt (status=INVALID). "
                        + "Check the domain and account configuration.");
            }
            progress("Waiting for certificate issuance… attempt " + i + "/" + POLL_ATTEMPTS);
        }
        throw new IllegalStateException("Timed out waiting for certificate issuance");
    }

    // ── File I/O ──────────────────────────────────────────────────────────────

    private KeyPair loadOrCreateAccountKey(Path certDir) throws Exception {
        Path keyFile = certDir.resolve("account.key");
        if (Files.exists(keyFile)) {
            try (Reader r = Files.newBufferedReader(keyFile)) {
                return KeyPairUtils.readKeyPair(r);
            }
        }
        KeyPair kp = KeyPairUtils.createKeyPair(2048);
        try (Writer w = Files.newBufferedWriter(keyFile)) {
            KeyPairUtils.writeKeyPair(kp, w);
        }
        log.info("New ACME account key generated at {}", keyFile);
        return kp;
    }

    /**
     * Write the full certificate chain and private key as PEM files.
     *
     * <p>Uses a write-to-temp-then-rename strategy so Spring Boot's
     * {@code reload-on-update} watcher never observes a partial file.
     * {@code StandardCopyOption.ATOMIC_MOVE} ensures the rename is atomic
     * on POSIX filesystems.
     */
    private void writeCertAndKey(Path certDir, Certificate certificate, KeyPair domainKey)
            throws Exception {
        // Certificate chain
        Path certTmp  = certDir.resolve("cert.pem.tmp");
        Path certFinal = certDir.resolve("cert.pem");
        try (Writer w = Files.newBufferedWriter(certTmp)) {
            for (X509Certificate c : certificate.getCertificateChain()) {
                w.write("-----BEGIN CERTIFICATE-----\n");
                w.write(Base64.getMimeEncoder(64, new byte[]{'\n'})
                              .encodeToString(c.getEncoded()));
                w.write("\n-----END CERTIFICATE-----\n");
            }
        }
        Files.move(certTmp, certFinal,
                StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);

        // Private key (written via acme4j's KeyPairUtils — handles key type correctly)
        Path keyTmp   = certDir.resolve("privkey.pem.tmp");
        Path keyFinal  = certDir.resolve("privkey.pem");
        try (Writer w = Files.newBufferedWriter(keyTmp)) {
            KeyPairUtils.writeKeyPair(domainKey, w);
        }
        Files.move(keyTmp, keyFinal,
                StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);

        log.debug("PEM files written atomically to {}", certDir);
    }

    private void writeCertMetadata(Path certDir, String hostname, String email,
                                   boolean staging, Instant expiresAt) throws IOException {
        CertMetadata meta = new CertMetadata(hostname, email, staging, Instant.now(), expiresAt);
        objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValue(certDir.resolve("cert-metadata.json").toFile(), meta);
    }

    private Optional<CertMetadata> readCertMetadata() {
        Path metaFile = Paths.get(certDirPath, "cert-metadata.json");
        try {
            return Optional.of(objectMapper.readValue(metaFile.toFile(), CertMetadata.class));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    // ── Scheduled renewal ─────────────────────────────────────────────────────

    /**
     * Runs daily at 03:00 server time.  Renews if fewer than {@value #RENEW_DAYS}
     * days remain on the certificate.
     *
     * <p>After renewal, {@code cert.pem} and {@code privkey.pem} are overwritten
     * atomically.  Spring Boot's {@code reload-on-update=true} detects the file
     * change via a background {@code WatchService} and hot-reloads the SSL
     * context — no restart is required.
     */
    @Scheduled(cron = "0 0 3 * * ?")
    public void renewIfNeeded() {
        if (!sslEnabled) return;

        Path certFile = Paths.get(certDirPath, "cert.pem");
        if (!Files.exists(certFile)) {
            log.warn("Renewal check: cert.pem not found at {}", certDirPath);
            return;
        }
        try {
            long daysLeft = daysUntilExpiry(certFile);
            log.debug("Certificate renewal check: {} day(s) remaining", daysLeft);

            if (daysLeft >= RENEW_DAYS) return;

            log.info("Certificate expires in {} day(s) (threshold {}d) — renewing now",
                     daysLeft, RENEW_DAYS);

            CertMetadata meta = readCertMetadata().orElseThrow(() ->
                    new IllegalStateException(
                            "cert-metadata.json not found in " + certDirPath
                            + " — cannot determine renewal parameters"));

            obtainCertificate(meta.hostname(), meta.email(), meta.staging());
            // Spring Boot's reload-on-update=true handles the TLS context reload
            log.info("Certificate successfully renewed for {}", meta.hostname());

        } catch (Exception e) {
            log.error("Certificate renewal failed: {}", e.getMessage(), e);
        }
    }

    private long daysUntilExpiry(Path certFile) throws Exception {
        String  pem     = Files.readString(certFile);
        Matcher matcher = FIRST_CERT_PATTERN.matcher(pem);
        if (!matcher.find()) throw new IllegalStateException("No certificate found in " + certFile);

        byte[] der = Base64.getDecoder().decode(
                matcher.group(1).replaceAll("\\s+", ""));
        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(der));
        return ChronoUnit.DAYS.between(Instant.now(), cert.getNotAfter().toInstant());
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void progress(String message) {
        log.info("ACME: {}", message);
        SetupStatus current = setupStatus.get();
        if (current.state() == SetupState.RUNNING) {
            setupStatus.compareAndSet(current, SetupStatus.running(message));
        }
    }

    // ── Setup status types ────────────────────────────────────────────────────

    /** Lifecycle states for first-run setup and ACME acquisition. */
    public enum SetupState {
        /** Setup has not started yet. */
        IDLE,
        /** Certificate acquisition is currently running. */
        RUNNING,
        /** Certificate acquisition completed successfully. */
        DONE,
        /** Certificate acquisition failed. */
        ERROR
    }

    /**
     * Public setup status payload returned by the polling endpoint.
     *
     * @param state high-level setup lifecycle state.
     * @param message user-facing progress or error message.
     */
    public record SetupStatus(SetupState state, String message) {
        static SetupStatus idle()              { return new SetupStatus(SetupState.IDLE,    "Not started"); }
        static SetupStatus running(String msg) { return new SetupStatus(SetupState.RUNNING, msg); }
        static SetupStatus done(String msg)    { return new SetupStatus(SetupState.DONE,    msg); }
        static SetupStatus error(String msg)   { return new SetupStatus(SetupState.ERROR,   msg); }
    }
}
