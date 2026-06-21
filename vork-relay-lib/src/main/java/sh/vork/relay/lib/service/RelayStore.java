package sh.vork.relay.lib.service;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import sh.vork.relay.lib.model.RelayEntry;
import sh.vork.relay.lib.model.RelaySubmission;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Ephemeral in-memory relay store.
 *
 * <h2>Zero-knowledge guarantees</h2>
 * <ul>
 *   <li>Ciphertext blobs are stored as opaque byte sequences; the service
 *       never decrypts or inspects field values.
 *   <li>Form entries are deleted immediately after the first successful
 *       browser read (fetch-once semantics).
 *   <li>All entries are evicted after {@code vork.relay.ttl-minutes} regardless
 *       of whether they were read.
 *   <li>Payload values are never written to logs.
 * </ul>
 */
@Service
public class RelayStore {

    private static final Logger log = LoggerFactory.getLogger(RelayStore.class);

    @Value("${vork.relay.ttl-minutes:15}")
    private int ttlMinutes;

    @Value("${vork.relay.max-entries:1000}")
    private int maxEntries;

    @Value("${vork.relay.upload-token:}")
    private String uploadToken;

    // Pending forms waiting to be read by a browser (keyed by sessionId)
    private final ConcurrentHashMap<String, Timestamped<RelayEntry>> forms = new ConcurrentHashMap<>();

    // Submitted responses waiting to be collected by the offline container
    private final ConcurrentHashMap<String, Timestamped<RelaySubmission>> submissions = new ConcurrentHashMap<>();

    // Long-poll futures: offline container blocks here until a submission arrives
    private final ConcurrentHashMap<String, CompletableFuture<RelaySubmission>> responseFutures =
            new ConcurrentHashMap<>();

    @PostConstruct
    void warnIfNoToken() {
        if (uploadToken == null || uploadToken.isBlank()) {
            log.warn("vork.relay.upload-token is not set — form uploads are unauthenticated. " +
                     "Set this property in production.");
        }
    }

    // ── Form storage ──────────────────────────────────────────────────────────

    /**
     * Store an encrypted form entry for the given session.
     *
     * @return {@code true} if stored; {@code false} if the session already
     *         exists or the store is at capacity.
     */
    public boolean putForm(String sessionId, RelayEntry entry) {
        if (forms.size() >= maxEntries) {
            log.warn("Store at capacity [maxEntries={}] — upload rejected [sessionId={}]",
                     maxEntries, sessionId);
            return false;
        }
        int effectiveMinutes = (entry.timeoutMinutes() != null && entry.timeoutMinutes() > 0)
                ? entry.timeoutMinutes() : ttlMinutes;
        Instant expiresAt = Instant.now().plus(effectiveMinutes, ChronoUnit.MINUTES);
        // putIfAbsent is atomic — prevents a second upload overwriting an existing entry
        boolean stored = forms.putIfAbsent(sessionId, new Timestamped<>(entry, expiresAt)) == null;
        if (!stored) {
            log.debug("Duplicate upload attempt rejected [sessionId={}]", sessionId);
        } else {
            log.debug("Form stored [sessionId={}, ttlMinutes={}]", sessionId, effectiveMinutes);
        }
        return stored;
    }

    /**
     * Fetch and atomically remove the form entry.  Returns empty if the entry
     * was already consumed or never uploaded (fetch-once semantics).
     */
    public Optional<RelayEntry> getAndRemoveForm(String sessionId) {
        Timestamped<RelayEntry> entry = forms.remove(sessionId);
        return Optional.ofNullable(entry).map(Timestamped::value);
    }

    // ── Submission storage ────────────────────────────────────────────────────

    /**
     * Store the browser's encrypted response and notify any waiting long-poll.
     */
    public void putSubmission(String sessionId, RelaySubmission submission) {
        Instant expiresAt = Instant.now().plus(ttlMinutes, ChronoUnit.MINUTES);
        submissions.put(sessionId, new Timestamped<>(submission, expiresAt));
        // Complete any blocking long-poll future immediately
        CompletableFuture<RelaySubmission> future = responseFutures.remove(sessionId);
        if (future != null) {
            future.complete(submission);
        }
    }

    /**
     * Returns a future that completes when the browser submits a response.
     *
     * <p>If a response is already available it completes immediately.
     * The offline container uses this for long-poll delivery.
     */
    public CompletableFuture<RelaySubmission> awaitSubmission(String sessionId) {
        // Check for an already-submitted response (handles the race where
        // the browser submits before the container starts polling)
        Timestamped<RelaySubmission> existing = submissions.remove(sessionId);
        if (existing != null) {
            return CompletableFuture.completedFuture(existing.value());
        }
        return responseFutures.computeIfAbsent(sessionId, k -> new CompletableFuture<>());
    }

    // ── TTL eviction ──────────────────────────────────────────────────────────

    /** Runs every 60 seconds; purges entries older than {@code ttl-minutes}. */
    @Scheduled(fixedDelay = 60_000)
    public void evictExpiredEntries() {
        Instant now = Instant.now();

        List<String> expiredForms = forms.entrySet().stream()
                .filter(e -> e.getValue().expiresAt().isBefore(now))
                .map(java.util.Map.Entry::getKey)
                .toList();

        expiredForms.forEach(id -> {
            forms.remove(id);
            // Cancel any pending long-poll waiting for a submission on this session
            CompletableFuture<RelaySubmission> f = responseFutures.remove(id);
            if (f != null) {
                f.cancel(false);
            }
        });

        List<String> expiredSubs = submissions.entrySet().stream()
                .filter(e -> e.getValue().expiresAt().isBefore(now))
                .map(java.util.Map.Entry::getKey)
                .toList();
        expiredSubs.forEach(submissions::remove);

        int total = expiredForms.size() + expiredSubs.size();
        if (total > 0) {
            log.info("TTL eviction complete [ttlMinutes={}, forms={}, submissions={}]",
                     ttlMinutes, expiredForms.size(), expiredSubs.size());
        }
    }

    // ── Internal wrapper ──────────────────────────────────────────────────────

    /** Pairs a value with its per-entry expiry instant for TTL tracking. */
    record Timestamped<T>(T value, Instant expiresAt) {}
}
