package sh.vork.relay.lib.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.async.DeferredResult;
import sh.vork.relay.lib.model.RelayEntry;
import sh.vork.relay.lib.model.RelaySubmission;
import sh.vork.relay.lib.service.RelayStore;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Blind relay REST API.
 *
 * <h3>Zero-knowledge contract</h3>
 * <ul>
 *   <li>No endpoint logs payload field values.
 *   <li>The GET fetch-once endpoint atomically deletes the entry on first read.
 *   <li>The server never holds the AES key; the key travels only in the URL
 *       hash fragment, which is not included in HTTP requests.
 * </ul>
 *
 * <h3>Endpoints</h3>
 * <pre>
 *   POST /api/v1/relay/{sessionId}           — upload encrypted form (offline container)
 *   GET  /api/v1/relay/{sessionId}           — fetch + delete form (browser, fetch-once)
 *   POST /api/v1/relay/{sessionId}/submit    — submit encrypted response (browser)
 *   GET  /api/v1/relay/{sessionId}/response  — long-poll for response (offline container)
 * </pre>
 */
@RestController
@RequestMapping("/api/v1/relay")
public class RelayApiController {

    private static final Logger log = LoggerFactory.getLogger(RelayApiController.class);

    /** sessionId must be a canonical UUID — prevents path traversal and injection. */
    private static final Pattern UUID_PATTERN = Pattern.compile(
            "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            Pattern.CASE_INSENSITIVE);

    /** Default long-poll timeout for the /response endpoint (milliseconds). */
    private static final long MAX_POLL_TIMEOUT_MS = 60_000L;

    private final RelayStore store;

    @Value("${vork.relay.upload-token:}")
    private String uploadToken;

    public RelayApiController(RelayStore store) {
        this.store = store;
    }

    // ── Upload (offline container → relay) ────────────────────────────────────

    /**
     * Store an AES-256-GCM encrypted form schema for a session.
     *
     * <p>If {@code vork.relay.upload-token} is set, the caller must supply the
     * matching value in the {@code X-Relay-Token} header.
     *
     * @return 201 Created on success; 409 if the session already exists.
     */
    @PostMapping("/{sessionId}")
    public ResponseEntity<?> upload(
            @PathVariable String sessionId,
            @RequestBody RelayEntry entry,
            @RequestHeader(value = "X-Relay-Token", required = false) String token) {

        if (!isValidSessionId(sessionId)) {
            return badRequest("Invalid session ID — must be a UUID");
        }
        if (!uploadToken.isBlank() && !uploadToken.equals(token)) {
            log.warn("Upload rejected: missing or invalid X-Relay-Token [sessionId={}]", sessionId);
            return ResponseEntity.status(401).body(error("Unauthorized"));
        }
        if (isBlank(entry.encryptedSchema()) || isBlank(entry.nonce()) || isBlank(entry.authTag())) {
            return badRequest("encryptedSchema, nonce, and authTag are all required");
        }

        boolean stored = store.putForm(sessionId, entry);
        if (!stored) {
            return ResponseEntity.status(409).body(error("Session already exists or store is at capacity"));
        }

        // Log the session ID only — never the payload
        log.info("Form uploaded [sessionId={}]", sessionId);
        return ResponseEntity.status(201).body(Map.of("ok", true, "sessionId", sessionId));
    }

    // ── Fetch (browser → relay, fetch-once) ───────────────────────────────────

    /**
     * Return the encrypted form entry and atomically delete it from the store.
     *
     * <p>This is a one-shot operation: a second request for the same session
     * returns 404.  This prevents replay and limits the exposure window.
     */
    @GetMapping("/{sessionId}")
    public ResponseEntity<?> fetch(@PathVariable String sessionId) {
        if (!isValidSessionId(sessionId)) {
            return badRequest("Invalid session ID — must be a UUID");
        }

        Optional<RelayEntry> entry = store.getAndRemoveForm(sessionId);
        if (entry.isEmpty()) {
            log.debug("Fetch miss: session not found or already consumed [sessionId={}]", sessionId);
            return ResponseEntity.notFound().build();
        }

        log.info("Form fetched and removed from store [sessionId={}]", sessionId);
        return ResponseEntity.ok(entry.get());
    }

    // ── Submit (browser → relay) ──────────────────────────────────────────────

    /**
     * Accept the browser's client-side-encrypted response for delivery to the
     * offline container via long-poll.
     */
    @PostMapping("/{sessionId}/submit")
    public ResponseEntity<?> submit(
            @PathVariable String sessionId,
            @RequestBody RelaySubmission submission) {

        if (!isValidSessionId(sessionId)) {
            return badRequest("Invalid session ID — must be a UUID");
        }
        if (isBlank(submission.encryptedResponse()) || isBlank(submission.nonce()) || isBlank(submission.authTag())) {
            return badRequest("encryptedResponse, nonce, and authTag are all required");
        }

        store.putSubmission(sessionId, submission);
        log.info("Response submission received [sessionId={}]", sessionId);
        return ResponseEntity.accepted().body(Map.of("ok", true));
    }

    // ── Poll (offline container ← relay) ──────────────────────────────────────

    /**
     * Long-poll endpoint for the offline container to collect the user's
     * encrypted response.
     *
     * <p>Blocks until either:
     * <ul>
     *   <li>a submission is available → 200 OK with the {@link RelaySubmission}
     *   <li>{@code timeoutMs} elapses → 204 No Content (caller should retry)
     * </ul>
     */
    @GetMapping("/{sessionId}/response")
    public DeferredResult<ResponseEntity<?>> pollResponse(
            @PathVariable String sessionId,
            @RequestParam(defaultValue = "25000") long timeoutMs) {

        long effectiveTimeout = Math.min(Math.max(1_000L, timeoutMs), MAX_POLL_TIMEOUT_MS);
        DeferredResult<ResponseEntity<?>> deferred =
                new DeferredResult<>(effectiveTimeout, ResponseEntity.noContent().build());

        if (!isValidSessionId(sessionId)) {
            deferred.setResult(badRequest("Invalid session ID — must be a UUID"));
            return deferred;
        }

        store.awaitSubmission(sessionId)
             .orTimeout(effectiveTimeout, TimeUnit.MILLISECONDS)
             .whenComplete((submission, ex) -> {
                 if (submission != null) {
                     log.info("Response delivered to poller [sessionId={}]", sessionId);
                     deferred.setResult(ResponseEntity.ok(submission));
                 } else {
                     // Timeout or cancellation — caller retries
                     deferred.setResult(ResponseEntity.noContent().build());
                 }
             });

        return deferred;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private boolean isValidSessionId(String id) {
        return id != null && UUID_PATTERN.matcher(id).matches();
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private static ResponseEntity<?> badRequest(String message) {
        return ResponseEntity.badRequest().body(error(message));
    }

    private static Map<String, String> error(String message) {
        return Map.of("error", message);
    }
}
