package sh.vork.relay;

import com.microsoft.playwright.*;
import com.microsoft.playwright.options.WaitForSelectorState;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import sh.vork.relay.lib.model.RelayEntry;
import sh.vork.relay.lib.model.RelaySubmission;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * End-to-end test verifying the zero-knowledge relay round-trip.
 *
 * <h3>Scenario</h3>
 * <ol>
 *   <li>An AES-256-GCM key is generated in Java (simulates offline container).</li>
 *   <li>A form schema JSON is encrypted with that key.</li>
 *   <li>The ciphertext is uploaded to the relay via the REST API.</li>
 *   <li>Playwright navigates to the auth page with the key in the URL hash.</li>
 *   <li>The browser decrypts the schema client-side, renders the form.</li>
 *   <li>The test fills in a password and clicks Approve.</li>
 *   <li>The browser encrypts the response and POSTs only ciphertext — the
 *       POST body must not contain the plaintext password.</li>
 *   <li>The offline container polls the relay, receives the ciphertext, decrypts
 *       it in Java, and verifies the submitted password value.</li>
 * </ol>
 *
 * <p>Note: Playwright downloads Chromium on first run (~100 MB).  Subsequent
 * runs use the cached browser.  Tag this test as {@code @Tag("e2e")} if you
 * want to exclude it from fast-feedback CI pipelines:
 * {@code mvn test -Dgroups='!e2e'}.
 */
@Tag("e2e")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class RelayE2ETest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    private static Playwright playwright;
    private static Browser browser;

    @BeforeAll
    static void launchBrowser() {
        playwright = Playwright.create();
        browser    = playwright.chromium().launch(
                new BrowserType.LaunchOptions().setHeadless(true));
    }

    @AfterAll
    static void closeBrowser() {
        if (browser   != null) browser.close();
        if (playwright != null) playwright.close();
    }

    // ── Test ──────────────────────────────────────────────────────────────────

    @Test
    @Order(1)
    @DisplayName("Full zero-knowledge round-trip: upload → decrypt in browser → submit → decrypt in Java")
    void fullZeroKnowledgeRoundTrip() throws Exception {

        // ── 1. Generate AES-256-GCM key (offline container side) ─────────────
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, new SecureRandom());
        SecretKey key = kg.generateKey();

        // ── 2. Encrypt form schema ────────────────────────────────────────────
        String schema = """
                {
                  "title": "SSH Authentication Required",
                  "description": "Approve connection to server 10.0.22.22",
                  "fields": [
                    {
                      "name": "password",
                      "type": "password",
                      "label": "SSH Password",
                      "placeholder": "Enter password",
                      "required": true
                    }
                  ],
                  "actions": [
                    { "name": "APPROVE", "label": "Connect",  "variant": "primary"   },
                    { "name": "DENY",    "label": "Cancel",   "variant": "secondary" }
                  ]
                }
                """;

        EncryptionResult enc = encryptAesGcm(key, schema);
        String sessionId = UUID.randomUUID().toString();

        // ── 3. Upload ciphertext to relay ─────────────────────────────────────
        RelayEntry entry     = new RelayEntry(enc.ciphertext(), enc.nonce(), enc.authTag(), null);
        HttpHeaders headers  = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> uploadResp = restTemplate.postForEntity(
                "/api/v1/relay/" + sessionId,
                new HttpEntity<>(entry, headers),
                Map.class);

        assertThat(uploadResp.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        // ── 4. Build the auth URL (key is in the hash — never sent to server) ─
        String keyB64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(key.getEncoded());
        String authUrl   = "http://localhost:" + port + "/auth/" + sessionId + "#k=" + keyB64Url;

        // ── 5. Launch browser and navigate ────────────────────────────────────
        String testPassword = "correct-horse-battery-staple";
        Page page = browser.newPage();
        try {
            // Capture browser console messages for diagnosing JS failures
            page.onConsoleMessage(msg -> System.out.println("[BROWSER " + msg.type().toUpperCase() + "] " + msg.text()));
            page.onRequestFailed(req -> System.out.println("[BROWSER FAIL] " + req.method() + " " + req.url() + " → " + req.failure()));

            page.navigate(authUrl);

            // ── 6. Wait for form to appear (proves browser decryption succeeded) ─
            page.waitForSelector(
                    "input[name='password']",
                    new Page.WaitForSelectorOptions()
                            .setState(WaitForSelectorState.VISIBLE)
                            .setTimeout(20_000));

            // ── 7. Fill in the password ───────────────────────────────────────
            page.fill("input[name='password']", testPassword);

            // ── 8. Click Approve ──────────────────────────────────────────────
            page.click("button[data-action='APPROVE']");

            // ── 9. Wait for success message (proves submit completed) ─────────
            page.waitForSelector(
                    "#success-container",
                    new Page.WaitForSelectorOptions()
                            .setState(WaitForSelectorState.VISIBLE)
                            .setTimeout(10_000));

        } finally {
            page.close();
        }

        // ── 10. Offline container polls relay for the encrypted response ──────
        ResponseEntity<RelaySubmission> pollResp = restTemplate.getForEntity(
                "/api/v1/relay/" + sessionId + "/response?timeoutMs=10000",
                RelaySubmission.class);

        assertThat(pollResp.getStatusCode()).isEqualTo(HttpStatus.OK);
        RelaySubmission submission = pollResp.getBody();
        assertThat(submission).isNotNull();
        assertThat(submission.encryptedResponse()).isNotBlank();
        assertThat(submission.nonce()).isNotBlank();
        assertThat(submission.authTag()).isNotBlank();

        // ── 11. Zero-knowledge: the relay payload must be opaque ciphertext ───
        // The relay stored exactly what the browser sent — verify it contains
        // no plaintext.  Only the holder of the AES key can read the content.
        assertThat(submission.encryptedResponse())
                .as("Encrypted response must not expose the plaintext password")
                .doesNotContain(testPassword);
        assertThat(submission.authTag())
                .as("Auth tag must not expose the plaintext password")
                .doesNotContain(testPassword);

        // ── 12. Decrypt in Java — proves round-trip fidelity ──────────────────
        String responsePlaintext = decryptAesGcm(key,
                submission.nonce(),
                submission.encryptedResponse(),
                submission.authTag());

        // Response JSON: {"action":"APPROVE","fields":{"password":"..."},"timestamp":"..."}
        assertThat(responsePlaintext).contains("\"APPROVE\"");
        assertThat(responsePlaintext).contains("correct-horse-battery-staple");
    }

    @Test
    @Order(2)
    @DisplayName("Fetch-once: second browser request for same session returns 404")
    void fetchOnceSemanticsEnforced() {
        KeyGenerator kg;
        SecretKey key;
        try {
            kg  = KeyGenerator.getInstance("AES");
            kg.init(256, new SecureRandom());
            key = kg.generateKey();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        String schema    = "{\"title\":\"test\",\"fields\":[],\"actions\":[]}";
        EncryptionResult enc;
        try {
            enc = encryptAesGcm(key, schema);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        String sessionId = UUID.randomUUID().toString();
        RelayEntry entry = new RelayEntry(enc.ciphertext(), enc.nonce(), enc.authTag(), null);

        // Upload
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> upload = restTemplate.postForEntity(
                "/api/v1/relay/" + sessionId, entry, Map.class);
        assertThat(upload.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        // First fetch — should succeed
        ResponseEntity<RelayEntry> first = restTemplate.getForEntity(
                "/api/v1/relay/" + sessionId, RelayEntry.class);
        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.OK);

        // Second fetch — entry was deleted; must return 404
        ResponseEntity<RelayEntry> second = restTemplate.getForEntity(
                "/api/v1/relay/" + sessionId, RelayEntry.class);
        assertThat(second.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    @Order(3)
    @DisplayName("Duplicate upload for same session ID is rejected with 409")
    void duplicateUploadRejected() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256, new SecureRandom());
        SecretKey key    = kg.generateKey();
        EncryptionResult enc = encryptAesGcm(key, "{\"title\":\"t\",\"fields\":[],\"actions\":[]}");

        String sessionId = UUID.randomUUID().toString();
        RelayEntry entry = new RelayEntry(enc.ciphertext(), enc.nonce(), enc.authTag(), null);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> first  = restTemplate.postForEntity("/api/v1/relay/" + sessionId, entry, Map.class);
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> second = restTemplate.postForEntity("/api/v1/relay/" + sessionId, entry, Map.class);

        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(second.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    @Order(4)
    @DisplayName("Non-UUID session ID is rejected with 400")
    void invalidSessionIdRejected() {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> resp = restTemplate.getForEntity(
                "/api/v1/relay/../../etc/passwd", Map.class);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    @Order(5)
    @DisplayName("Long-poll returns 204 when no submission arrives within timeout")
    void longPollTimeoutReturns204() {
        String sessionId = UUID.randomUUID().toString();
        ResponseEntity<Void> resp = restTemplate.getForEntity(
                "/api/v1/relay/" + sessionId + "/response?timeoutMs=500",
                Void.class);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }

    // ── Crypto helpers ────────────────────────────────────────────────────────

    record EncryptionResult(String ciphertext, String nonce, String authTag) {}

    /**
     * Encrypt plaintext with AES-256-GCM.
     *
     * <p>Java's {@code Cipher.doFinal()} returns {@code ciphertext ‖ authTag}
     * concatenated.  We split off the last 16 bytes as the auth tag to match
     * the relay API's three-field structure.
     */
    private static EncryptionResult encryptAesGcm(SecretKey key, String plaintext) throws Exception {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));

        byte[] ciphertextWithTag = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        int    cipherLen         = ciphertextWithTag.length - 16;
        byte[] ciphertext        = Arrays.copyOf(ciphertextWithTag, cipherLen);
        byte[] authTag           = Arrays.copyOfRange(ciphertextWithTag, cipherLen, ciphertextWithTag.length);

        Base64.Encoder enc = Base64.getUrlEncoder().withoutPadding();
        return new EncryptionResult(
                enc.encodeToString(ciphertext),
                enc.encodeToString(iv),
                enc.encodeToString(authTag));
    }

    /**
     * Decrypt an AES-256-GCM ciphertext received from the relay.
     *
     * <p>Recombines {@code ciphertext ‖ authTag} before calling
     * {@code Cipher.doFinal()}.
     */
    private static String decryptAesGcm(SecretKey key, String nonceB64,
                                        String ciphertextB64, String authTagB64) throws Exception {
        Base64.Decoder dec = Base64.getUrlDecoder();
        byte[] iv         = dec.decode(nonceB64);
        byte[] ciphertext = dec.decode(ciphertextB64);
        byte[] authTag    = dec.decode(authTagB64);

        // Reassemble ciphertext ‖ authTag
        byte[] combined = new byte[ciphertext.length + authTag.length];
        System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
        System.arraycopy(authTag,    0, combined, ciphertext.length, authTag.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] plaintext = cipher.doFinal(combined);
        return new String(plaintext, StandardCharsets.UTF_8);
    }
}
