package sh.vork.relay;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import sh.vork.relay.lib.model.RelayEntry;
import sh.vork.relay.lib.model.RelaySubmission;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Fast integration tests that verify relay API semantics without a browser.
 * These run on every build (no {@code @Tag("e2e")}).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RelayApiIntegrationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate rest;

    @Test
    void contextLoads() {
        // Verifies the Spring application context starts without errors.
    }

    @Test
    void healthEndpointIsReachable() {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> resp = rest.getForEntity("/actuator/health", Map.class);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void uploadAndFetchOnce() {
        String sessionId = UUID.randomUUID().toString();
        RelayEntry entry = new RelayEntry("encCipher==", "nonce==", "tag==", null);

        // Upload
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> upload = rest.postForEntity(
                "/api/v1/relay/" + sessionId, entry, Map.class);
        assertThat(upload.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        // First fetch — succeeds and removes entry
        ResponseEntity<RelayEntry> first = rest.getForEntity(
                "/api/v1/relay/" + sessionId, RelayEntry.class);
        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(first.getBody()).isNotNull();
        assertThat(first.getBody().encryptedSchema()).isEqualTo("encCipher==");

        // Second fetch — entry was deleted; 404
        ResponseEntity<RelayEntry> second = rest.getForEntity(
                "/api/v1/relay/" + sessionId, RelayEntry.class);
        assertThat(second.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void duplicateUploadReturns409() {
        String sessionId = UUID.randomUUID().toString();
        RelayEntry entry = new RelayEntry("c==", "n==", "t==", null);

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> first  = rest.postForEntity("/api/v1/relay/" + sessionId, entry, Map.class);
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> second = rest.postForEntity("/api/v1/relay/" + sessionId, entry, Map.class);

        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(second.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void uploadWithCustomTimeoutIsStoredAndFetchable() {
        String sessionId = UUID.randomUUID().toString();
        RelayEntry entry = new RelayEntry("enc==", "iv==", "tag==", 60); // 60-minute TTL

        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> upload = rest.postForEntity(
                "/api/v1/relay/" + sessionId, entry, Map.class);
        assertThat(upload.getStatusCode()).isEqualTo(HttpStatus.CREATED);

        // Entry must be present immediately after upload
        ResponseEntity<RelayEntry> fetch = rest.getForEntity(
                "/api/v1/relay/" + sessionId, RelayEntry.class);
        assertThat(fetch.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(fetch.getBody()).isNotNull();
        assertThat(fetch.getBody().encryptedSchema()).isEqualTo("enc==");
    }

    @Test
    void submitAndPollSubmission() {
        String sessionId   = UUID.randomUUID().toString();
        RelaySubmission sub = new RelaySubmission("respCipher==", "iv==", "tag==");

        // Browser submits the encrypted response
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> submitResp = rest.postForEntity(
                "/api/v1/relay/" + sessionId + "/submit", sub, Map.class);
        assertThat(submitResp.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);

        // Offline container polls (response is already available — no blocking needed)
        ResponseEntity<RelaySubmission> poll = rest.getForEntity(
                "/api/v1/relay/" + sessionId + "/response?timeoutMs=5000",
                RelaySubmission.class);
        assertThat(poll.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(poll.getBody()).isNotNull();
        assertThat(poll.getBody().encryptedResponse()).isEqualTo("respCipher==");
    }

    @Test
    void invalidSessionIdReturnsBadRequest() {
        @SuppressWarnings("rawtypes")
        ResponseEntity<Map> resp = rest.getForEntity(
                "/api/v1/relay/not-a-uuid", Map.class);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void longPollTimeoutReturns204WhenNoSubmission() {
        String sessionId = UUID.randomUUID().toString();
        ResponseEntity<Void> resp = rest.getForEntity(
                "/api/v1/relay/" + sessionId + "/response?timeoutMs=300",
                Void.class);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    }

    @Test
    void authPageRendersForValidSessionId() {
        String sessionId = UUID.randomUUID().toString();
        ResponseEntity<String> resp = rest.getForEntity(
                "/auth/" + sessionId, String.class);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(resp.getBody()).contains("relay-app");
        assertThat(resp.getBody()).contains(sessionId);
        assertThat(resp.getBody()).contains("relay-auth.js");
    }
}
