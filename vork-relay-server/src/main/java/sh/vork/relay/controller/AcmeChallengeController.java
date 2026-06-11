package sh.vork.relay.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import sh.vork.relay.acme.AcmeChallengeStore;

/**
 * Serves Let's Encrypt HTTP-01 challenge responses.
 *
 * <p>Let's Encrypt contacts {@code http://{domain}/.well-known/acme-challenge/{token}}
 * to verify domain control.  This controller is always registered — it is
 * needed both during initial setup (port 80 only) and during scheduled
 * renewal (served on the auxiliary port-80 connector in HTTPS mode).
 *
 * <p>In HTTPS mode, Spring Security's {@code requiresChannel} is configured
 * to serve these paths over HTTP ({@code requiresInsecure()}) so that Let's
 * Encrypt receives the challenge response without an HTTPS redirect loop.
 *
 * <p>Token format validation follows RFC 8555 §8.3: tokens contain only
 * base64url characters ({@code [A-Za-z0-9_-]}).
 */
@RestController
public class AcmeChallengeController {

    private static final Logger log = LoggerFactory.getLogger(AcmeChallengeController.class);

    private final AcmeChallengeStore challengeStore;

    public AcmeChallengeController(AcmeChallengeStore challengeStore) {
        this.challengeStore = challengeStore;
    }

    @GetMapping(value = "/.well-known/acme-challenge/{token}",
                produces = MediaType.TEXT_PLAIN_VALUE)
    public ResponseEntity<String> challenge(@PathVariable String token) {
        // RFC 8555 §8.3: token is base64url-encoded, characters [A-Za-z0-9_-]
        if (!token.matches("[A-Za-z0-9_-]+")) {
            log.warn("Rejected ACME challenge request with non-base64url token");
            return ResponseEntity.badRequest().build();
        }

        String keyAuth = challengeStore.get(token);
        if (keyAuth == null) {
            log.debug("ACME challenge token not found: {}", token);
            return ResponseEntity.notFound().build();
        }

        log.info("Serving ACME HTTP-01 challenge token: {}", token);
        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_PLAIN)
                .body(keyAuth);
    }
}
