package sh.vork.relay;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Vork Relay — zero-knowledge encrypted authorization form relay.
 *
 * <p>This service is deliberately blind: it stores only AES-256-GCM ciphertext
 * and has no knowledge of the decryption key, which is delivered out-of-band
 * via the URL hash fragment (never transmitted to the server).
 */
@SpringBootApplication
@EnableScheduling
public class VorkRelayApplication {

    /** Create relay application bootstrap type. */
    public VorkRelayApplication() {
    }

    /**
     * Start the Vork Relay Spring Boot application.
     *
     * @param args standard Spring Boot command-line arguments.
     */
    public static void main(String[] args) {
        SpringApplication.run(VorkRelayApplication.class, args);
    }
}
