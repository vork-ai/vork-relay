package sh.vork.relay.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import sh.vork.relay.acme.AcmeService;
import sh.vork.relay.acme.AcmeService.SetupState;
import sh.vork.relay.acme.AcmeService.SetupStatus;

import java.util.Map;
import java.util.regex.Pattern;

/**
 * First-run setup wizard.  Active only when {@code vork.relay.ssl-enabled=false}
 * (i.e. no TLS certificate has been issued yet).
 *
 * <h2>Flow</h2>
 * <ol>
 *   <li>{@code GET /} or {@code GET /setup} → render the setup form.
 *   <li>{@code POST /setup/initiate} → validate input, start the ACME flow
 *       asynchronously, return JSON {@code {ok:true}}.
 *   <li>{@code GET /setup/status} → return {@link SetupStatus} as JSON (polled
 *       by the browser every 3 seconds).
 *   <li>On {@code DONE}: {@link AcmeService} calls {@code System.exit(0)} so
 *       the process manager restarts the JVM with HTTPS enabled.
 * </ol>
 *
 * <p>All relay API endpoints ({@code /api/v1/**}) and the auth view
 * ({@code /auth/**}) are unreachable in setup mode — Spring Security denies
 * them.  Only {@code /setup/**}, {@code /.well-known/**}, and
 * {@code /actuator/health} are permitted.
 */
@Controller
@ConditionalOnProperty(name = "vork.relay.ssl-enabled", havingValue = "false", matchIfMissing = true)
public class SetupController {

    private static final Logger log = LoggerFactory.getLogger(SetupController.class);

    /**
     * Permissive hostname regex: at least two labels, each containing
     * alphanumerics and hyphens.  Does not enforce TLD exhaustiveness —
     * Let's Encrypt will reject invalid names in any case.
     */
    private static final Pattern HOSTNAME_PATTERN = Pattern.compile(
            "^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$");

    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[^@\\s]+@[^@\\s]+\\.[^@\\s]{2,}$");

    private final AcmeService acmeService;

    /**
     * Create the setup controller.
     *
     * @param acmeService ACME orchestration service for setup and polling status.
     */
    public SetupController(AcmeService acmeService) {
        this.acmeService = acmeService;
    }

    /**
     * Redirect root to setup page in setup mode.
     *
     * @return redirect view name to {@code /setup}.
     */
    @GetMapping("/")
    public String root() {
        return "redirect:/setup";
    }

    /**
     * Render the setup form, or redirect to progress if already running.
     *
     * @return template view name or a redirect view name.
     */
    @GetMapping("/setup")
    public String setupPage() {
        SetupStatus status = acmeService.getSetupStatus();
        if (status.state() == SetupState.RUNNING || status.state() == SetupState.DONE) {
            return "redirect:/setup/progress";
        }
        return "setup";
    }

    /**
     * Render the progress page.
     *
     * @return setup template view name.
     */
    @GetMapping("/setup/progress")
    public String progressPage() {
        return "setup";   // same template handles both views via JS
    }

    /**
     * Start the ACME certificate acquisition asynchronously.
     *
     * <p>Validates hostname and email before delegating.  Returns JSON so the
     * setup form can submit via {@code fetch()} and immediately show progress.
    *
    * @param hostname requested DNS hostname for the certificate.
    * @param email ACME account contact email.
    * @param staging whether to use Let's Encrypt staging endpoint.
    * @param agreeTos whether the user accepted Let's Encrypt terms.
    * @return JSON response indicating success or validation/conflict failure.
     */
    @PostMapping("/setup/initiate")
    @ResponseBody
    public ResponseEntity<?> initiateSetup(
            @RequestParam String hostname,
            @RequestParam String email,
            @RequestParam(defaultValue = "false") boolean staging,
            @RequestParam(value = "agree_tos", defaultValue = "false") boolean agreeTos) {

        hostname = hostname.trim().toLowerCase();
        email    = email.trim().toLowerCase();

        if (!agreeTos) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "You must agree to the Let's Encrypt Terms of Service"));
        }
        if (!HOSTNAME_PATTERN.matcher(hostname).matches()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid hostname: must be a fully qualified domain name"));
        }
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid email address"));
        }

        log.info("Setup initiated: hostname={}, staging={}", hostname, staging);
        try {
            acmeService.startAcquisitionAsync(hostname, email, staging);
        } catch (IllegalStateException e) {
            return ResponseEntity.status(409).body(Map.of("error", e.getMessage()));
        }

        return ResponseEntity.ok(Map.of("ok", true, "hostname", hostname));
    }

    /**
     * JSON polling endpoint for setup progress.
     * The browser calls this every 3 seconds during the ACME flow.
        *
        * @return current setup state and message.
     */
    @GetMapping("/setup/status")
    @ResponseBody
    public SetupStatus setupStatus() {
        return acmeService.getSetupStatus();
    }

    /**
     * Reset the setup state back to IDLE so the user can retry after an error.
     * No-op if acquisition is currently running.
        *
        * @return JSON acknowledgement containing {@code ok=true}.
     */
    @PostMapping("/setup/reset")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> resetSetup() {
        log.info("Setup reset requested");
        acmeService.resetStatus();
        return ResponseEntity.ok(Map.of("ok", true));
    }
}
