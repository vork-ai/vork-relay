package sh.vork.relay.lib.controller;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.server.ResponseStatusException;

import java.util.regex.Pattern;

/**
 * Serves the relay authorization page at {@code GET /auth/{sessionId}}.
 *
 * <p>This controller is intentionally minimal: it validates the session ID
 * format and passes it to the Thymeleaf template.  All cryptographic work
 * happens in the browser — this endpoint has no knowledge of any key.
 */
@Controller
public class AuthViewController {

    private static final Pattern UUID_PATTERN = Pattern.compile(
            "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            Pattern.CASE_INSENSITIVE);

    /**
     * Render the auth page.  The URL hash fragment (containing the AES key)
     * is never transmitted to this endpoint — it remains purely client-side.
     */
    @GetMapping("/auth/{sessionId}")
    public String authPage(@PathVariable String sessionId, Model model) {
        if (sessionId == null || !UUID_PATTERN.matcher(sessionId).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid session ID format");
        }
        model.addAttribute("sessionId", sessionId);
        return "relay/auth";
    }
}
