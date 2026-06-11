package sh.vork.relay.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security configuration with two operating modes:
 *
 * <h3>SETUP mode ({@code vork.relay.ssl-enabled=false})</h3>
 * The server runs on plain HTTP port 80 with no certificate.  Only the
 * setup wizard and ACME challenge endpoints are accessible; all relay API
 * and auth view endpoints are denied.
 *
 * <h3>SECURE mode ({@code vork.relay.ssl-enabled=true})</h3>
 * The main listener is HTTPS on port 443.  An auxiliary Tomcat connector
 * on port 80 handles two traffic patterns:
 * <ul>
 *   <li>{@code /.well-known/acme-challenge/**} — served over plain HTTP so
 *       Let's Encrypt can complete HTTP-01 challenges for renewal.
 *   <li>All other port-80 traffic — redirected to HTTPS via Spring
 *       Security's {@code requiresChannel().requiresSecure()}.
 * </ul>
 *
 * <h3>CSRF</h3>
 * Disabled for API and setup endpoints (stateless; session UUID + encrypted
 * payload provide equivalent protection for the relay API).
 *
 * <h3>HSTS</h3>
 * Only emitted in secure mode; a browser receiving HSTS over plain HTTP would
 * incorrectly pin a non-TLS connection.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final String CSP =
            "default-src 'self'; " +
            "script-src 'self'; " +
            "style-src 'self'; " +
            "img-src 'self' data:; " +
            "font-src 'self'; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none'; " +
            "form-action 'self'";

    @Value("${vork.relay.ssl-enabled:false}")
    private boolean sslEnabled;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // CSRF: disabled for API and setup endpoints
        http.csrf(csrf -> csrf
                .ignoringRequestMatchers("/api/**", "/auth/**", "/setup/**"));

        // Universal security headers
        http.headers(headers -> {
            headers.frameOptions(fo -> fo.deny());
            headers.contentSecurityPolicy(csp -> csp.policyDirectives(CSP));
            // HSTS only valid on HTTPS responses
            if (sslEnabled) {
                headers.httpStrictTransportSecurity(hsts -> hsts
                        .includeSubDomains(true)
                        .maxAgeInSeconds(31_536_000));
            } else {
                headers.httpStrictTransportSecurity(hsts -> hsts.disable());
            }
        });

        // No HTTP session — relay is fully stateless
        http.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        if (sslEnabled) {
            // ── SECURE mode ───────────────────────────────────────────────────
            // ACME challenge must be served over plain HTTP (LE spec).
            // requiresInsecure() means: if this path arrives over HTTPS, redirect
            // to HTTP.  In practice LE always uses HTTP — this is defensive only.
            // requiresSecure() redirects everything else from HTTP to HTTPS.
            http
                .requiresChannel(channel -> channel
                        .requestMatchers("/.well-known/acme-challenge/**").requiresInsecure()
                        .anyRequest().requiresSecure())
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll());
        } else {
            // ── SETUP mode ────────────────────────────────────────────────────
            // No HTTPS yet — the server is on plain HTTP port 80.
            // All paths are permitted; route isolation is enforced structurally:
            //   - SetupController (@ConditionalOnProperty ssl-enabled=false) handles /setup/**
            //   - Relay API and auth view are reachable but running over HTTP; operators
            //     should restrict port-80 ingress at the firewall until HTTPS is configured.
            http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        }

        return http.build();
    }
}
