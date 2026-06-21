package sh.vork.relay.config;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Runs before any {@code @Configuration} class is processed.
 *
 * <p>Inspects {@code ${vork.relay.cert-dir}} for a valid TLS certificate and
 * injects the appropriate Spring Boot SSL bundle properties:
 *
 * <ul>
 *   <li><b>Certificate present and valid</b> → SECURE mode: HTTPS on port 443
 *       with SSL bundle wired for {@code reload-on-update} (hot-reload on
 *       renewal), plus {@code vork.relay.ssl-enabled=true}.
 *   <li><b>Certificate absent or expired</b> → SETUP mode: plain HTTP on
 *       port 80, {@code vork.relay.ssl-enabled=false}.
 * </ul>
 *
 * <p>Registered via
 * {@code META-INF/spring/org.springframework.boot.env.EnvironmentPostProcessor.imports}.
 */
public class CertificateEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {

    private static final Pattern FIRST_CERT = Pattern.compile(
            "-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", Pattern.DOTALL);

    /** Create the certificate-based environment post-processor. */
    public CertificateEnvironmentPostProcessor() {
    }

    /**
     * Run after {@code ConfigDataEnvironmentPostProcessor} (order
     * {@code HIGHEST_PRECEDENCE + 10}) so that {@code vork.relay.cert-dir} has
     * already been resolved from {@code application.properties} before we check
     * for a certificate.
     */
    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE - 5;
    }

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment env, SpringApplication app) {
        String certDirProp = env.getProperty("vork.relay.cert-dir", "/etc/vork/relay/certs");
        Path   certDir     = Paths.get(certDirProp);
        Path   certFile    = certDir.resolve("cert.pem");
        Path   keyFile     = certDir.resolve("privkey.pem");

        System.out.println("[vork-relay] Certificate check — dir: " + certDir.toAbsolutePath()
                + "  cert.pem=" + Files.exists(certFile)
                + "  privkey.pem=" + Files.exists(keyFile));

        Map<String, Object> props = new LinkedHashMap<>();

        if (Files.exists(certFile) && Files.exists(keyFile) && isCertUsable(certFile)) {
            String certAbs = certFile.toAbsolutePath().toString();
            String keyAbs  = keyFile.toAbsolutePath().toString();

            System.out.println("[vork-relay] TLS certificate found at " + certDirProp
                    + " — SECURE mode (HTTPS :443, HTTP redirect :80)");

            // Use System.setProperty so these win over any application.properties value
            // regardless of how Spring Boot re-orders property sources after the
            // EnvironmentPostProcessor phase (attach, convertEnvironment, etc.).
            System.setProperty("server.port",       "443");
            System.setProperty("server.ssl.bundle", "vork-relay");

            props.put("server.port",                                                 "443");
            props.put("spring.ssl.bundle.pem.vork-relay.keystore.certificate",      "file:" + certAbs);
            props.put("spring.ssl.bundle.pem.vork-relay.keystore.private-key",      "file:" + keyAbs);
            props.put("spring.ssl.bundle.pem.vork-relay.reload-on-update",          "true");
            props.put("server.ssl.bundle",                                           "vork-relay");
            props.put("vork.relay.ssl-enabled",                                      "true");
        } else if (certDirExists(certDir)) {
            // Cert dir exists (production layout) but no valid cert yet — SETUP mode on port 80.
            // We only force port 80 when the production cert directory is present, so that
            // local development runs (where /etc/vork/relay/certs does not exist) keep
            // whatever port is configured in application.properties (default 8090).
            System.out.println("[vork-relay] No valid TLS certificate — SETUP mode (HTTP :80)");

            System.setProperty("server.port", "80");

            props.put("server.port",             "80");
            props.put("vork.relay.ssl-enabled",  "false");
        } else {
            // Local development — cert dir absent entirely.
            // Fall through: server.port stays as configured (application.properties / env var).
            System.out.println("[vork-relay] Cert dir not found (" + certDirProp
                    + ") — local dev mode, using configured server.port");

            props.put("vork.relay.ssl-enabled",  "false");
        }

        // addFirst so these values take precedence over application.properties
        env.getPropertySources().addFirst(
                new MapPropertySource("vorkRelayCertAutoConfig", props));
    }

    /** Returns true if the cert directory itself exists (regardless of its contents). */
    private static boolean certDirExists(Path certDir) {
        return Files.isDirectory(certDir);
    }

    /**
     * Returns {@code true} only if the first certificate in the PEM file:
     * <ul>
     *   <li>parses cleanly as an X.509 certificate, and
     *   <li>remains valid for at least 7 more days (prevents starting HTTPS
     *       with a cert that would expire mid-session).
     * </ul>
     * On any failure the server falls back to setup mode rather than crashing.
     */
    private static boolean isCertUsable(Path certFile) {
        try {
            String  pem     = Files.readString(certFile);
            Matcher matcher = FIRST_CERT.matcher(pem);
            if (!matcher.find()) {
                System.err.println("[vork-relay] Certificate check failed: no PEM block found in " + certFile);
                return false;
            }

            // getMimeDecoder is lenient about line endings and whitespace variants
            byte[]          der  = Base64.getMimeDecoder().decode(matcher.group(1));
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));

            // Must still be valid 7 days from now (startup grace window)
            cert.checkValidity(Date.from(Instant.now().plus(7, ChronoUnit.DAYS)));

            System.out.println("[vork-relay] Certificate valid until " + cert.getNotAfter()
                    + " — SECURE mode active");
            return true;
        } catch (Exception e) {
            System.err.println("[vork-relay] Certificate check failed (" + e.getClass().getSimpleName()
                    + ": " + e.getMessage() + ") — falling back to SETUP mode");
            return false;
        }
    }
}
