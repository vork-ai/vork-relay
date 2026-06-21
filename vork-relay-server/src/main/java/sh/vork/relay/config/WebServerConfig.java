package sh.vork.relay.config;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Tomcat connector configuration for HTTPS mode.
 *
 * <h2>Why a second connector?</h2>
 * Spring Boot's main server port is configured to 443 by
 * {@link CertificateEnvironmentPostProcessor} when a certificate is present.
 * HTTPS on 443 handles the relay traffic.  However, two things still need
 * plain HTTP on port 80:
 *
 * <ol>
 *   <li><b>Let's Encrypt HTTP-01 renewal challenges</b> — Let's Encrypt
 *       contacts {@code http://domain/.well-known/acme-challenge/{token}}
 *       directly on port 80.  Spring Security's {@code requiresInsecure()}
 *       rule for that path ensures these requests are served as-is rather than
 *       being redirected to HTTPS.</li>
 *   <li><b>HTTP → HTTPS redirects</b> — all other traffic arriving on port 80
 *       is redirected to HTTPS via Spring Security's
 *       {@code requiresChannel().requiresSecure()}.  Tomcat's
 *       {@code redirectPort} is set to 443 so the redirect URL is
 *       constructed correctly.</li>
 * </ol>
 *
 * <p>This bean is only created when {@code vork.relay.ssl-enabled=true}.
 * In setup mode the main server already listens on port 80 and no additional
 * connector is needed.
 */
@Configuration
public class WebServerConfig {

    /** Create web server connector configuration. */
    public WebServerConfig() {
    }

    /**
     * Adds an auxiliary plain-HTTP connector on port 80 to the embedded Tomcat
     * instance that is otherwise configured for HTTPS on port 443.
     *
     * @return web server customizer that adds an additional HTTP connector.
     */
    @Bean
    @ConditionalOnProperty(name = "vork.relay.ssl-enabled", havingValue = "true")
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> httpRedirectConnector() {
        return factory -> {
            Connector http = new Connector(Http11NioProtocol.class.getName());
            http.setScheme("http");
            http.setPort(80);
            http.setSecure(false);
            // Used by Spring Security when building the HTTPS redirect URL
            http.setRedirectPort(443);
            factory.addAdditionalTomcatConnectors(http);
        };
    }
}
