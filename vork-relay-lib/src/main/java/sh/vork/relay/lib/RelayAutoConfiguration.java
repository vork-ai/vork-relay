package sh.vork.relay.lib;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.scheduling.annotation.EnableScheduling;
import sh.vork.relay.lib.controller.AuthViewController;
import sh.vork.relay.lib.controller.RelayApiController;
import sh.vork.relay.lib.service.RelayStore;

/**
 * Spring Boot auto-configuration for the vork-relay-lib relay server components.
 *
 * <p>Registers the in-memory {@link RelayStore}, the blind REST API
 * ({@link RelayApiController}), and the Thymeleaf auth view
 * ({@link AuthViewController}) into any Spring Boot application that
 * includes {@code vork-relay-lib} on its classpath.
 *
 * <p>Activated automatically via
 * {@code META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports}.
 *
 * <h2>Configuration properties</h2>
 * <ul>
 *   <li>{@code vork.relay.ttl-minutes} (default 15) — entry TTL
 *   <li>{@code vork.relay.max-entries} (default 1000) — store capacity cap
 *   <li>{@code vork.relay.upload-token} (default blank, unauthenticated) — optional bearer token
 * </ul>
 */
@AutoConfiguration
@EnableScheduling
@Import({RelayStore.class, RelayApiController.class, AuthViewController.class})
public class RelayAutoConfiguration {
}
