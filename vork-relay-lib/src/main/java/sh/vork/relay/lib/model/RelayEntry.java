package sh.vork.relay.lib.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * The encrypted form payload uploaded by the offline container.
 *
 * <p>All three fields are base64url-encoded bytes.  The server stores them
 * verbatim and never attempts to interpret or log their contents.
 *
 * <ul>
 *   <li>{@code encryptedSchema}  – AES-256-GCM ciphertext of the form schema JSON
 *   <li>{@code nonce}            – 96-bit (12-byte) GCM initialization vector
 *   <li>{@code authTag}          – 128-bit (16-byte) GCM authentication tag
 *   <li>{@code timeoutMinutes}   – optional TTL override in minutes; {@code null}
 *                                  means the server's global {@code vork.relay.ttl-minutes}
 *                                  is used (default 15 minutes).
 * </ul>
 *
 * The browser recombines {@code encryptedSchema ‖ authTag} before passing to
 * {@code SubtleCrypto.decrypt()}, which requires the tag appended to the
 * ciphertext as a single buffer.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record RelayEntry(
        String encryptedSchema,
        String nonce,
        String authTag,
        Integer timeoutMinutes
) {}
