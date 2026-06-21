# vork-relay

A zero-knowledge encrypted authorization-form relay for [Vork](../vork-server) DevOps tooling.

Vork agents running inside air-gapped or firewalled environments need a way to pause a running automation and ask a human for approval or credentials — without requiring that environment to be reachable from the public internet.  `vork-relay` is the secure middleman that makes this possible.

---

## The Problem

Vork runs long-lived AI-driven automations (SSH connections, terminal commands, code compilation) that occasionally need human authorization.  When Vork is embedded in a cloud VM, a CI runner, or an on-premises host, you face a classic network topology problem:

```
  ┌─────────────────────────┐          ┌──────────────────────────────┐
  │  Vork agent             │          │  Human (phone / browser)     │
  │  (private subnet / VM)  │          │  (arbitrary network)         │
  │                         │          │                              │
  │  needs: "what is the    │   ???    │  has: an answer              │
  │  SSH password for        │◄────────│                              │
  │  server-42?"             │         │                              │
  └─────────────────────────┘          └──────────────────────────────┘
```

The naive solutions all have drawbacks:

| Approach | Problem |
|---|---|
| Expose Vork's web UI on a public port | Firewall hole; TLS cert management; DDoS surface |
| VPN / jump host | Requires infrastructure; blocks mobile use |
| Store credentials in config files | Static secrets; not suitable for ephemeral or per-session auth |
| Webhook back to agent | Requires the agent to be reachable; same firewall problem |

`vork-relay` solves this by inverting the connection direction: **the agent pushes a question outward to a public relay, and the human pulls the form from the relay in their browser**.  The agent only needs outbound HTTPS.

```
  ┌─────────────────────────┐   HTTPS out   ┌─────────────────┐   HTTPS   ┌──────────┐
  │  Vork agent             │──────────────►│  vork-relay     │◄──────────│  Human   │
  │  (no inbound ports)     │               │  (public HTTPS) │           │ browser  │
  └─────────────────────────┘               └─────────────────┘           └──────────┘
```

---

## The Security Challenge

Moving sensitive data (SSH passwords, API tokens, approval decisions) through a public relay creates an obvious problem: **the relay can read everything it stores**.  A compromised or malicious relay becomes a credential-harvesting machine.

The solution is to make the relay **cryptographically blind**.

---

## Zero-Knowledge Architecture

`vork-relay` stores only AES-256-GCM ciphertext.  It has no access to the decryption key and therefore no ability to read the form schema or the user's response, even if an attacker gains full control of the relay server, its database, its memory, or its logs.

### Key Transport: URL Hash Fragment

The AES-256-GCM key is encoded as a base64url string and appended to the authorization URL as a **hash fragment**:

```
https://relay.example.com/auth/550e8400-e29b-41d4-a716-446655440000#k=Zm9vYmFyYmF6...
```

The hash fragment (`#k=…`) has a critical property defined in [RFC 3986 §3.5](https://www.rfc-editor.org/rfc/rfc3986#section-3.5) and enforced by every browser:

> **The fragment identifier component of a URI is not sent to the server in HTTP requests.**

This means:
- The relay server receives only the path (`/auth/550e8400-…`) — no key.
- CDN edge nodes, load balancers, and access logs never see the key.
- TLS termination proxies only see the hostname and path.
- Even a full packet capture of the HTTPS session (after decryption) cannot expose the key.

The key exists in only two places: the Vork agent's RAM (which generated it) and the user's browser memory (which received it via the Telegram/notification link).

### Encryption: AES-256-GCM

Both directions of the relay (form schema → browser, response → agent) are encrypted with [AES-256-GCM](https://csrc.nist.gov/publications/detail/sp/800-38d/final):

| Property | Value |
|---|---|
| Algorithm | AES-GCM |
| Key length | 256 bits (32 bytes) |
| Nonce (IV) | 96 bits (12 bytes), randomly generated per message |
| Authentication tag | 128 bits (16 bytes) |
| Key derivation | None — raw random key from `SecureRandom` / `crypto.getRandomValues` |

GCM mode provides both **confidentiality** (the ciphertext reveals nothing about the plaintext) and **authenticity** (the 128-bit authentication tag cryptographically binds the ciphertext to the key and nonce; any tampering causes decryption to throw before any plaintext is produced).

The relay API separates the ciphertext and authentication tag into distinct JSON fields for explicitness.  The browser's `SubtleCrypto.decrypt()` requires them concatenated (`ciphertext ‖ authTag`), so `relay-auth.js` recombines them locally before the call.

### Client-Side Decryption via Web Crypto API

All cryptographic operations in the browser use the [Web Crypto API](https://www.w3.org/TR/WebCryptoAPI/) (`window.crypto.subtle`), which:

- Runs in the browser's native C++ crypto engine — no JavaScript crypto library (no supply-chain risk from npm).
- Imports the key as a **non-extractable** `CryptoKey` object: the raw key bytes cannot be read back from the object via JavaScript after import.
- Is available in all modern browsers and is required for [Secure Contexts](https://w3c.github.io/webappsec-secure-contexts/) (HTTPS only).

### Fetch-Once Semantics

The form payload is deleted from the relay's memory on the **first successful GET**.  A second request for the same session returns `404`.  This means:

- A passive attacker who intercepts the URL link but arrives after the legitimate user cannot retrieve the ciphertext.
- There is no "standing" copy of the question on the relay that could be re-read later.

### Response Encryption

When the user submits the form, `relay-auth.js` encrypts the response **in the browser before any network call**:

1. Collect field values into a JSON object: `{ action, fields, timestamp }`.
2. Generate a fresh 96-bit random nonce (`crypto.getRandomValues`).
3. `SubtleCrypto.encrypt()` with the same AES-256-GCM key.
4. POST only the ciphertext, nonce, and authentication tag to `/api/v1/relay/{id}/submit`.

The plaintext password (or other sensitive value) **never leaves the browser**.  The relay receives and stores only ciphertext.

---

## Data Flow

```
Vork Agent (offline container)          vork-relay                Browser (user)
─────────────────────────────          ──────────                 ──────────────

1. Generate 256-bit key K
   random_nonce_1 = random 12B
   encSchema = AES-GCM(K, nonce1, formSchemaJson)
   authTag1  = last 16B of GCM output

2. POST /api/v1/relay/{sessionId}
   { encryptedSchema, nonce1, authTag1,      ──────────────────────►  store in RAM
     timeoutMinutes? }                                                  (TTL: per-entry or
                                                                        server default 15 min)

3. Send Telegram message:
   https://relay/auth/{sessionId}#k=BASE64URL(K)

                                                                   4. User taps link
                                                                      browser GETs /auth/{sessionId}
                                                                      [k=... stays in browser only]

                                                       ◄────────  5. GET /api/v1/relay/{sessionId}
                                                                      fetch-once + delete from RAM
   store returns { encryptedSchema, nonce1, authTag1 } ──────────►

                                                                   6. importKey(K) → non-extractable
                                                                      SubtleCrypto.decrypt(
                                                                        {name:'AES-GCM', iv:nonce1},
                                                                        encryptedSchema ‖ authTag1
                                                                      ) → formSchemaJson

                                                                   7. Render form, user fills fields

                                                                   8. nonce2 = crypto.getRandomValues(12B)
                                                                      encResp = AES-GCM(K, nonce2, responseJson)

                                                       ────────►  9. POST /api/v1/relay/{sessionId}/submit
                                                                      { encryptedResponse, nonce2, authTag2 }
                                                                      store in RAM

10. GET /api/v1/relay/{sessionId}/response
    (long-poll, 25s default)  ◄──────────────────────────────────  deliver { encryptedResponse, nonce2, authTag2 }

11. AES-GCM-Decrypt(K, nonce2, encResp ‖ authTag2)
    → responseJson
    → { action: "APPROVE", fields: { password: "..." } }
```

At no point does the relay hold the key `K` or the plaintext of either message.

---

## What the Relay Server Can See

Being explicit about the relay's knowledge is the basis of informed trust:

| Data | Relay sees | Notes |
|---|---|---|
| Session UUID | ✅ Yes | Required for routing — not sensitive |
| AES-256 key | ❌ No | URL hash fragment; not in HTTP request |
| Form schema (field names, labels, tool name) | ❌ No | AES-GCM ciphertext only |
| User's submitted values (passwords, approvals) | ❌ No | AES-GCM ciphertext only |
| Number of active sessions | ✅ Yes | Size of in-memory map |
| Timing of requests | ✅ Yes | Access log timestamps |
| User's IP address | ✅ Yes | Standard HTTP |
| Whether a session was fetched/submitted | ✅ Yes | From map operations |

The relay cannot reconstruct any sensitive content even with full server access, provided the AES-256-GCM implementation is sound (which it is — it uses the JVM's `javax.crypto` and the browser's native `SubtleCrypto`, not a JavaScript userland implementation).

---

## API Reference

All relay endpoints are at `/api/v1/relay/{sessionId}`.  The `sessionId` must be a canonical UUID (validated by regex); path traversal and injection attempts are rejected with `400 Bad Request`.

### `POST /api/v1/relay/{sessionId}` — Upload form (offline container)

Request body:
```json
{
  "encryptedSchema": "<base64url ciphertext>",
  "nonce":           "<base64url 12-byte IV>",
  "authTag":         "<base64url 16-byte GCM tag>",
  "timeoutMinutes":  240
}
```

| Field | Required | Description |
|---|---|---|
| `encryptedSchema` | ✓ | AES-256-GCM ciphertext of the form schema JSON |
| `nonce` | ✓ | 96-bit (12-byte) base64url GCM initialization vector |
| `authTag` | ✓ | 128-bit (16-byte) base64url GCM authentication tag |
| `timeoutMinutes` | | Per-entry TTL in minutes. `null` or absent → server default (`vork.relay.ttl-minutes`, default 15 min). Use a longer value for background jobs where a human may respond hours later (e.g. `240` for a 4-hour window). |

- Returns `201 Created` on success.
- Returns `409 Conflict` if the session ID already exists (prevents overwrite attacks).
- Returns `503` (capacity error) if the store is at `vork.relay.max-entries`.
- If `vork.relay.upload-token` is configured, the `X-Relay-Token` header must match.

### `GET /api/v1/relay/{sessionId}` — Fetch form (browser)

- Returns `200 OK` with the `RelayEntry` JSON body.
- **Atomically deletes the entry on first read** (fetch-once).
- Returns `404 Not Found` if the entry was already consumed or expired.

### `POST /api/v1/relay/{sessionId}/submit` — Submit response (browser)

Request body:
```json
{
  "encryptedResponse": "<base64url ciphertext>",
  "nonce":             "<base64url 12-byte IV>",
  "authTag":           "<base64url 16-byte GCM tag>"
}
```

- Returns `202 Accepted`.
- Completes any waiting long-poll future immediately.

### `GET /api/v1/relay/{sessionId}/response` — Long-poll for response (offline container)

Query parameter: `timeoutMs` (default `25000`, max `60000`).

- Blocks until a submission arrives, then returns `200 OK` with the `RelaySubmission` body.
- Returns `204 No Content` on timeout (caller should retry).

---

## Form Schema

The Vork agent encrypts a JSON schema document.  After decryption the browser renders it dynamically — no server-side HTML templating of sensitive content.

```json
{
  "title":       "SSH Authentication Required",
  "description": "Approve connection to server-42 as user lee",
  "fields": [
    {
      "name":        "password",
      "type":        "password",
      "label":       "SSH Password",
      "placeholder": "Enter password",
      "required":    true
    }
  ],
  "actions": [
    { "name": "APPROVE", "label": "Connect", "variant": "primary"   },
    { "name": "DENY",    "label": "Cancel",  "variant": "secondary" }
  ]
}
```

Supported field types: `text`, `password`, `select` (with `options` array).  
Supported action variants: `primary`, `secondary`, `danger`.

---

## Security Configuration

### HTTP Security Headers

Set by `SecurityConfig` on every response:

| Header | Value |
|---|---|
| `X-Frame-Options` | `DENY` — prevents clickjacking |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self'; …; frame-ancestors 'none'` |

The CSP `script-src 'self'` is possible because `relay-auth.js` is served as a static resource — there are no inline scripts on the page, eliminating XSS injection of crypto-overriding code.

### Upload Token

In production, set `vork.relay.upload-token` to a strong random secret.  Without it, any caller who discovers a valid-format UUID can upload a form (though they still can't read responses without the key).

```properties
# Generate: openssl rand -base64 32
vork.relay.upload-token=Zq3...your-secret-here...
```

The Vork agent includes this in the `X-Relay-Token` header of its upload request.

### Session Isolation

Each session is keyed by a UUID generated by the Vork agent.  There is no cross-session access — fetching `/api/v1/relay/{id-A}` has no effect on session `id-B`.

### No Persistent Storage

All relay data lives exclusively in JVM heap memory (`ConcurrentHashMap`).  There is no database, no disk write, and no persistent log of payload contents.  A server restart wipes all pending sessions.

### TTL Eviction

A `@Scheduled` task runs every 60 seconds and evicts entries older than `vork.relay.ttl-minutes` (default: 15 minutes).  Expired long-poll futures are cancelled rather than silently abandoned.

---

## Actuator Hardening

Spring Actuator is included for liveness probes but locked down:

```properties
management.endpoints.web.exposure.include=health
management.endpoint.health.show-details=never
management.endpoint.heapdump.enabled=false      # heap dump would expose in-RAM ciphertext
management.endpoint.threaddump.enabled=false
management.endpoint.env.enabled=false
management.endpoint.beans.enabled=false
```

`heapdump` is explicitly disabled because a JVM heap dump taken during an active session would contain the ciphertext blobs in memory.  While that doesn't expose the key (which is never in the relay's JVM), it is still an information leak about active session IDs and timing.

---

## Logging Policy

`logback-spring.xml` enforces:

- `RelayApiController` logs at `INFO` only — session IDs are logged, payload field values are never logged.
- `CommonsRequestLoggingFilter` is set to `OFF` — Spring's built-in request body logger is disabled.
- Spring Security logging is at `WARN` — suppresses the verbose debug output that can echo request paths.

No log line in this service should ever contain a ciphertext blob, a base64-encoded key, or any portion of a decrypted payload.

---

## Deployment

### Running Locally

```bash
mvn spring-boot:run
# Listening on http://localhost:8090
```

Local development defaults to HTTP on port `8090` when no certificate directory is present.

### TLS Certificate Modes (Startup Behavior)

At startup, `vork-relay` checks `vork.relay.cert-dir` (default `/etc/vork/relay/certs`) for:

- `cert.pem` (certificate chain)
- `privkey.pem` (private key)

The server mode is selected automatically:

| Mode | Condition | Listener behavior |
|---|---|---|
| Local dev mode | Certificate directory does not exist | HTTP on configured `server.port` (default `8090`) |
| Setup mode | Certificate directory exists, but no usable cert/key | HTTP on `:80`, setup wizard at `/setup` acquires Let's Encrypt cert |
| Secure mode | Valid cert/key found (at least 7 days before expiry) | HTTPS on `:443` + HTTP `:80` for ACME challenge and redirect |

### Certificate Sources Supported

1. **Automatic Let's Encrypt (built in)**
- First boot in setup mode serves a one-time setup flow at `/setup`.
- Relay obtains a certificate via ACME HTTP-01 and restarts into HTTPS mode.
- Renewal is automatic (starts 30 days before expiry).

**Critical requirement for this path:** Let's Encrypt HTTP-01 validation must reach your relay on public inbound **port 80**. This is not optional and not configurable to another external port.

- `relay.example.com:80` must be reachable from the public internet.
- Port remapping to a different external port (for example exposing `8080` or `30080` externally) will fail HTTP-01 validation.
- If you cannot expose public inbound port 80, use the Bring Your Own certificate path.

2. **Bring Your Own certificate (pre-provisioned)**
- Place your existing PEM files in the configured cert directory before startup:
  - `cert.pem` (full chain)
  - `privkey.pem` (matching private key)
- Relay will boot directly into secure mode without running setup.

Current automated ACME integration is Let's Encrypt only. If you use another CA, pre-provision `cert.pem` and `privkey.pem`.

### Why production must use a signed certificate

In production, this should be a publicly trusted, CA-signed certificate:

- Users open relay approval links from chat apps and mobile browsers; untrusted/self-signed certs cause blocking warnings and broken trust UX.
- Relay serves active JavaScript (`relay-auth.js`) that performs browser-side crypto; certificate warnings on this endpoint undermine integrity guarantees for users.
- Setup mode and renewal rely on ACME HTTP-01 reachability on port `80` and secure service on `443`.

Self-signed certs are acceptable only for isolated development/testing.

### Bring Your Own Certificate Example

```bash
mkdir -p /opt/vork-relay/certs
cp /path/to/fullchain.pem /opt/vork-relay/certs/cert.pem
cp /path/to/privkey.pem /opt/vork-relay/certs/privkey.pem
chmod 600 /opt/vork-relay/certs/privkey.pem
chmod 644 /opt/vork-relay/certs/cert.pem
```

### Production Checklist

- [ ] Run behind a TLS-terminating reverse proxy (nginx, Caddy, Cloudflare Tunnel).
- [ ] If using built-in Let's Encrypt automation: public inbound port `80` for your relay hostname is open and routable to this instance.
- [ ] Set `vork.relay.upload-token` to a strong random value.
- [ ] Set `vork.relay.ttl-minutes` appropriate for your workflow (default: 15).
- [ ] Set `vork.relay.max-entries` to cap memory usage (default: 1000).
- [ ] Do **not** enable `management.endpoint.heapdump`.
- [ ] Confirm `server.port` is not directly exposed; only the proxy should be public.
- [ ] Review CSP header if you need to serve from a CDN (currently `'self'` only).

### Docker (Self-Hosting)

Prebuilt image on Docker Hub:

```bash
docker pull justvork/vork-relay:latest

docker run --rm -p 8090:8090 \
  -e VORK_RELAY_UPLOAD_TOKEN="$(openssl rand -base64 32)" \
  -e VORK_RELAY_TTL_MINUTES=15 \
  -e VORK_RELAY_MAX_ENTRIES=1000 \
  justvork/vork-relay:latest
```

Production (automatic Let's Encrypt or pre-provisioned certs):

```bash
docker run -d --name vork-relay \
  -p 80:80 -p 443:443 \
  -v /opt/vork-relay/certs:/etc/vork/relay/certs \
  -e VORK_RELAY_UPLOAD_TOKEN="$(openssl rand -base64 32)" \
  -e VORK_RELAY_TTL_MINUTES=15 \
  -e VORK_RELAY_MAX_ENTRIES=1000 \
  --restart unless-stopped \
  justvork/vork-relay:latest
```

Notes:
- Use an empty mounted cert directory on first boot to enter setup mode (`/setup`) and issue a Let's Encrypt cert.
- Or pre-populate the mounted directory with `cert.pem` + `privkey.pem` to start directly on HTTPS.
- Ensure DNS points your hostname to this host and inbound port `80` is reachable for ACME HTTP-01 validation.
- For Let's Encrypt HTTP-01, the external validation path must be on port `80` exactly. If that is not possible in your environment, pre-provision `cert.pem` and `privkey.pem` instead.

Build locally from this repository:

```bash
docker build -t justvork/vork-relay:local .

docker run --rm -p 8090:8090 \
  -e VORK_RELAY_UPLOAD_TOKEN="your-token" \
  justvork/vork-relay:local
```

The image runs the standalone relay server module (`vork-relay-server`) and listens on port `8090` by default.

If token protection is enabled on the relay, configure Vork server with the same token value via `vork.relay.upload-token` (for example environment variable `VORK_RELAY_UPLOAD_TOKEN`) so upload requests include a matching `X-Relay-Token` header.

---

## Running the Tests

### API Integration Tests (fast, no browser)

```bash
mvn test -Dgroups='!e2e'
```

Covers: context load, health endpoint, upload/fetch-once, duplicate rejection, submit/poll, invalid UUID rejection, long-poll timeout, auth page rendering.

### Full E2E Test (Playwright, ~30 s on first run)

```bash
mvn test
```

Downloads Chromium on first run (~100 MB, cached thereafter).  The E2E test performs the complete zero-knowledge round-trip:

1. Generates a real AES-256-GCM key in Java.
2. Encrypts a form schema and uploads to the relay.
3. Navigates Chromium to the auth URL with the key in the hash.
4. Waits for client-side decryption and form rendering.
5. Fills in a password and clicks Approve.
6. Asserts the network POST body contains `encryptedResponse` and **does not contain the plaintext password**.
7. Polls the relay from Java, decrypts the response, and asserts the submitted password matches.

To exclude E2E from CI fast-feedback builds:

```bash
mvn test -Dgroups='!e2e'
# or in pom.xml:
# <excludedGroups>e2e</excludedGroups>
```

---

## Threat Model Summary

| Threat | Mitigated by |
|---|---|
| Relay server compromise (full memory read) | Key never in relay JVM; ciphertext useless without key |
| TLS interception / MITM | Key in URL fragment — not in TLS-visible HTTP request |
| Replay attack (reuse captured ciphertext) | Fetch-once semantics; entry deleted on first read |
| Brute-force session ID | UUID search space: 2¹²² ≈ 5 × 10³⁶ |
| GCM nonce reuse | Agent uses `SecureRandom`; browser uses `crypto.getRandomValues`; fresh nonce per message |
| Ciphertext tampering | AES-GCM auth tag — any bit flip causes `DOMException` before plaintext |
| XSS injection to override `crypto.subtle` | CSP `script-src 'self'`; no inline scripts; no `eval` |
| Clickjacking | `X-Frame-Options: DENY`; CSP `frame-ancestors 'none'` |
| Memory exhaustion | `vork.relay.max-entries` hard cap; TTL eviction |
| Log exfiltration | Payload values never written to logs |

### Out of Scope

- **Endpoint device compromise**: if the user's browser or the agent's host is compromised, all bets are off — this is true of any end-to-end encrypted system.
- **Denial of service**: no rate limiting beyond the `max-entries` cap.
- **Key confidentiality after session**: the key persists in the Telegram/notification message link until the notification is deleted; manage your notification retention accordingly.
