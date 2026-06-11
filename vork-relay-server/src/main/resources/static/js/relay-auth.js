/**
 * relay-auth.js — Vork Relay client-side decryption engine.
 *
 * Zero-knowledge design:
 *   - The AES-256-GCM key is read ONLY from the URL hash fragment.
 *   - The hash fragment is never transmitted in HTTP requests (browser spec).
 *   - The server is blind: it stores only ciphertext and cannot read the form.
 *   - The user's input is encrypted client-side before any network call.
 *
 * Dependencies: none — vanilla JS using the Web Crypto API (SubtleCrypto).
 */
'use strict';

// ── Bootstrap ─────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    const app = document.getElementById('relay-app');
    const sessionId = app ? app.dataset.sessionId : null;
    if (!sessionId) {
        showError('Relay application container not found. Page may be malformed.');
        return;
    }
    main(sessionId).catch(err => {
        appendLogSync('✗', 'Uncaught error: ' + err.message, 'error');
        showError('An unexpected error occurred: ' + err.message);
    });
});

// ── Globals ───────────────────────────────────────────────────────────────────

/** Non-extractable CryptoKey held only in memory; never in DOM or localStorage. */
let globalCryptoKey = null;

// ── Base64URL helpers ─────────────────────────────────────────────────────────

function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return Uint8Array.from(atob(str), ch => ch.charCodeAt(0));
}

function base64UrlEncode(bytes) {
    let binary = '';
    bytes.forEach(b => { binary += String.fromCharCode(b); });
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ── Web Crypto: AES-256-GCM ───────────────────────────────────────────────────

/**
 * Import raw key bytes as a non-extractable AES-256-GCM CryptoKey.
 *
 * non-extractable = the key cannot be read back from the CryptoKey object,
 * reducing exposure if JS memory is inspected.
 */
async function importAesKey(keyBytes) {
    return crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-GCM', length: 256 },
        false,          // non-extractable
        ['encrypt', 'decrypt']
    );
}

/**
 * Decrypt an AES-256-GCM payload.
 *
 * Web Crypto expects a single buffer: ciphertext ‖ authTag.
 * The relay API splits them for auditability; we recombine here.
 *
 * @param {CryptoKey} cryptoKey
 * @param {string}    nonceB64          base64url-encoded 12-byte IV
 * @param {string}    ciphertextB64     base64url-encoded ciphertext
 * @param {string}    authTagB64        base64url-encoded 16-byte GCM tag
 * @returns {Promise<string>}           decoded plaintext
 */
async function decryptPayload(cryptoKey, nonceB64, ciphertextB64, authTagB64) {
    const nonce      = base64UrlDecode(nonceB64);
    const ciphertext = base64UrlDecode(ciphertextB64);
    const authTag    = base64UrlDecode(authTagB64);

    // SubtleCrypto.decrypt requires: ciphertext ‖ authTag as one buffer
    const combined = new Uint8Array(ciphertext.length + authTag.length);
    combined.set(ciphertext, 0);
    combined.set(authTag, ciphertext.length);

    const plaintextBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce, tagLength: 128 },
        cryptoKey,
        combined
    );
    return new TextDecoder().decode(plaintextBuffer);
}

/**
 * Encrypt the user's response payload client-side before transmission.
 *
 * A fresh 12-byte IV is generated for every response; reusing IVs under
 * GCM is catastrophic, so we never reuse the decryption nonce.
 *
 * @param {CryptoKey} cryptoKey
 * @param {string}    plaintext
 * @returns {Promise<{encryptedResponse: string, nonce: string, authTag: string}>}
 */
async function encryptResponse(cryptoKey, plaintext) {
    const iv      = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plaintext);

    const ciphertextWithTag = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        cryptoKey,
        encoded
    );

    const buf        = new Uint8Array(ciphertextWithTag);
    const ciphertext = buf.slice(0, buf.length - 16);
    const authTag    = buf.slice(buf.length - 16);

    return {
        encryptedResponse: base64UrlEncode(ciphertext),
        nonce:             base64UrlEncode(iv),
        authTag:           base64UrlEncode(authTag)
    };
}

// ── Showboat: progressive crypto log panel ────────────────────────────────────

let logSeq = 0;

function escapeHtml(str) {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(String(str)));
    return div.innerHTML;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function appendLogSync(icon, message, cssClass) {
    const body = document.getElementById('log-body');
    if (!body) return;
    const entry = document.createElement('div');
    entry.id        = 'log-' + (++logSeq);
    entry.className = 'log-entry' + (cssClass ? ' ' + cssClass : '');
    entry.innerHTML = `<span class="log-icon" aria-hidden="true">${escapeHtml(icon)}</span>`
                    + `<span class="log-msg">${escapeHtml(message)}</span>`;
    body.appendChild(entry);
    body.scrollTop = body.scrollHeight;
    // Trigger CSS entrance animation on next frame
    requestAnimationFrame(() => entry.classList.add('visible'));
}

async function logStep(icon, message, cssClass, delayMs = 80) {
    await sleep(delayMs);
    appendLogSync(icon, message, cssClass || '');
}

// ── Form rendering ────────────────────────────────────────────────────────────

/**
 * Dynamically build the authorization form from the decrypted schema.
 *
 * Schema shape:
 * {
 *   title:       string,
 *   description: string,
 *   fields: [{ name, type, label, placeholder, required, options? }],
 *   actions: [{ name, label, variant }]
 * }
 */
function renderForm(schema) {
    document.getElementById('form-title').textContent =
        schema.title || 'Authorization Required';
    document.getElementById('form-description').textContent =
        schema.description || '';

    const fieldsDiv = document.getElementById('form-fields');
    (schema.fields || []).forEach(field => {
        const group = document.createElement('div');
        group.className = 'field-group';

        const label = document.createElement('label');
        label.htmlFor     = 'field-' + field.name;
        label.textContent = field.label || field.name;
        group.appendChild(label);

        let input;
        if (field.type === 'select' && Array.isArray(field.options)) {
            input = document.createElement('select');
            field.options.forEach(opt => {
                const option       = document.createElement('option');
                option.value       = typeof opt === 'object' ? opt.value : opt;
                option.textContent = typeof opt === 'object' ? opt.label : opt;
                input.appendChild(option);
            });
        } else {
            input             = document.createElement('input');
            input.type        = field.type || 'text';
            input.placeholder = field.placeholder || '';
            if (field.required) input.required = true;
        }
        input.id        = 'field-' + field.name;
        input.name      = field.name;
        input.className = 'relay-input';
        group.appendChild(input);
        fieldsDiv.appendChild(group);
    });

    const actionsDiv = document.getElementById('form-actions');
    const actions    = schema.actions && schema.actions.length
        ? schema.actions
        : [{ name: 'APPROVE', label: 'Approve', variant: 'primary' }];

    actions.forEach(action => {
        const btn         = document.createElement('button');
        btn.type          = 'button';
        btn.className     = 'relay-btn relay-btn-' + (action.variant || 'secondary');
        btn.dataset.action = action.name;
        btn.textContent   = action.label || action.name;
        btn.addEventListener('click', () => handleSubmit(action.name));
        actionsDiv.appendChild(btn);
    });

    document.getElementById('form-container').classList.remove('vork-hidden');
}

// ── Form submission ───────────────────────────────────────────────────────────

async function handleSubmit(action) {
    // Disable all action buttons to prevent double-submit
    document.querySelectorAll('#form-actions .relay-btn').forEach(b => {
        b.disabled = true;
    });

    // Collect field values
    const fields = {};
    document.querySelectorAll('#form-fields [name]').forEach(el => {
        fields[el.name] = el.value;
    });

    const sessionId = document.getElementById('relay-app').dataset.sessionId;
    const responsePayload = JSON.stringify({
        action,
        fields,
        timestamp: new Date().toISOString()
    });

    await logStep('🔐', 'Encrypting response payload client-side...', 'pending', 200);

    let encrypted;
    try {
        encrypted = await encryptResponse(globalCryptoKey, responsePayload);
    } catch (err) {
        await logStep('✗', 'Client-side encryption failed: ' + err.message, 'error');
        document.querySelectorAll('#form-actions .relay-btn').forEach(b => {
            b.disabled = false;
        });
        return;
    }

    await logStep('✓', 'Response encrypted. Plaintext will not leave this browser.', 'success', 100);
    await logStep('📤', 'Transmitting ciphertext to relay...', 'pending', 200);

    const resp = await fetch('/api/v1/relay/' + sessionId + '/submit', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(encrypted)
    });

    if (resp.ok) {
        await logStep('✓', 'Ciphertext delivered. Server has no knowledge of your response.', 'success', 100);
        document.getElementById('form-container').classList.add('vork-hidden');
        document.getElementById('success-container').classList.remove('vork-hidden');
    } else {
        await logStep('✗', 'Submission failed: HTTP ' + resp.status, 'error');
        showError('Failed to submit response (HTTP ' + resp.status + '). Please try again.');
        document.querySelectorAll('#form-actions .relay-btn').forEach(b => {
            b.disabled = false;
        });
    }
}

// ── Main orchestration ────────────────────────────────────────────────────────

async function main(sessionId) {

    // ── Step 1: Read key from URL hash ────────────────────────────────────────
    await logStep('🔑', 'Reading decryption key from URL hash fragment...', 'pending', 200);

    const hash = window.location.hash;
    if (!hash.startsWith('#k=') || hash.length < 5) {
        await logStep('✗', 'No key fragment in URL (#k=…). Cannot decrypt.', 'error');
        showError('Missing decryption key. The authorization link may be incomplete or expired.');
        return;
    }

    const rawKey = hash.slice(3);   // everything after '#k='
    await logStep('✓', 'Key fragment located. Key material exists only in this browser — never transmitted.', 'success', 120);

    // ── Step 2: Validate and import key ──────────────────────────────────────
    await logStep('⚙', 'Decoding and importing AES-256 key...', 'pending', 150);

    let keyBytes;
    try {
        keyBytes = base64UrlDecode(rawKey);
    } catch (err) {
        await logStep('✗', 'Key is not valid base64url.', 'error');
        showError('Decryption key is malformed. The link may be incomplete.');
        return;
    }

    if (keyBytes.length !== 32) {
        await logStep('✗', 'Key length invalid: expected 32 bytes, got ' + keyBytes.length + '.', 'error');
        showError('Decryption key has unexpected length (' + keyBytes.length + ' bytes; need 32). Link may be truncated.');
        return;
    }

    try {
        globalCryptoKey = await importAesKey(keyBytes);
    } catch (err) {
        await logStep('✗', 'SubtleCrypto key import failed: ' + err.message, 'error');
        showError('Failed to initialize cryptographic key. Your browser may not support the Web Crypto API.');
        return;
    }

    await logStep('✓', 'AES-256-GCM key imported as non-extractable CryptoKey object.', 'success', 100);

    // ── Step 3: Fetch encrypted payload ──────────────────────────────────────
    await logStep('📡', 'Fetching encrypted payload from relay (session: ' + sessionId.substring(0, 8) + '…)', 'pending', 200);

    let payload;
    try {
        const fetchResp = await fetch('/api/v1/relay/' + sessionId);
        if (!fetchResp.ok) {
            if (fetchResp.status === 404) {
                await logStep('✗', 'Session not found or already consumed. This link is single-use.', 'error');
                showError('Authorization session not found. The link may have already been used, or it expired (TTL: 15 minutes).');
            } else {
                await logStep('✗', 'Relay returned HTTP ' + fetchResp.status + '.', 'error');
                showError('Relay error: HTTP ' + fetchResp.status);
            }
            return;
        }
        payload = await fetchResp.json();
    } catch (err) {
        await logStep('✗', 'Network error fetching payload: ' + err.message, 'error');
        showError('Network error: ' + err.message);
        return;
    }

    await logStep('✓', 'Encrypted payload received. Server delivered ciphertext with no knowledge of contents.', 'success', 120);

    // ── Step 4: Showboat crypto details ──────────────────────────────────────
    const nonceBytes  = base64UrlDecode(payload.nonce);
    const nonceHex    = Array.from(nonceBytes).map(b => b.toString(16).padStart(2, '0')).join('');
    await logStep('🔒', 'AES-256-GCM nonce (IV): 0x' + nonceHex, 'info', 150);
    await logStep('🔒', 'GCM auth tag present — integrity and authenticity will be verified.', 'info', 120);

    // ── Step 5: Decrypt ───────────────────────────────────────────────────────
    await logStep('⚙', 'Verifying GCM authentication tag and executing AES-256-GCM decryption...', 'pending', 350);

    let plaintext;
    try {
        plaintext = await decryptPayload(
            globalCryptoKey,
            payload.nonce,
            payload.encryptedSchema,
            payload.authTag
        );
    } catch (err) {
        await logStep('✗', 'Decryption failed — authentication tag mismatch. Payload may be corrupted or key is wrong.', 'error');
        showError('Decryption failed. The key may not match this session, or the payload was corrupted.');
        return;
    }

    await logStep('✓', 'AES-256-GCM integrity verified. Decryption complete. Server remains blind.', 'success', 150);

    // ── Step 6: Parse schema and render form ──────────────────────────────────
    await logStep('📋', 'Parsing form schema from plaintext...', 'pending', 200);

    let schema;
    try {
        schema = JSON.parse(plaintext);
    } catch (err) {
        await logStep('✗', 'Form schema is not valid JSON: ' + err.message, 'error');
        showError('Decrypted content is not a valid form schema.');
        return;
    }

    const title = schema.title || 'Authorization Required';
    await logStep('✓', 'Schema loaded: "' + title + '". Rendering authorization form.', 'success', 100);
    renderForm(schema);
}

// ── Error display ─────────────────────────────────────────────────────────────

function showError(message) {
    const container = document.getElementById('error-container');
    container.innerHTML =
        '<div class="error-box">'
        + '<span class="error-icon" aria-hidden="true">⚠</span>'
        + '<p>' + escapeHtml(message) + '</p>'
        + '</div>';
    container.classList.remove('vork-hidden');
}
