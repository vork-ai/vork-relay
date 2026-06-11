/**
 * setup.js — Vork Relay first-run TLS setup wizard.
 *
 * Handles the two-phase UI:
 *   Phase 1 — form: collect hostname, email, ToS agreement.
 *   Phase 2 — progress: poll /setup/status every 3 s and update the ACME log.
 */
'use strict';

let pollTimer     = null;
let lastMessage   = null;
let logSeq        = 0;

// ── Helpers ───────────────────────────────────────────────────────────────────

function escapeHtml(str) {
    const div = document.createElement('div');
    div.appendChild(document.createTextNode(String(str)));
    return div.innerHTML;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function appendLog(icon, message, cssClass) {
    const body  = document.getElementById('progress-log');
    if (!body) return;
    const entry = document.createElement('div');
    entry.id        = 'log-' + (++logSeq);
    entry.className = 'log-entry' + (cssClass ? ' ' + cssClass : '');
    entry.innerHTML = `<span class="log-icon" aria-hidden="true">${escapeHtml(icon)}</span>`
                    + `<span class="log-msg">${escapeHtml(message)}</span>`;
    body.appendChild(entry);
    body.scrollTop = body.scrollHeight;
    requestAnimationFrame(() => entry.classList.add('visible'));
}

// ── Phase 1: form submission ──────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('setup-form');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        const hostname = document.getElementById('hostname').value.trim().toLowerCase();
        const email    = document.getElementById('email').value.trim().toLowerCase();
        const staging  = document.getElementById('staging').checked;
        const agreeTos = document.getElementById('agree_tos').checked;

        const errorBanner = document.getElementById('form-error');
        errorBanner.classList.add('vork-hidden');

        const submitBtn = document.getElementById('submit-btn');
        submitBtn.disabled = true;
        submitBtn.textContent = "Connecting to Let\u2019s Encrypt\u2026";

        let resp;
        try {
            resp = await fetch('/setup/initiate', {
                method:  'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body:    new URLSearchParams({ hostname, email, staging, agree_tos: agreeTos })
            });
        } catch (err) {
            showFormError('Network error: ' + err.message);
            submitBtn.disabled = false;
            submitBtn.textContent = 'Obtain Certificate';
            return;
        }

        const data = await resp.json();

        if (!resp.ok) {
            showFormError(data.error || 'Server returned ' + resp.status);
            submitBtn.disabled = false;
            submitBtn.textContent = 'Obtain Certificate';
            return;
        }

        // Transition to progress phase
        showProgressSection(data.hostname || hostname, staging);
    });
    const retryBtn = document.getElementById('retry-btn');
    if (retryBtn) retryBtn.addEventListener('click', resetToForm);
});

function showFormError(message) {
    const banner = document.getElementById('form-error');
    banner.textContent = message;
    banner.classList.remove('vork-hidden');
}

// ── Phase 2: progress polling ─────────────────────────────────────────────────

function showProgressSection(hostname, staging) {
    document.getElementById('form-section').classList.add('vork-hidden');
    document.getElementById('progress-section').classList.remove('vork-hidden');
    document.getElementById('progress-hostname').textContent  =
            hostname + (staging ? ' (staging)' : '');

    appendLog('\u27F4', "ACME flow initiated \u2014 connecting to Let\u2019s Encrypt\u2026", 'pending');
    startPolling(hostname);
}

function startPolling(hostname) {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = setInterval(() => pollStatus(hostname), 3000);
}

async function pollStatus(hostname) {
    let data;
    try {
        const resp = await fetch('/setup/status');
        if (!resp.ok) return;
        data = await resp.json();
    } catch (err) {
        return;  // transient network error — keep polling
    }

    const { state, message } = data;

    // Only log new messages to avoid duplicates
    if (message && message !== lastMessage) {
        lastMessage = message;
        const cssClass = state === 'DONE'    ? 'success'
                       : state === 'ERROR'   ? 'error'
                       : state === 'RUNNING' ? 'pending'
                       : '';
        const icon     = state === 'DONE'  ? '✓'
                       : state === 'ERROR' ? '✗'
                       : '⚙';
        appendLog(icon, message, cssClass);
    }

    if (state === 'DONE') {
        clearInterval(pollTimer);
        showDone(hostname);
    } else if (state === 'ERROR') {
        clearInterval(pollTimer);
        showError(message);
    }
}

function showDone(hostname) {
    const doneBox   = document.getElementById('done-box');
    const httpsLink = document.getElementById('https-link');
    const url       = 'https://' + hostname + '/';

    httpsLink.href        = url;
    httpsLink.textContent = url;
    doneBox.classList.remove('vork-hidden');

    // Countdown redirect — give the server ~10 s to restart
    let secs = 15;
    const countdown = document.getElementById('countdown');
    const tick = setInterval(() => {
        secs--;
        countdown.textContent = 'Redirecting in ' + secs + ' second' + (secs !== 1 ? 's' : '') + '…';
        if (secs <= 0) {
            clearInterval(tick);
            window.location.href = url;
        }
    }, 1000);
    countdown.textContent = 'Redirecting in ' + secs + ' seconds…';
}

function showError(message) {
    document.getElementById('progress-error-msg').textContent =
            message || 'An unexpected error occurred.';
    document.getElementById('progress-error').classList.remove('vork-hidden');
    if (pollTimer) clearInterval(pollTimer);
}

function resetToForm() {
    // Tell the server to reset state to IDLE so the next submit can proceed.
    // Fire-and-forget: even if this fails the server now allows retry from ERROR.
    fetch('/setup/reset', { method: 'POST' }).catch(() => {});

    lastMessage = null;
    logSeq      = 0;
    document.getElementById('progress-log').innerHTML  = '';
    document.getElementById('progress-error').classList.add('vork-hidden');
    document.getElementById('done-box').classList.add('vork-hidden');
    document.getElementById('progress-section').classList.add('vork-hidden');
    document.getElementById('form-section').classList.remove('vork-hidden');
    const btn = document.getElementById('submit-btn');
    btn.disabled    = false;
    btn.textContent = 'Obtain Certificate';
    document.getElementById('form-error').classList.add('vork-hidden');
}