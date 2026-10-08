// POST /api/submit
// Runs on Cloudflare's servers. The Supabase service-role key lives only here
// (as a Pages secret) and is never sent to the browser.
import { validateSubmission } from '../_lib/validate.js';

const MAX_BODY_CHARS = 64 * 1024;

function reply(status, code, message) {
  const body = code === 'ok' ? { ok: true } : { ok: false, code, error: message };
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
  });
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function verifyTurnstile(token, secret, ip) {
  if (!token || typeof token !== 'string') return false;
  try {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: new URLSearchParams({ secret, response: token, remoteip: ip }),
    });
    const data = await res.json();
    return data.success === true;
  } catch {
    return false;
  }
}

export async function onRequestPost({ request, env }) {
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) {
    console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY');
    return reply(500, 'server_error', 'The service is not configured. Please contact the Digital Entity.');
  }

  // Same-origin only.
  const origin = request.headers.get('Origin');
  if (!origin || origin !== new URL(request.url).origin) {
    return reply(403, 'forbidden', 'Submission rejected.');
  }
  if (!(request.headers.get('Content-Type') || '').includes('application/json')) {
    return reply(415, 'invalid', 'Submission rejected.');
  }

  const text = await request.text();
  if (text.length > MAX_BODY_CHARS) return reply(413, 'invalid', 'The submission is too large.');
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return reply(400, 'invalid', 'Malformed submission.');
  }

  // Honeypot: real visitors never fill this field.
  if (body && typeof body === 'object' && body.website) {
    return reply(400, 'invalid', 'Submission rejected.');
  }

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

  if (env.TURNSTILE_SECRET_KEY) {
    const ok = await verifyTurnstile(body && body.turnstile_token, env.TURNSTILE_SECRET_KEY, ip);
    if (!ok) {
      return reply(400, 'verification_failed', 'Verification failed. Reload the page and try again.');
    }
  }

  const result = validateSubmission(body);
  if (!result.ok) return reply(422, 'invalid', result.error);

  const clientHash = await sha256Hex(`${env.HASH_SALT || env.SUPABASE_URL}|${ip}`);

  const key = env.SUPABASE_SERVICE_ROLE_KEY;
  const headers = { 'Content-Type': 'application/json', apikey: key };
  if (key.startsWith('eyJ')) headers.Authorization = `Bearer ${key}`; // legacy JWT keys only

  let res;
  try {
    res = await fetch(`${env.SUPABASE_URL.replace(/\/+$/, '')}/rest/v1/rpc/submit_registration`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ payload: result.value, p_client_hash: clientHash }),
    });
  } catch (err) {
    console.error('Supabase unreachable', err);
    return reply(502, 'server_error', 'We could not save your submission. Please try again in a moment.');
  }

  if (res.ok) return reply(200, 'ok');

  let detail = {};
  try {
    detail = await res.json();
  } catch {
    /* ignore */
  }
  const message = String(detail.message || '');
  if (message.startsWith('rate_limited')) {
    return reply(429, 'rate_limited', 'Too many submissions. Please wait an hour and try again.');
  }
  if (detail.code === '23505') {
    return reply(422, 'invalid', 'Two people in this submission look identical (same name or email).');
  }
  if (message.startsWith('invalid:')) {
    return reply(422, 'invalid', message.replace(/^invalid:\s*/, ''));
  }
  console.error('Supabase error', res.status, detail.code, message);
  return reply(502, 'server_error', 'We could not save your submission. Please try again in a moment.');
}
