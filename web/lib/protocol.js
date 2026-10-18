// Message authentication shared with the agent (internal/httpapi on the Go
// side). Every MAC is HMAC-SHA256(key, label + "\n" + part1 + "\n" + ...).
//
// After pairing, the shared secret is imported as a non-extractable HMAC
// CryptoKey and the raw bytes are dropped.

import { b64encode, b64urlDecode } from './sshwire.js';

const te = new TextEncoder();

export const LABEL_PAIR = 'pocket-ssh-agent pair v1';
export const LABEL_AUTH = 'pocket-ssh-agent auth v1';
export const LABEL_REQ = 'pocket-ssh-agent request v1';

function message(label, parts) {
  return te.encode([label, ...parts].join('\n'));
}

export function b64url(bytes) {
  return b64encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function importMacKey(raw) {
  return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

export async function mac(key, label, ...parts) {
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, message(label, parts)));
}

export async function verifyMac(key, macB64url, label, ...parts) {
  let sig;
  try {
    sig = b64urlDecode(macB64url);
  } catch {
    return false;
  }
  return crypto.subtle.verify('HMAC', key, sig, message(label, parts));
}

/** Authorization header for a request to the agent. */
export async function authHeader(key, method, uri, body = '') {
  const t = String(Math.floor(Date.now() / 1000));
  const nonce = b64url(crypto.getRandomValues(new Uint8Array(16)));
  const bodyHash = b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(body))));
  const m = b64url(await mac(key, LABEL_AUTH, method, uri, t, nonce, bodyHash));
  return `PSA-HMAC t=${t},n=${nonce},m=${m}`;
}

/** Checks that a sign request really comes from the paired agent. */
export function verifyRequest(key, r) {
  return verifyMac(key, r.mac || '', LABEL_REQ, r.id, r.kind, r.data, r.claimedHostKey || '', r.forwarded ? '1' : '0', r.expiresAt);
}

/** Checks the pairing response proof made with the one-time pairing code. */
export async function verifyPairProof(code, { secret, pcName, proof }, publicKey) {
  const key = await importMacKey(te.encode(code));
  return verifyMac(key, proof || '', LABEL_PAIR, secret, publicKey, pcName);
}
