// SSH wire-format helpers and the parser for data the phone is asked to sign.
//
// The phone never trusts the PC's description of a request: it parses the
// raw bytes itself and refuses anything that is not an SSH user
// authentication request for our key or an SSHSIG blob. This keeps the key
// from being used as a generic signing oracle.

const te = new TextEncoder();
const td = new TextDecoder();

const MSG_USERAUTH_REQUEST = 50;
const METHOD_PUBLICKEY = 'publickey';
const METHOD_HOSTBOUND = 'publickey-hostbound-v00@openssh.com';
const SSHSIG_MAGIC = te.encode('SSHSIG');

export const KEY_TYPE = 'ssh-ed25519';

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export function sshString(bytes) {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
}

export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function b64encode(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function b64decode(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function b64urlDecode(str) {
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return b64decode(s);
}

/** Wire-format public key blob for a raw 32-byte Ed25519 public key. */
export function publicKeyBlob(raw) {
  if (raw.length !== 32) throw new Error('Ed25519 public key must be 32 bytes');
  return concat(sshString(te.encode(KEY_TYPE)), sshString(raw));
}

/** authorized_keys line for a raw Ed25519 public key. */
export function authorizedKey(raw, comment = '') {
  const line = `${KEY_TYPE} ${b64encode(publicKeyBlob(raw))}`;
  return comment ? `${line} ${comment}` : line;
}

/** OpenSSH-style SHA256 fingerprint of a key blob. */
export async function fingerprint(blob) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', blob));
  return 'SHA256:' + b64encode(digest).replace(/=+$/, '');
}

/** Key type ("ssh-ed25519", ...) of a key blob, or "" if malformed. */
export function keyType(blob) {
  try {
    const r = new Reader(blob);
    return td.decode(r.str());
  } catch {
    return '';
  }
}

export class FormatError extends Error {}

class Reader {
  constructor(bytes) {
    this.b = bytes;
    this.off = 0;
  }
  byte() {
    if (this.off + 1 > this.b.length) throw new FormatError('truncated');
    return this.b[this.off++];
  }
  str() {
    if (this.off + 4 > this.b.length) throw new FormatError('truncated');
    const n = new DataView(this.b.buffer, this.b.byteOffset + this.off, 4).getUint32(0);
    this.off += 4;
    if (n > this.b.length - this.off) throw new FormatError('truncated');
    const v = this.b.subarray(this.off, this.off + n);
    this.off += n;
    return v;
  }
  done() {
    return this.off === this.b.length;
  }
}

/**
 * Parse the data an SSH client wants signed.
 *
 * Returns one of
 *   {kind: 'ssh-userauth', user, service, method, sessionId, hostKey}
 *   {kind: 'sshsig', namespace, hashAlg}
 * and throws FormatError for anything else, including authentication
 * requests for a key other than keyBlob.
 */
export function parseSignData(data, keyBlob) {
  if (data.length >= SSHSIG_MAGIC.length && equalBytes(data.subarray(0, SSHSIG_MAGIC.length), SSHSIG_MAGIC)) {
    return parseSSHSig(data.subarray(SSHSIG_MAGIC.length));
  }
  return parseUserAuth(data, keyBlob);
}

function parseUserAuth(data, keyBlob) {
  const r = new Reader(data);
  const sessionId = r.str();
  if (r.byte() !== MSG_USERAUTH_REQUEST) throw new FormatError('not a userauth request');
  const user = td.decode(r.str());
  const service = td.decode(r.str());
  const method = td.decode(r.str());
  if (method !== METHOD_PUBLICKEY && method !== METHOD_HOSTBOUND) {
    throw new FormatError(`unexpected method ${method}`);
  }
  if (r.byte() !== 1) throw new FormatError('not a signature request');
  const alg = td.decode(r.str());
  const blob = r.str();
  const hostKey = method === METHOD_HOSTBOUND ? r.str() : null;
  if (!r.done() || sessionId.length === 0) throw new FormatError('malformed userauth request');
  if (alg !== KEY_TYPE) throw new FormatError(`unexpected algorithm ${alg}`);
  if (!equalBytes(blob, keyBlob)) throw new FormatError('request is for a different key');
  return { kind: 'ssh-userauth', user, service, method, sessionId, hostKey };
}

function parseSSHSig(data) {
  const r = new Reader(data);
  const namespace = td.decode(r.str());
  r.str(); // reserved
  const hashAlg = td.decode(r.str());
  const hash = r.str();
  if (!r.done() || namespace === '') throw new FormatError('malformed SSHSIG blob');
  const ok = (hashAlg === 'sha256' && hash.length === 32) || (hashAlg === 'sha512' && hash.length === 64);
  if (!ok) throw new FormatError('unexpected SSHSIG hash');
  return { kind: 'sshsig', namespace, hashAlg };
}
