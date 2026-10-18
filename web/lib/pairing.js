// Pairing links look like
//   https://<pwa>/#pair=<base64url(JSON {v:1, url, code, name})>
// The secret lives in the fragment, which browsers never send to the server
// hosting the PWA.

import { b64urlDecode } from './sshwire.js';

export function hasPairingFragment(text) {
  return /[#&]pair=/.test(text);
}

/** Parse a pairing link (or just its fragment). Throws on invalid input. */
export function parsePairingLink(text) {
  const m = String(text).trim().match(/[#&]pair=([A-Za-z0-9_-]+)/);
  if (!m) throw new Error('ペアリング用のリンクではありません');
  let info;
  try {
    info = JSON.parse(new TextDecoder().decode(b64urlDecode(m[1])));
  } catch {
    throw new Error('ペアリング情報を読み取れません');
  }
  if (info?.v !== 1 || typeof info.url !== 'string' || typeof info.code !== 'string') {
    throw new Error('対応していないペアリング情報です');
  }
  let u;
  try {
    u = new URL(info.url);
  } catch {
    throw new Error('接続先URLが不正です');
  }
  const local = u.hostname === 'localhost' || u.hostname === '127.0.0.1';
  if (u.protocol !== 'https:' && !(local && u.protocol === 'http:')) {
    throw new Error('接続先はhttpsである必要があります');
  }
  if (u.username || u.password || (u.pathname !== '/' && u.pathname !== '') || u.search || u.hash) {
    throw new Error('接続先URLが不正です');
  }
  return {
    url: u.origin,
    code: info.code,
    name: typeof info.name === 'string' ? info.name.slice(0, 64) : '',
    isTailnet: u.hostname.endsWith('.ts.net'),
  };
}
