// Client for the PC agent's HTTP API (see internal/httpapi on the Go side).

import { authHeader } from './protocol.js';

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function call(url, { method = 'GET', macKey, body, signal } = {}) {
  const headers = {};
  const text = body === undefined ? '' : JSON.stringify(body);
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (macKey) {
    const u = new URL(url);
    headers.Authorization = await authHeader(macKey, method, u.pathname + u.search, text);
  }
  const res = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : text,
    signal,
    mode: 'cors',
    credentials: 'omit',
    cache: 'no-store',
    referrerPolicy: 'no-referrer',
  });
  if (res.status === 204) return null;
  let data = null;
  try {
    data = await res.json();
  } catch {
    // ignore
  }
  if (!res.ok) throw new ApiError(res.status, data?.code || '', data?.error || `HTTP ${res.status}`);
  return data;
}

/** Returns {secret, pcName, proof}; the caller must verify the proof. */
export function pair(baseUrl, { code, publicKey, deviceName }) {
  return call(`${baseUrl}/v1/pair`, { method: 'POST', body: { code, publicKey, deviceName } });
}

export class Client {
  constructor(baseUrl, macKey) {
    this.baseUrl = baseUrl;
    this.macKey = macKey;
  }

  /** Long poll; resolves when the pending set differs from `known`. */
  requests({ wait = 25, known = [], signal } = {}) {
    const q = new URLSearchParams({ wait: String(wait) });
    if (known.length) q.set('known', known.join(','));
    return call(`${this.baseUrl}/v1/requests?${q}`, { macKey: this.macKey, signal });
  }

  answer(id, decision, signature) {
    const body = { decision };
    if (signature) body.signature = signature;
    return call(`${this.baseUrl}/v1/requests/${encodeURIComponent(id)}`, { method: 'POST', macKey: this.macKey, body });
  }
}
