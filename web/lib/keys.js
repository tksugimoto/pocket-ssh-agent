// The phone's SSH key: a non-extractable Ed25519 WebCrypto key kept in
// IndexedDB.

import * as store from './store.js';

const KEY = 'ssh-key';

export async function ed25519Supported() {
  try {
    await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
    return true;
  } catch {
    return false;
  }
}

/** Returns {privateKey, publicRaw, createdAt} or undefined. */
export async function loadKey() {
  return store.get(KEY);
}

export async function loadOrCreateKey() {
  const existing = await loadKey();
  if (existing) return existing;
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const record = { privateKey: pair.privateKey, publicRaw, createdAt: new Date().toISOString() };
  await store.set(KEY, record);
  return record;
}

export async function deleteKey() {
  await store.del(KEY);
}

export async function sign(privateKey, data) {
  return new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, data));
}
