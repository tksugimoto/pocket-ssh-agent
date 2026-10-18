// Unit tests for the PWA libraries. Run with: node --test web/test/
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { parsePairingLink } from '../lib/pairing.js';
import {
  FormatError, authorizedKey, b64decode, b64encode, concat, fingerprint, keyType, parseSignData, publicKeyBlob, sshString,
} from '../lib/sshwire.js';

const te = new TextEncoder();
const s = (x) => sshString(typeof x === 'string' ? te.encode(x) : x);

async function newKey() {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  return { pair, raw, blob: publicKeyBlob(raw) };
}

function userAuth({ session = te.encode('session'), user = 'git', method = 'publickey', alg = 'ssh-ed25519', key, hostKey }) {
  const parts = [s(session), Uint8Array.of(50), s(user), s('ssh-connection'), s(method), Uint8Array.of(1), s(alg), s(key)];
  if (hostKey) parts.push(s(hostKey));
  return concat(...parts);
}

function sshsig(ns, alg, hash) {
  return concat(te.encode('SSHSIG'), s(ns), s(new Uint8Array()), s(alg), s(hash));
}

const hasSshKeygen = (() => {
  try {
    execFileSync('ssh-keygen', ['-?'], { stdio: 'ignore' });
  } catch (e) {
    return e.status !== undefined && e.code !== 'ENOENT';
  }
  return true;
})();

test('authorized key and fingerprint match ssh-keygen', { skip: !hasSshKeygen && 'ssh-keygen not installed' }, async () => {
  const { raw, blob } = await newKey();
  const line = authorizedKey(raw, 'test');
  assert.match(line, /^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]+=* test$/);
  const dir = mkdtempSync(join(tmpdir(), 'psa-'));
  writeFileSync(join(dir, 'k.pub'), line + '\n');
  const out = execFileSync('ssh-keygen', ['-l', '-f', join(dir, 'k.pub')]).toString();
  assert.equal(out.split(' ')[1], await fingerprint(blob));
  assert.equal(keyType(blob), 'ssh-ed25519');
});

test('base64 round trip', () => {
  const bytes = Uint8Array.from({ length: 256 }, (_, i) => i);
  assert.deepEqual(b64decode(b64encode(bytes)), bytes);
});

test('parseSignData accepts userauth and SSHSIG', async () => {
  const { blob } = await newKey();
  assert.deepEqual(
    parseSignData(userAuth({ key: blob }), blob),
    { kind: 'ssh-userauth', user: 'git', service: 'ssh-connection', method: 'publickey', sessionId: te.encode('session'), hostKey: null },
  );
  const hb = parseSignData(userAuth({ key: blob, method: 'publickey-hostbound-v00@openssh.com', hostKey: te.encode('hk') }), blob);
  assert.deepEqual(hb.hostKey, te.encode('hk'));
  assert.deepEqual(parseSignData(sshsig('git', 'sha512', new Uint8Array(64)), blob), { kind: 'sshsig', namespace: 'git', hashAlg: 'sha512' });
  assert.deepEqual(parseSignData(sshsig('file', 'sha256', new Uint8Array(32)), blob), { kind: 'sshsig', namespace: 'file', hashAlg: 'sha256' });
});

test('parseSignData rejects everything else', async () => {
  const { blob } = await newKey();
  const other = (await newKey()).blob;
  const bad = [
    userAuth({ key: other }),
    userAuth({ key: blob, alg: 'ssh-rsa' }),
    userAuth({ key: blob, method: 'password' }),
    userAuth({ key: blob, session: new Uint8Array() }),
    concat(userAuth({ key: blob }), Uint8Array.of(0)),
    sshsig('git', 'sha512', new Uint8Array(32)),
    sshsig('', 'sha512', new Uint8Array(64)),
    te.encode('please sign this'),
    new Uint8Array(),
    Uint8Array.of(0xff, 0xff, 0xff, 0xff, 1),
  ];
  for (const data of bad) assert.throws(() => parseSignData(data, blob), FormatError);
});

test('parsePairingLink', () => {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const ok = parsePairingLink(`https://x.github.io/app/#pair=${enc({ v: 1, url: 'https://pc.tail1.ts.net:7766', code: 'abc', name: 'pc' })}`);
  assert.deepEqual(ok, { url: 'https://pc.tail1.ts.net:7766', code: 'abc', name: 'pc', isTailnet: true });
  assert.equal(parsePairingLink(`#pair=${enc({ v: 1, url: 'http://127.0.0.1:7766', code: 'c' })}`).url, 'http://127.0.0.1:7766');
  for (const url of ['http://pc.example:7766', 'https://u:p@pc.example', 'https://pc.example/path', 'javascript:alert(1)']) {
    assert.throws(() => parsePairingLink(`#pair=${enc({ v: 1, url, code: 'c' })}`), url);
  }
  assert.throws(() => parsePairingLink('#pair=!!!'));
  assert.throws(() => parsePairingLink(`#pair=${enc({ v: 2, url: 'https://a.ts.net', code: 'c' })}`));
  assert.throws(() => parsePairingLink('https://example.com/'));
});

test('protocol MACs match the Go implementation', async () => {
  const { importMacKey, mac, verifyRequest, verifyPairProof, b64url, LABEL_REQ, LABEL_PAIR } = await import('../lib/protocol.js');
  // Vector computed with httpapi.Mac(key=0x01*32, "pocket-ssh-agent request v1", "a", "b", "", "0", "c").
  const key = await importMacKey(new Uint8Array(32).fill(1));
  const got = b64url(await mac(key, LABEL_REQ, 'a', 'b', '', '0', 'c'));
  assert.equal(got, 'ljXD7DjIya-YjNXhB3G8TzsJMPyEinQ0gncq67WZB4E');
  const r = { id: 'id1', kind: 'sshsig', data: 'AAAA', forwarded: true, expiresAt: '2026-01-01T00:00:00Z' };
  r.mac = b64url(await mac(key, LABEL_REQ, r.id, r.kind, r.data, '', '1', r.expiresAt));
  assert.equal(await verifyRequest(key, r), true);
  assert.equal(await verifyRequest(key, { ...r, forwarded: false }), false);
  assert.equal(await verifyRequest(key, { ...r, data: 'BBBB' }), false);
  assert.equal(await verifyRequest(key, { ...r, mac: undefined }), false);

  const codeKey = await importMacKey(new TextEncoder().encode('code'));
  const proof = b64url(await mac(codeKey, LABEL_PAIR, 'sec', 'ssh-ed25519 AAA', 'pc'));
  assert.equal(await verifyPairProof('code', { secret: 'sec', pcName: 'pc', proof }, 'ssh-ed25519 AAA'), true);
  assert.equal(await verifyPairProof('other', { secret: 'sec', pcName: 'pc', proof }, 'ssh-ed25519 AAA'), false);
  assert.equal(await verifyPairProof('code', { secret: 'sec', pcName: 'evil', proof }, 'ssh-ed25519 AAA'), false);
});

test('visible escapes control and bidi characters', async () => {
  const { visible } = await import('../lib/text.js');
  assert.equal(visible('git'), 'git');
  assert.equal(visible('ユーザー'), 'ユーザー');
  assert.equal(visible('ad\u202Enimg'), 'ad\\u{202E}nimg');
  assert.equal(visible('a\x1b[2Jb\n'), 'a\\u{1B}[2Jb\\u{A}');
  assert.equal(visible('a\u200Bb'), 'a\\u{200B}b');
});
