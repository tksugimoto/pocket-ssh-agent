// A scripted "phone" for end-to-end tests. It uses the PWA's own libraries
// (web/lib) and WebCrypto, pairs with a running agent, writes the public key
// to a file and then answers sign requests:
//   - SSHSIG requests in namespace "deny-me" are denied,
//   - everything else that parses is approved,
//   - anything that does not parse is denied.
// Each answer is logged as one JSON line on stdout.
//
// Usage: node fake-phone.mjs <pairing link> <pubkey output file>

import { writeFileSync } from 'node:fs';

import { ApiError, Client, pair } from '../../web/lib/api.js';
import { parsePairingLink } from '../../web/lib/pairing.js';
import { importMacKey, verifyPairProof, verifyRequest } from '../../web/lib/protocol.js';
import {
  authorizedKey, b64decode, b64encode, b64urlDecode, fingerprint, parseSignData, publicKeyBlob,
} from '../../web/lib/sshwire.js';

const [link, pubOut] = process.argv.slice(2);
const info = parsePairingLink(link);

const keys = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
const raw = new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey));
const blob = publicKeyBlob(raw);
const pub = authorizedKey(raw, 'fake-phone');

const res = await pair(info.url, { code: info.code, publicKey: pub, deviceName: 'fake-phone' });
if (!(await verifyPairProof(info.code, res, pub))) throw new Error('pairing proof does not verify');
const macKey = await importMacKey(b64urlDecode(res.secret));
writeFileSync(pubOut, pub + '\n');
console.log(JSON.stringify({ event: 'paired', pcName: res.pcName }));

const client = new Client(info.url, macKey);
const seen = new Set();
for (;;) {
  let reqs;
  try {
    ({ requests: reqs } = await client.requests({ wait: 5 }));
  } catch (e) {
    if (e instanceof ApiError) throw e;
    await new Promise((r) => setTimeout(r, 200)); // agent restarting or gone
    continue;
  }
  for (const r of reqs) {
    if (seen.has(r.id)) continue;
    seen.add(r.id);
    if (!(await verifyRequest(macKey, r))) throw new Error(`request MAC does not verify: ${r.id}`);
    const data = b64decode(r.data);
    let parsed;
    try {
      parsed = parseSignData(data, blob);
    } catch (e) {
      await client.answer(r.id, 'deny');
      console.log(JSON.stringify({ event: 'deny', reason: e.message }));
      continue;
    }
    const entry = { event: '', kind: parsed.kind, forwarded: r.forwarded };
    if (parsed.kind === 'ssh-userauth') {
      entry.user = parsed.user;
      if (parsed.hostKey) entry.hostKey = await fingerprint(parsed.hostKey);
      if (r.claimedHostKey) entry.claimedHostKey = await fingerprint(b64decode(r.claimedHostKey));
    } else {
      entry.namespace = parsed.namespace;
    }
    if (parsed.kind === 'sshsig' && parsed.namespace === 'deny-me') {
      await client.answer(r.id, 'deny');
      entry.event = 'deny';
    } else {
      const sig = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, keys.privateKey, data));
      await client.answer(r.id, 'approve', b64encode(sig));
      entry.event = 'approve';
    }
    console.log(JSON.stringify(entry));
  }
}
