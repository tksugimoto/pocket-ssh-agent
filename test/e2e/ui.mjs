// Browser end-to-end test: the real PWA in headless Chromium, the real agent
// binary and ssh-keygen as the SSH client.
//
//   node test/e2e/ui.mjs
//
// Uses Playwright's Chromium (npx playwright install chromium). To use
// another Chromium build, set CHROME_PATH (and optionally CHROME_ARGS as a
// JSON array).

import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { chromium } from 'playwright';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const webDir = join(root, 'web');
const work = mkdtempSync(join(tmpdir(), 'psa-ui-'));
const API_PORT = Number(process.env.API_PORT || 17767);
const cleanups = [];

function log(msg) {
  console.log(`== ${msg}`);
}

// --- static server for web/ (http://localhost is a secure context)
const types = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
  '.png': 'image/png',
};
const web = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p.endsWith('/')) p += 'index.html';
  const file = normalize(join(webDir, p));
  if (!file.startsWith(webDir)) {
    res.writeHead(403).end();
    return;
  }
  try {
    const body = readFileSync(file);
    res.writeHead(200, { 'Content-Type': types[extname(file)] || 'application/octet-stream' }).end(body);
  } catch {
    res.writeHead(404).end();
  }
});
web.listen(0, '127.0.0.1');
await once(web, 'listening');
cleanups.push(() => web.close());
const webURL = `http://localhost:${web.address().port}/`;

function run(cmd, args, env = {}) {
  const p = spawn(cmd, args, { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  p.stdout.on('data', (d) => { out += d; });
  p.stderr.on('data', (d) => { out += d; });
  const done = new Promise((r) => p.on('exit', (code) => r(code)));
  return { proc: p, done, output: () => out };
}

async function waitFor(fn, ms, what) {
  const end = Date.now() + ms;
  for (;;) {
    const v = fn();
    if (v) return v;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 100));
  }
}

let browser;
let agent;
try {
  log('build agent');
  const bin = join(work, 'pocket-ssh-agent');
  execFileSync('go', ['build', '-o', bin, './cmd/pocket-ssh-agent'], { cwd: root, stdio: 'inherit' });

  log('start agent');
  const sock = join(work, 'agent.sock');
  agent = run(bin, [
    '-mode', 'serve', '-listen', `127.0.0.1:${API_PORT}`, '-socket', sock, '-config', join(work, 'config.json'),
    '-public-url', `http://127.0.0.1:${API_PORT}`, '-web-url', webURL, '-name', 'ui-test-pc', '-timeout', '20s',
  ]);
  cleanups.push(() => agent.proc.kill());
  const link = await waitFor(() => agent.output().match(/http:\/\/localhost:\d+\/#pair=[A-Za-z0-9_-]+/)?.[0], 10000, 'pairing link');

  log('open PWA and pair');
  const args = process.env.CHROME_ARGS ? JSON.parse(process.env.CHROME_ARGS) : [];
  browser = await chromium.launch({ executablePath: process.env.CHROME_PATH || undefined, args, headless: true });
  const page = await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 });
  // Set SCREENSHOT_DIR to save screenshots of each step.
  const shot = async (name) => {
    if (process.env.SCREENSHOT_DIR) await page.screenshot({ path: join(process.env.SCREENSHOT_DIR, `${name}.png`) });
  };
  const pageErrors = [];
  page.on('pageerror', (e) => pageErrors.push(e));
  page.on('console', (m) => { if (m.type() === 'error') pageErrors.push(new Error(m.text())); });

  await page.goto(link);
  await page.waitForSelector('#view-pair-confirm:not([hidden])');
  assert.equal(await page.textContent('#pair-name'), 'ui-test-pc');
  assert.equal(new URL(page.url()).hash, '', 'pairing secret must be removed from the URL');
  await shot('1-pair-confirm');
  await page.click('#pair-ok');
  await page.waitForSelector('#view-main:not([hidden])');
  await page.waitForSelector('#conn.ok');
  await shot('2-paired');
  const pub = (await page.textContent('#pubkey')).trim();
  assert.match(pub, /^ssh-ed25519 \S+ pocket-ssh-agent$/);
  const pubFile = join(work, 'phone.pub');
  writeFileSync(pubFile, pub + '\n');

  const sshEnv = { SSH_AUTH_SOCK: sock };
  const listed = execFileSync('ssh-add', ['-L'], { env: { ...process.env, ...sshEnv } }).toString();
  assert.ok(listed.includes(pub.split(' ')[1]), 'agent lists the key generated in the browser');

  log('approve a git signature in the PWA');
  const msg = join(work, 'msg');
  writeFileSync(msg, 'hello from the UI test\n');
  const signer = run('ssh-keygen', ['-Y', 'sign', '-f', pubFile, '-n', 'git', msg], sshEnv);
  await page.waitForSelector('.request .approve');
  assert.equal((await page.textContent('.request .request-title')).trim(), 'Git 署名');
  assert.equal(await page.isDisabled('.request .approve'), true, 'approve is disarmed right after a card appears');
  await shot('3-request');
  await page.click('.request .approve');
  assert.equal(await signer.done, 0, `ssh-keygen sign failed: ${signer.output()}`);
  writeFileSync(join(work, 'allowed'), `ui@example ${pub}\n`);
  execFileSync('ssh-keygen', ['-Y', 'verify', '-f', join(work, 'allowed'), '-I', 'ui@example', '-n', 'git', '-s', `${msg}.sig`], {
    input: readFileSync(msg),
  });
  await page.waitForSelector('#no-requests:not([hidden])');

  log('deny in the PWA');
  const msg2 = join(work, 'msg2');
  writeFileSync(msg2, 'deny me\n');
  const signer2 = run('ssh-keygen', ['-Y', 'sign', '-f', pubFile, '-n', 'git', msg2], sshEnv);
  await page.waitForSelector('.request .deny');
  await page.click('.request .deny');
  assert.notEqual(await signer2.done, 0, 'denied request must fail');

  log('key and pairing survive a reload');
  await page.reload();
  await page.waitForSelector('#view-main:not([hidden])');
  assert.equal((await page.textContent('#pubkey')).trim(), pub);

  log('a pairing link does not replace an existing pairing');
  await page.goto('about:blank');
  await page.goto(link);
  await page.waitForSelector('#view-main:not([hidden])');
  assert.match(await page.textContent('#toast'), /リンクは無視しました/);
  assert.equal(new URL(page.url()).hash, '', 'pairing secret must be removed from the URL');

  assert.deepEqual(pageErrors.map(String), [], 'no errors in the page');
  console.log('PASS');
} catch (e) {
  console.error('FAIL:', e);
  if (agent) console.error('--- agent output\n' + agent.output());
  process.exitCode = 1;
} finally {
  await browser?.close();
  for (const c of cleanups.reverse()) c();
  rmSync(work, { recursive: true, force: true });
}
