import { ApiError, Client, pair } from './lib/api.js';
import { deleteKey, ed25519Supported, loadKey, loadOrCreateKey, sign } from './lib/keys.js';
import { KNOWN_HOSTS } from './lib/known-hosts.js';
import { hasPairingFragment, parsePairingLink } from './lib/pairing.js';
import { importMacKey, verifyPairProof, verifyRequest } from './lib/protocol.js';
import {
  FormatError, authorizedKey, b64decode, b64encode, b64urlDecode, fingerprint, keyType, parseSignData, publicKeyBlob,
} from './lib/sshwire.js';
import * as store from './lib/store.js';
import { visible } from './lib/text.js';

const PAIRING = 'pairing';
const POLL_WAIT_S = 25;
const POLL_TIMEOUT_MS = (POLL_WAIT_S + 10) * 1000;
// After the list of requests changes, approve buttons stay disabled for a
// moment so that a request swapped in under the user's finger cannot be
// approved by a tap meant for another one.
const ARM_DELAY_MS = 1000;

const $ = (id) => document.getElementById(id);

const state = {
  key: null, // {privateKey, publicRaw}
  pairing: null, // {url, macKey, pcName, pairedAt}
  pendingPair: null, // parsed pairing link awaiting confirmation
  requests: new Map(), // id -> view model, in arrival order
  ignored: new Set(), // IDs of requests dropped for a bad MAC
  armedAt: 0,
  serverOffsetMs: 0,
  polling: false,
  pollAbort: null,
  scanStream: null,
  view: 'loading',
};

// ---------------------------------------------------------------- helpers

const isIOS = /iPhone|iPad|iPod/.test(navigator.userAgent)
  || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
const isStandalone = () => window.matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;

function deviceName() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return 'iPhone';
  if (/iPad/.test(ua) || (isIOS && !/iPhone/.test(ua))) return 'iPad';
  if (/Android/.test(ua)) return 'Android';
  return 'Browser';
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let toastTimer;
function toast(msg) {
  const el = $('toast');
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 4000);
}

function describeError(e) {
  if (e instanceof ApiError) {
    if (e.code === 'clock_skew') return 'スマホと PC の時計がずれています。時刻の自動設定を確認してください';
    return e.message;
  }
  if (e instanceof TypeError) {
    return 'PC に接続できません。Tailscale の接続と、PC 側の agent・tailscale serve を確認してください'
      + '（Android の Chrome では「ローカル ネットワーク」へのアクセス許可を求められたら許可してください）';
  }
  return e?.message || String(e);
}

function setConn(kind, text) {
  const el = $('conn');
  el.hidden = !kind && !text;
  el.className = `conn ${kind || ''}`;
  $('conn-text').textContent = text || '';
}

// ---------------------------------------------------------------- views

function show(view) {
  state.view = view;
  for (const v of ['loading', 'unsupported', 'pair-confirm', 'setup', 'scanner', 'main']) {
    $(`view-${v}`).hidden = v !== view;
  }
  const keyVisible = !!state.key && (view === 'main' || view === 'setup');
  $('key-section').hidden = !keyVisible;
  $('settings').hidden = !(view === 'main' || (view === 'setup' && state.key));
  $('unpair').hidden = !state.pairing;
  $('ios-warning').hidden = !(isIOS && !isStandalone() && (view === 'setup' || view === 'pair-confirm'));
  if (view !== 'main') setConn(null);
}

function render() {
  if (state.pendingPair) {
    renderPairConfirm();
    show('pair-confirm');
  } else if (state.pairing) {
    $('main-pc').textContent = state.pairing.pcName || state.pairing.url;
    renderRequests();
    show('main');
    startPolling();
  } else {
    show('setup');
  }
  renderKey();
}

async function renderKey() {
  if (!state.key) return;
  const blob = publicKeyBlob(state.key.publicRaw);
  $('pubkey').textContent = authorizedKey(state.key.publicRaw, 'pocket-ssh-agent');
  $('pubkey-fp').textContent = await fingerprint(blob);
}

// ---------------------------------------------------------------- pairing

function acceptPairingLink(text) {
  try {
    state.pendingPair = parsePairingLink(text);
  } catch (e) {
    toast(e.message);
  }
  render();
}

function renderPairConfirm() {
  const p = state.pendingPair;
  const host = new URL(p.url).host;
  $('pair-host').textContent = host;
  $('pair-name').textContent = p.name ? visible(p.name) : '(なし)';
  $('pair-not-tailnet').hidden = p.isTailnet;
  $('pair-ok').disabled = false;
}

async function confirmPair() {
  const p = state.pendingPair;
  $('pair-ok').disabled = true;
  try {
    state.key = await loadOrCreateKey();
    const publicKey = authorizedKey(state.key.publicRaw, 'pocket-ssh-agent');
    const res = await pair(p.url, { code: p.code, publicKey, deviceName: deviceName() });
    if (!res?.secret || !(await verifyPairProof(p.code, res, publicKey))) {
      throw new Error('PC からの応答を確認できませんでした。ペアリングを中止しました');
    }
    const macKey = await importMacKey(b64urlDecode(res.secret));
    stopPolling();
    state.pairing = { url: p.url, macKey, pcName: res.pcName || p.name, pairedAt: new Date().toISOString() };
    state.requests.clear();
    state.ignored.clear();
    await store.set(PAIRING, state.pairing);
    state.pendingPair = null;
    navigator.storage?.persist?.().catch(() => {});
    render();
    toast('ペアリングしました。公開鍵を GitHub などに登録してください');
  } catch (e) {
    $('pair-ok').disabled = false;
    if (e instanceof ApiError && e.status === 403) {
      toast('コードが無効か期限切れです。PC で pocket-ssh-agent -pair を実行し直してください');
    } else {
      toast(describeError(e));
    }
  }
}

// ---------------------------------------------------------------- QR scanner

async function startScanner() {
  if (!navigator.mediaDevices?.getUserMedia || typeof window.jsQR !== 'function') {
    toast('このブラウザではカメラを使えません。リンクを貼り付けてください');
    return;
  }
  try {
    state.scanStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
  } catch {
    toast('カメラを使用できません（権限を確認してください）');
    return;
  }
  show('scanner');
  const video = $('scan-video');
  video.srcObject = state.scanStream;
  await video.play().catch(() => {});
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d', { willReadFrequently: true });

  const tick = () => {
    if (!state.scanStream) return;
    if (video.readyState >= 2 && video.videoWidth) {
      const scale = Math.min(1, 720 / Math.max(video.videoWidth, video.videoHeight));
      canvas.width = Math.round(video.videoWidth * scale);
      canvas.height = Math.round(video.videoHeight * scale);
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = window.jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' });
      if (code?.data && hasPairingFragment(code.data)) {
        stopScanner();
        acceptPairingLink(code.data);
        return;
      }
    }
    setTimeout(tick, 150);
  };
  tick();
}

function stopScanner() {
  state.scanStream?.getTracks().forEach((t) => t.stop());
  state.scanStream = null;
  $('scan-video').srcObject = null;
}

// ---------------------------------------------------------------- polling

function client() {
  return new Client(state.pairing.url, state.pairing.macKey);
}

async function startPolling() {
  if (state.polling || !state.pairing || document.visibilityState !== 'visible') return;
  state.polling = true;
  setConn('', '接続中…');
  let backoff = 1000;
  while (state.pairing && document.visibilityState === 'visible') {
    const ac = new AbortController();
    state.pollAbort = ac;
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; ac.abort(); }, POLL_TIMEOUT_MS);
    try {
      const res = await client().requests({ wait: POLL_WAIT_S, known: [...state.requests.keys(), ...state.ignored], signal: ac.signal });
      state.serverOffsetMs = Date.parse(res.serverTime) - Date.now();
      await updateRequests(res.requests);
      setConn('ok', '接続済み');
      backoff = 1000;
    } catch (e) {
      if (ac.signal.aborted && !timedOut) break; // stopped on purpose
      if (e instanceof ApiError && e.status === 401 && e.code !== 'clock_skew' && e.code !== 'replay') {
        setConn('error', 'ペアリングが無効です');
        toast('PC 側でペアリングが変わっています。もう一度ペアリングしてください');
        break;
      }
      setConn('error', e instanceof ApiError && e.code === 'clock_skew' ? '時計のずれ' : '再接続中…');
      if (e instanceof ApiError && e.code === 'clock_skew') toast(describeError(e));
      await sleep(backoff);
      backoff = Math.min(backoff * 2, 15000);
    } finally {
      clearTimeout(timer);
    }
  }
  state.polling = false;
  state.pollAbort = null;
}

function stopPolling() {
  state.pollAbort?.abort();
}

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible') {
    if (state.view === 'main') startPolling();
  } else {
    stopPolling();
  }
});

// ---------------------------------------------------------------- requests

async function describeHost(blob) {
  const fp = await fingerprint(blob);
  return { fp, name: KNOWN_HOSTS[fp] || null, type: keyType(blob) };
}

async function toViewModel(r) {
  const vm = {
    id: r.id,
    data: b64decode(r.data),
    expiresAt: Date.parse(r.expiresAt),
    forwarded: !!r.forwarded,
    receivedAt: new Date(),
    busy: false,
  };
  try {
    vm.parsed = parseSignData(vm.data, publicKeyBlob(state.key.publicRaw));
  } catch (e) {
    vm.error = e instanceof FormatError ? '未対応の形式のため署名できません' : String(e);
    return vm;
  }
  if (vm.parsed.kind === 'ssh-userauth') {
    if (vm.parsed.hostKey) {
      vm.host = { ...(await describeHost(vm.parsed.hostKey)), trusted: true };
    } else if (r.claimedHostKey) {
      vm.host = { ...(await describeHost(b64decode(r.claimedHostKey))), trusted: false };
    }
  }
  return vm;
}

async function updateRequests(list) {
  const ids = new Set(list.map((r) => r.id));
  for (const id of state.ignored) {
    if (!ids.has(id)) state.ignored.delete(id);
  }
  let changed = false;
  for (const id of state.requests.keys()) {
    if (!ids.has(id)) {
      state.requests.delete(id);
      changed = true;
    }
  }
  for (const r of list) {
    if (state.requests.has(r.id) || state.ignored.has(r.id)) continue;
    // Requests must come from the paired agent; anything else (e.g. a
    // process squatting the agent's port) is ignored.
    if (!(await verifyRequest(state.pairing.macKey, r))) {
      // Remember it so that the long poll still waits instead of returning
      // immediately because the phone does not "know" this ID.
      console.warn('ignoring request with an invalid MAC', r.id);
      state.ignored.add(r.id);
      continue;
    }
    state.requests.set(r.id, await toViewModel(r));
    changed = true;
  }
  if (changed) {
    state.armedAt = Date.now() + ARM_DELAY_MS;
    setTimeout(renderRequests, ARM_DELAY_MS + 50);
    if (list.length) navigator.vibrate?.(200);
  }
  renderRequests();
}

function addRow(dl, label, value, badge, cls) {
  const dt = document.createElement('dt');
  dt.textContent = label;
  const dd = document.createElement('dd');
  dd.textContent = value;
  if (cls) dd.className = cls;
  if (badge) {
    const b = document.createElement('span');
    b.className = `badge ${badge.cls || ''}`;
    b.textContent = badge.text;
    dd.append(b);
  }
  dl.append(dt, dd);
}

function buildCard(vm) {
  const node = $('tpl-request').content.firstElementChild.cloneNode(true);
  node.dataset.id = vm.id;
  const dl = node.querySelector('.request-kv');
  if (vm.error) {
    node.querySelector('.request-title').textContent = '不明なリクエスト';
    const err = node.querySelector('.request-error');
    err.textContent = vm.error;
    err.hidden = false;
    node.querySelector('.approve').hidden = true;
  } else if (vm.parsed.kind === 'ssh-userauth') {
    node.querySelector('.request-title').textContent = 'SSH ログイン';
    addRow(dl, 'ユーザー', visible(vm.parsed.user));
    if (vm.host?.trusted) {
      addRow(dl, '接続先', vm.host.name || '未登録のサーバー', { text: '署名で確認済み', cls: 'trusted' });
      addRow(dl, 'ホスト鍵', vm.host.fp);
    } else if (vm.host) {
      // Only the PC says so; a compromised PC can claim any server. Make it
      // look clearly different from a verified host.
      addRow(dl, '接続先', `${vm.host.name || '未登録のサーバー'}（未確認）`, { text: 'PC の申告' }, 'claimed');
      addRow(dl, 'ホスト鍵', vm.host.fp);
    } else {
      addRow(dl, '接続先', '不明（SSH クライアントが通知していません）');
    }
  } else {
    node.querySelector('.request-title').textContent = vm.parsed.namespace === 'git' ? 'Git 署名' : 'SSH 署名';
    addRow(dl, '用途', vm.parsed.namespace === 'git' ? 'コミット／タグへの署名' : `名前空間 "${visible(vm.parsed.namespace)}"`);
  }
  if (vm.forwarded) {
    const w = node.querySelector('.request-forwarded');
    w.textContent = '転送された agent 経由の要求です（ssh -A の接続先のサーバーから来ています）。心当たりがなければ拒否してください。';
    w.hidden = false;
  }
  addRow(dl, '受信', vm.receivedAt.toLocaleTimeString());
  node.querySelector('.approve').addEventListener('click', () => answer(vm, 'approve'));
  node.querySelector('.deny').addEventListener('click', () => answer(vm, 'deny'));
  return node;
}

// Cards are added and removed in place; an existing card is never replaced
// by another one at the same position.
function renderRequests() {
  const box = $('requests');
  const existing = new Map([...box.children].map((n) => [n.dataset.id, n]));
  for (const [id, node] of existing) {
    if (!state.requests.has(id)) node.remove();
  }
  for (const vm of state.requests.values()) {
    if (!existing.has(vm.id)) box.append(buildCard(vm));
  }
  const armed = Date.now() >= state.armedAt;
  for (const node of box.children) {
    const vm = state.requests.get(node.dataset.id);
    node.querySelector('.approve').disabled = vm.busy || !armed;
    node.querySelector('.deny').disabled = vm.busy;
  }
  const n = state.requests.size;
  $('no-requests').hidden = n > 0;
  const warn = $('multi-warn');
  warn.hidden = n < 2;
  warn.textContent = `${n} 件の要求が同時に届いています。自分の操作の回数と合わない場合は、心当たりのないものを拒否してください。`;
  document.title = n ? `(${n}) Pocket SSH Agent` : 'Pocket SSH Agent';
  updateTimers();
}

function updateTimers() {
  const now = Date.now() + state.serverOffsetMs;
  for (const node of $('requests').children) {
    const vm = state.requests.get(node.dataset.id);
    if (!vm) continue;
    const left = Math.max(0, Math.round((vm.expiresAt - now) / 1000));
    node.querySelector('.request-timer').textContent = left > 0 ? `残り ${left} 秒` : '期限切れ';
  }
}
setInterval(updateTimers, 1000);

async function answer(vm, decision) {
  if (decision === 'approve' && Date.now() < state.armedAt) return;
  vm.busy = true;
  renderRequests();
  try {
    let sig;
    if (decision === 'approve') {
      if (vm.error) throw new Error('この要求には署名できません');
      sig = b64encode(await sign(state.key.privateKey, vm.data));
    }
    await client().answer(vm.id, decision, sig);
    toast(decision === 'approve' ? '承認しました' : '拒否しました');
    state.requests.delete(vm.id);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) {
      toast('期限切れか、すでに処理済みです');
      state.requests.delete(vm.id);
    } else {
      toast(describeError(e));
      vm.busy = false;
    }
  }
  renderRequests();
}

// ---------------------------------------------------------------- settings

async function unpair() {
  if (!confirm('この PC とのペアリングを解除しますか？（鍵は残ります）')) return;
  stopPolling();
  await store.del(PAIRING);
  state.pairing = null;
  state.requests.clear();
  state.ignored.clear();
  render();
}

async function removeKey() {
  if (!confirm('鍵を削除しますか？ GitHub などに登録した公開鍵は使えなくなります。')) return;
  if (!confirm('本当に削除しますか？ 元に戻せません。')) return;
  stopPolling();
  await store.del(PAIRING);
  await deleteKey();
  state.pairing = null;
  state.key = null;
  state.requests.clear();
  render();
  toast('鍵を削除しました');
}

async function copyPubkey() {
  const text = $('pubkey').textContent;
  try {
    await navigator.clipboard.writeText(text);
    toast('コピーしました');
  } catch {
    const range = document.createRange();
    range.selectNodeContents($('pubkey'));
    const sel = getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    toast('選択しました。コピーしてください');
  }
}

// ---------------------------------------------------------------- init

function bind() {
  $('pair-ok').addEventListener('click', confirmPair);
  $('pair-cancel').addEventListener('click', () => { state.pendingPair = null; render(); });
  $('scan-start').addEventListener('click', startScanner);
  $('scan-cancel').addEventListener('click', () => { stopScanner(); render(); });
  $('paste-ok').addEventListener('click', () => {
    const text = $('paste-input').value;
    $('paste-input').value = '';
    acceptPairingLink(text);
  });
  $('pubkey-copy').addEventListener('click', copyPubkey);
  $('unpair').addEventListener('click', unpair);
  $('delete-key').addEventListener('click', removeKey);
}

async function init() {
  // Never run inside a frame (clickjacking).
  if (window.top !== window.self) {
    document.body.textContent = '';
    return;
  }
  bind();
  if (!window.isSecureContext || !(await ed25519Supported())) {
    show('unsupported');
    return;
  }
  // Read the pairing secret from the fragment, then remove it from the URL
  // and history right away.
  const link = hasPairingFragment(location.hash) ? location.href : null;
  if (link) history.replaceState(null, '', location.pathname + location.search);

  state.key = (await loadKey()) || null;
  const saved = await store.get(PAIRING);
  state.pairing = saved?.macKey ? saved : null;
  if (link && state.pairing) {
    // Any web page can link here, so a link must not replace an existing
    // pairing: re-pairing means unpairing first and scanning in the app.
    render();
    toast('すでにペアリング済みのため、リンクは無視しました。ペアリングし直すには、設定で解除してからアプリ内で QR コードを読み取ってください');
  } else if (link) {
    acceptPairingLink(link);
  } else {
    render();
  }
}

init().catch((e) => {
  show('unsupported');
  toast(describeError(e));
});
