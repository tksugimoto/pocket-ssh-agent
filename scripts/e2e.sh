#!/usr/bin/env bash
# End-to-end test on Linux: real agent binary + scripted phone (using the
# PWA's libraries) + OpenSSH client and a throwaway sshd.
#
# Checks that
#   - ssh login works through the agent and the phone sees the server's
#     host key inside the signed data,
#   - "ssh-keygen -Y sign" (git commit signing) works and verifies,
#   - a request denied on the phone fails.
#
# Requires: go, node >= 22, ssh, ssh-keygen, sshd.
set -euo pipefail
cd "$(dirname "$0")/.."

API_PORT=${API_PORT:-17766}
SSH_PORT=${SSH_PORT:-2222}
WORK=$(mktemp -d)
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  if [ "${KEEP:-}" = 1 ]; then echo "work dir: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  for f in agent.log phone.log sshd.log; do
    echo "--- $f" >&2
    cat "$WORK/$f" >&2 2>/dev/null || true
  done
  exit 1
}

wait_for() { # wait_for <seconds> <command...>
  local n=$(($1 * 10)); shift
  for _ in $(seq "$n"); do "$@" >/dev/null 2>&1 && return 0; sleep 0.1; done
  return 1
}

echo "== build"
go build -o "$WORK/pocket-ssh-agent" ./cmd/pocket-ssh-agent

echo "== start agent"
SOCK="$WORK/agent.sock"
"$WORK/pocket-ssh-agent" \
  -mode serve -listen "127.0.0.1:$API_PORT" -socket "$SOCK" -config "$WORK/config.json" \
  -public-url "http://127.0.0.1:$API_PORT" -web-url "https://localhost/" \
  -name e2e-pc -timeout 20s >"$WORK/agent.log" 2>&1 &
PIDS+=($!)
wait_for 10 grep -q '#pair=' "$WORK/agent.log" || fail "agent did not print a pairing link"
LINK=$(grep -o 'https://localhost/#pair=[A-Za-z0-9_-]*' "$WORK/agent.log" | head -1)

echo "== pair fake phone"
node test/e2e/fake-phone.mjs "$LINK" "$WORK/phone.pub" >"$WORK/phone.log" 2>&1 &
PIDS+=($!)
wait_for 10 test -s "$WORK/phone.pub" || fail "phone did not pair"
grep -q '"pcName":"e2e-pc"' "$WORK/phone.log" || fail "unexpected pairing response"

export SSH_AUTH_SOCK="$SOCK"
ssh-add -L | grep -q "$(cut -d' ' -f2 "$WORK/phone.pub")" || fail "agent does not list the phone key"

echo "== start sshd"
ssh-keygen -q -t ed25519 -N '' -f "$WORK/hostkey"
cp "$WORK/phone.pub" "$WORK/authorized_keys"
chmod 600 "$WORK/authorized_keys"
cat >"$WORK/sshd_config" <<EOF
Port $SSH_PORT
ListenAddress 127.0.0.1
HostKey $WORK/hostkey
AuthorizedKeysFile $WORK/authorized_keys
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
UsePAM no
StrictModes no
PidFile $WORK/sshd.pid
EOF
if [ "$(id -u)" = 0 ]; then mkdir -p /run/sshd; fi
SSHD=$(command -v sshd || echo /usr/sbin/sshd)
"$SSHD" -f "$WORK/sshd_config" -D -e >"$WORK/sshd.log" 2>&1 &
PIDS+=($!)
wait_for 10 bash -c "echo > /dev/tcp/127.0.0.1/$SSH_PORT" || fail "sshd did not start"

echo "== ssh login"
OUT=$(ssh -F /dev/null -p "$SSH_PORT" -o BatchMode=yes -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$(id -un)@127.0.0.1" echo e2e-ok) || fail "ssh login failed"
[ "$OUT" = e2e-ok ] || fail "unexpected ssh output: $OUT"
HOST_FP=$(ssh-keygen -l -f "$WORK/hostkey.pub" | cut -d' ' -f2)
grep '"kind":"ssh-userauth"' "$WORK/phone.log" | grep -q "\"hostKey\":\"$HOST_FP\"" \
  || fail "phone did not see the server host key ($HOST_FP) in the signed data"
grep '"kind":"ssh-userauth"' "$WORK/phone.log" | grep -q "\"claimedHostKey\":\"$HOST_FP\"" \
  || fail "session-bind did not report the server host key"
grep '"kind":"ssh-userauth"' "$WORK/phone.log" | grep -q '"forwarded":false' || fail "local request flagged as forwarded"

echo "== git-style signature (ssh-keygen -Y sign)"
echo "hello from e2e" >"$WORK/msg"
ssh-keygen -Y sign -f "$WORK/phone.pub" -n git "$WORK/msg" 2>/dev/null || fail "ssh-keygen -Y sign failed"
echo "e2e@example $(cat "$WORK/phone.pub")" >"$WORK/allowed_signers"
ssh-keygen -Y verify -f "$WORK/allowed_signers" -I e2e@example -n git -s "$WORK/msg.sig" <"$WORK/msg" >/dev/null \
  || fail "signature does not verify"

echo "== request through a forwarded agent is flagged"
cp "$WORK/msg" "$WORK/msg3"
ssh -F /dev/null -A -p "$SSH_PORT" -o BatchMode=yes -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR "$(id -un)@127.0.0.1" \
  "ssh-keygen -Y sign -f '$WORK/phone.pub' -n forwarded-test '$WORK/msg3'" >/dev/null 2>&1 \
  || fail "signing through the forwarded agent failed"
grep '"namespace":"forwarded-test"' "$WORK/phone.log" | grep -q '"forwarded":true' \
  || fail "forwarded request was not flagged"

echo "== denied request fails"
cp "$WORK/msg" "$WORK/msg2"
if ssh-keygen -Y sign -f "$WORK/phone.pub" -n deny-me "$WORK/msg2" 2>/dev/null; then
  fail "denied request produced a signature"
fi
wait_for 5 bash -c "grep '\"namespace\":\"deny-me\"' '$WORK/phone.log' | grep -q '\"event\":\"deny\"'" || fail "phone did not log the denial"

echo "PASS"
