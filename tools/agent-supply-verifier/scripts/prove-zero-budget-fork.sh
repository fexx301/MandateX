#!/bin/sh
set -eu

fork_rpc_url="${BSC_RPC_URL:-https://bsc-dataseed.binance.org}"
anvil_rpc_url="http://127.0.0.1:18545"
anvil_port="18545"
anvil_log="${TMPDIR:-/tmp}/mandatex-anvil-zero-budget.log"

if cast chain-id --rpc-url "$anvil_rpc_url" >/dev/null 2>&1; then
  printf '%s\n' "Refusing to reuse occupied proof port $anvil_rpc_url" >&2
  exit 1
fi

anvil --silent --host 127.0.0.1 --port "$anvil_port" --chain-id 56 \
  --fork-url "$fork_rpc_url" >"$anvil_log" 2>&1 &
anvil_pid=$!

cleanup() {
  kill "$anvil_pid" 2>/dev/null || true
  wait "$anvil_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

attempt=0
while ! cast chain-id --rpc-url "$anvil_rpc_url" >/dev/null 2>&1; do
  if ! kill -0 "$anvil_pid" 2>/dev/null; then
    printf '%s\n' "Anvil fork exited before readiness; log: $anvil_log" >&2
    exit 1
  fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    printf '%s\n' "Anvil fork did not become ready; log: $anvil_log" >&2
    exit 1
  fi
  sleep 1
done

corepack pnpm exec tsx scripts/zero-budget-fork.ts
