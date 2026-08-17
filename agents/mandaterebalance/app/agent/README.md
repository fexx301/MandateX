# mandaterebalance — A2A seller agent

The valuable Agent and the **SOLE key-holder/signer** for the mandaterebalance seller.
Serves A2A directly on AgentCore; every signing op (quote-clamp-sign /
submit / settle) is fixed entrypoint code in `src/signing.ts` — never an
LLM-callable tool.

## What's here

- `src/main.ts` — A2A serving entrypoint (`serveA2a` on port 9000).
- `src/executor.ts` — the SellerAgentExecutor: the negotiate + notify_funded A2A skills.
- `src/agentCard.ts` — the discoverable AgentCard (+ OAuth2/Cognito scheme).
- `src/signing.ts` — protocol-neutral signing entrypoints. ALL on-chain writes
  go through these functions — never an LLM-callable tool.
- `src/model.ts` — provider adapter (e.g. the Pieverse managed model with
  budget-gated LLM-credit auto-renew).
- `src/tools.ts` — read-only chain tools.
- `src/rebalance.ts` — versioned MandateX schemas, fixed PancakeSwap V3 reads,
  deterministic policy gates, signed-task codec, and simulation/refusal receipts.
- `studio.toml` — Agent's own config (wallet, LLM, price bounds, budget).
- the wallet key material lives OUTSIDE this sub-project so deploy packaging can
  never bundle it: an evm-local keystore at the WORKSPACE root `.studio/wallets/`,
  or the twak mnemonic in the project's twak home (gitignored either way).

## Set up

```bash
# from the workspace root — installs the agent package too (pnpm workspace):
pnpm install
```

## Run locally

Run the Agent with `bag dev` from the workspace root — it auto-loads
`.studio/.env.local` and runs the agent in-process (`tsx src/main.ts`, no
Docker). Use `bag dev --container` to run it via `agentcore dev` in Docker
for image parity.

```bash
bag dev                                    # A2A on http://localhost:9000
```

## Milestone 1 product boundary

This reference agent quotes one narrow product: a bounded PancakeSwap V3 LP
rebalance plan on the configured BSC network. It reads the supplied pool and
position NFT, validates a deterministic trigger and target range, and returns
fresh evidence with a proposed permission manifest.

The target width must be divisible by the pool's observed tick spacing. The
agent chooses the aligned range whose midpoint is nearest the current tick,
resolving an exact half-spacing tie toward the greater tick because the upper
endpoint is exclusive. In integer form:

```text
lower = floor((2 * current_tick - target_width_ticks + tick_spacing)
              / (2 * tick_spacing)) * tick_spacing
upper = lower + target_width_ticks
```

Both endpoints are spacing-aligned, `upper - lower` is exactly the declared
target width, and containment uses `[lower, upper)`. A non-divisible width,
unaligned position range, or range outside the approved policy envelope is
refused deterministically.

The reader verifies the RPC's chain ID, requires code at the official
PancakeSwap V3 manager/factory/deployer and supplied pool, and pins every code
lookup and contract call to one EIP-1898 block hash with
`requireCanonical: true`. It observes head `N`, selects the target snapshot at
`N - 2`, and records `snapshot_head_block`,
`confirmation_depth_blocks`, `observed_block`, and `observed_block_hash`.
Two blocks is a minimum consistency buffer for this simulation milestone, not
economic finality. It then checks that the target block number still resolves
to the same hash. RPCs that cannot provide canonical hash-pinned reads fail
closed; there is no fallback to `latest`.

Delivery re-reads state and anchors either a `simulation_ready` receipt or a
rule-based `refused` receipt through ERC-8183. A position-owner change between
quote and delivery is reported as `STATE_DRIFT` with both public owner
addresses. It does **not** move liquidity, simulate EVM calldata, or claim
that a PancakeSwap transaction occurred. The USD cost estimate is supplied
with a timestamp and source URL; milestone 1 checks its freshness and caps but
does not independently verify it through a price oracle.

This revision freezes the strict `mandatex.*.v1` evidence and receipt schema.
Before any future liquidity execution is enabled, the owner and the
position-manager ERC-721 approval must be rechecked immediately before both
simulation and submission. No deployment or funded external `v1` job is part
of this milestone.

The `negotiate` data part uses this shape. The seller ignores caller-provided
task text and terms, then signs its own normalized, sanitizer-safe payload:

```json
{
  "skill": "negotiate",
  "request": {
    "mandate": {
      "version": "1",
      "mandate_id": "rebalance-demo-1",
      "category": "rebalancing",
      "chain_id": 97,
      "protocol": "pancakeswap-v3",
      "expires_at": 1800000900,
      "max_evidence_age_seconds": 120,
      "position": {
        "pool_address": "0x1111111111111111111111111111111111111111",
        "position_manager_address": "0x427bF5b37357632377eCbEC9de3626C71A5396c1",
        "token_id": "42"
      },
      "range_policy": {
        "approved_lower_tick": -600,
        "approved_upper_tick": 600,
        "target_width_ticks": 120,
        "trigger_mode": "boundary_proximity",
        "trigger_distance_ticks": 30,
        "max_delivery_tick_drift": 30
      },
      "limits": {
        "max_gas_usd": 3,
        "max_slippage_bps": 50,
        "max_exposure_usd": 1000
      },
      "execution_estimate": {
        "gas_usd": 1.25,
        "slippage_bps": 30,
        "exposure_usd": 500,
        "observed_at": 1800000000,
        "source_url": "https://example.com/estimates/rebalance-demo-1"
      },
      "permissions": {
        "allowed_contracts": [
          "0x427bF5b37357632377eCbEC9de3626C71A5396c1"
        ],
        "allowed_calls": [
          "decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
          "collect((uint256,address,uint128,uint128))",
          "mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))"
        ],
        "spend_cap_usd": 750,
        "expires_at": 1800000600
      }
    }
  }
}
```

Use current Unix timestamps and real BSC testnet contracts/position IDs when
calling the live reader. Run the deterministic suite without a wallet:

```bash
corepack pnpm test
corepack pnpm run build
```

Run the opt-in live reader check against BSC testnet without a wallet or
transaction:

```bash
STUDIO_BSC_TESTNET_RPC=https://bsc-testnet-rpc.publicnode.com corepack pnpm run test:live
```

`MANDATEX_LIVE_POOL` and `MANDATEX_LIVE_TOKEN_ID` can replace the default
ephemeral fixture. On August 16, 2026, the default fixture (position `36867`,
pool `0x11e2ea8492f7a6d0499ee7c2428259d08c8806b6`) returned a canonical snapshot
at block `125440863`, hash
`0xc02219b655c8c6c1a04a4327f4c59379db5234173cde867dc88fcb0c4318dd1c`,
with nonzero pool and position liquidity. The fixture can change or disappear,
so it is a smoke-test input rather than a permanent protocol guarantee.

The deterministic suite also covers raw EIP-1898 transport parameters,
canonical-retry exhaustion, owner and expiry drift, near-limit task codec
round trips, and the Express/JSON-RPC A2A negotiate-to-receipt flow on an
ephemeral loopback port. The live check is read-only and wallet-free.

## Deploy

No deployment was performed for this milestone. Deployment remains an
explicit follow-up action that must name the provider.

```bash
# From the workspace root:
bag deploy --provider aws
# ships to AgentCore (--protocol A2A) after a readiness sweep; the wallet
# is injected via AWS Secrets Manager, never in the package.
```
