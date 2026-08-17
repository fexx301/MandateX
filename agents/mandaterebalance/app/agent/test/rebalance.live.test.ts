import assert from "node:assert/strict";
import test from "node:test";
import {
  BSC_SNAPSHOT_CONFIRMATION_DEPTH_BLOCKS,
  decodeSignedRebalanceTask,
  PANCAKE_V3_DEPLOYMENTS,
  PancakeV3StateReader,
  type RebalanceEvidence,
  RebalanceMandateSchema,
  RebalanceService,
  REQUIRED_REBALANCE_CALLS,
} from "../src/rebalance.js";

const enabled = process.env.MANDATEX_LIVE_BSC_TESTNET === "1";
const defaultPool = "0x11e2ea8492f7a6d0499ee7c2428259d08c8806b6";
const defaultTokenId = "36867";

test(
  "live BSC testnet reader returns a canonical hash-pinned position snapshot",
  { skip: !enabled, timeout: 90_000 },
  async () => {
    const now = Math.floor(Date.now() / 1000);
    const manager = PANCAKE_V3_DEPLOYMENTS["bsc-testnet"].position_manager;
    const mandate = RebalanceMandateSchema.parse({
      version: "1",
      mandate_id: "live-smoke",
      category: "rebalancing",
      chain_id: 97,
      protocol: "pancakeswap-v3",
      expires_at: now + 900,
      max_evidence_age_seconds: 120,
      position: {
        pool_address: process.env.MANDATEX_LIVE_POOL ?? defaultPool,
        position_manager_address: manager,
        token_id: process.env.MANDATEX_LIVE_TOKEN_ID ?? defaultTokenId,
      },
      range_policy: {
        approved_lower_tick: -887272,
        approved_upper_tick: 887272,
        target_width_ticks: 600,
        trigger_mode: "out_of_range",
        trigger_distance_ticks: 0,
        max_delivery_tick_drift: 200,
      },
      limits: {
        max_gas_usd: 10,
        max_slippage_bps: 100,
        max_exposure_usd: 1000,
      },
      execution_estimate: {
        gas_usd: 1,
        slippage_bps: 10,
        exposure_usd: 100,
        observed_at: now - 5,
        source_url: "https://example.com/mandatex-live-smoke",
      },
      permissions: {
        allowed_contracts: [manager],
        allowed_calls: [...REQUIRED_REBALANCE_CALLS],
        spend_cap_usd: 1000,
        expires_at: now + 600,
      },
    });

    let evidence: RebalanceEvidence;
    try {
      evidence = await new PancakeV3StateReader().read(mandate, "bsc-testnet");
    } catch {
      assert.fail(
        "live BSC testnet snapshot failed; verify the configured RPC and ephemeral position fixture",
      );
    }

    assert.equal(evidence.network, "bsc-testnet");
    assert.equal(evidence.chain_id, 97);
    assert.equal(evidence.position_manager_address, manager);
    assert.equal(
      evidence.confirmation_depth_blocks,
      BSC_SNAPSHOT_CONFIRMATION_DEPTH_BLOCKS,
    );
    assert.equal(
      evidence.snapshot_head_block - evidence.observed_block,
      BSC_SNAPSHOT_CONFIRMATION_DEPTH_BLOCKS,
    );
    assert.equal(
      evidence.pool_address,
      (process.env.MANDATEX_LIVE_POOL ?? defaultPool).toLowerCase(),
    );
    assert.equal(
      evidence.position_token_id,
      process.env.MANDATEX_LIVE_TOKEN_ID ?? defaultTokenId,
    );
    assert.match(evidence.observed_block_hash, /^0x[0-9a-f]{64}$/);
    assert.ok(BigInt(evidence.pool_liquidity) > 0n);
    assert.ok(BigInt(evidence.position_liquidity) > 0n);
    assert.ok(
      evidence.sources.some(
        (source) => source.observed_block === evidence.observed_block,
      ),
    );

    const service = new RebalanceService({
      network: "bsc-testnet",
      reader: { async read() { return evidence; } },
      now: () => now,
    });
    const quote = await service.prepareQuote({ mandate });
    assert.equal(quote.ok, true);
    if (!quote.ok) return;
    const decoded = decodeSignedRebalanceTask(
      String(quote.request.task_description),
    );
    assert.equal(
      (decoded.evidence as RebalanceEvidence).observed_block_hash,
      evidence.observed_block_hash,
    );
  },
);
