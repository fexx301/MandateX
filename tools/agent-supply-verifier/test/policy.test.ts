import assert from "node:assert/strict";
import test from "node:test";

import {
  BSC_CHAIN_PROFILES,
  computePolicyFingerprint,
  DEFAULT_SOURCE_BUDGETS,
  PASSIVE_V1_POLICY,
  POLICY_FINGERPRINT,
} from "../src/policy.js";

test("policy fingerprint is canonical and changes with effective policy", () => {
  assert.equal(
    computePolicyFingerprint({ transport: { b: 2, a: 1 }, gates: ["one", "two"] }),
    computePolicyFingerprint({ gates: ["one", "two"], transport: { a: 1, b: 2 } }),
  );
  assert.notEqual(
    computePolicyFingerprint({ transport: { timeoutMs: 8_000 } }),
    computePolicyFingerprint({ transport: { timeoutMs: 8_001 } }),
  );
  assert.equal(POLICY_FINGERPRINT, computePolicyFingerprint(PASSIVE_V1_POLICY));
  assert.match(POLICY_FINGERPRINT, /^[a-f0-9]{64}$/);
});

test("passive v1 policy fixes the reviewed chain, budgets, and closed method surface", () => {
  assert.equal(BSC_CHAIN_PROFILES.mainnet.chainId, 56);
  assert.equal(BSC_CHAIN_PROFILES.mainnet.liveEnabled, true);
  assert.equal(BSC_CHAIN_PROFILES.testnet.liveEnabled, false);
  assert.equal(DEFAULT_SOURCE_BUDGETS.maxCandidates, 8);
  assert.equal(DEFAULT_SOURCE_BUDGETS.scanConcurrency, 2);
  assert.equal(DEFAULT_SOURCE_BUDGETS.requestDeadlineMs, 8_000);
  assert.equal(DEFAULT_SOURCE_BUDGETS.maxDecodedBodyBytes, 256 * 1024);
  assert.equal(PASSIVE_V1_POLICY.chain.requireCanonical, true);
  assert.equal(PASSIVE_V1_POLICY.chain.targetBlockLag, 2);
  assert.equal(PASSIVE_V1_POLICY.transport.methodMatrix.scan.method, "GET");
  assert.equal(PASSIVE_V1_POLICY.transport.methodMatrix.agentCard.method, "GET");
  assert.equal(PASSIVE_V1_POLICY.transport.methodMatrix.rpc.method, "POST");
  assert.equal(PASSIVE_V1_POLICY.classifications.verifiedHireableEnabled, false);
  assert.deepEqual(PASSIVE_V1_POLICY.activeMethods, {
    negotiate: false,
    notify_funded: false,
    create: false,
    fund: false,
  });
});

