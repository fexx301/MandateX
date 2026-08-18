import assert from "node:assert/strict";
import test from "node:test";

import {
  BSC_CATEGORY_STATE_READ_SELECTORS,
  categoryAdapterDeploymentSha256,
} from "@mandatex/agent-supply-verifier";
import { canonicalSha256 } from "@mandatex/marketplace-core";

import {
  MARKETPLACE_VERIFIER_POLICY_V2_SCHEMA,
  marketplaceVerifierPolicyManifest,
  marketplaceVerifierPolicySha256,
  marketplaceVerifierPolicyV2Manifest,
  marketplaceVerifierPolicyV2Sha256,
} from "../src/index.js";
import { categoryDeployment } from "./category-fixture.js";

const BASE_IDENTITY = Object.freeze({
  passivePolicyFingerprint: "aa".repeat(32),
  trustPolicySha256: "bb".repeat(32),
});

test("category policy v2 preserves the exact locked v1 base", () => {
  const base = marketplaceVerifierPolicyManifest(BASE_IDENTITY);
  const deployment = categoryDeployment();
  const manifest = marketplaceVerifierPolicyV2Manifest({
    ...BASE_IDENTITY,
    categoryAdapterDeployment: deployment,
  });

  assert.equal(
    marketplaceVerifierPolicySha256(BASE_IDENTITY),
    "d8cf9397aaef3d36c805791a96f0d5a4951f4338e1ceb09860db07a299d42195",
  );
  assert.deepEqual(manifest.base, base);
  assert.equal(manifest.schema, MARKETPLACE_VERIFIER_POLICY_V2_SCHEMA);
  assert.deepEqual(
    manifest.categoryPolicy.deployment.adapters.map((entry) => entry.adapterId),
    [
      "aave-v3-health-v1",
      "erc4626-yield-v1",
      "pancakeswap-v3-grid-v1",
      "venus-health-v1",
    ],
  );
  assert.equal(
    manifest.categoryPolicy.deploymentSha256,
    categoryAdapterDeploymentSha256(deployment),
  );
  assert.deepEqual(
    manifest.categoryPolicy.allowedStateReadSelectors,
    BSC_CATEGORY_STATE_READ_SELECTORS,
  );
  assert.equal(manifest.categoryPolicy.confirmationDepth, 2);
  assert.equal(Object.isFrozen(manifest), true);
  assert.equal(Object.isFrozen(manifest.categoryPolicy.deployment), true);
  assert.equal(canonicalSha256(manifest), marketplaceVerifierPolicyV2Sha256({
    ...BASE_IDENTITY,
    categoryAdapterDeployment: deployment,
  }));
  assert.equal(
    marketplaceVerifierPolicyV2Sha256({
      ...BASE_IDENTITY,
      categoryAdapterDeployment: deployment,
    }),
    "0f8af5895c12cc9cfa2bbcea1625d9c803c2b300fea4a9bfc9e2e8a42e44550c",
  );
});

test("category policy v2 binds deployment thresholds and rejects extra fields", () => {
  const first = marketplaceVerifierPolicyV2Sha256({
    ...BASE_IDENTITY,
    categoryAdapterDeployment: categoryDeployment(),
  });
  const second = marketplaceVerifierPolicyV2Sha256({
    ...BASE_IDENTITY,
    categoryAdapterDeployment: categoryDeployment({
      minLiquidityUsdScaled: "2000000000000000000000",
    }),
  });
  assert.notEqual(first, second);

  assert.throws(() =>
    marketplaceVerifierPolicyV2Manifest({
      ...BASE_IDENTITY,
      categoryAdapterDeployment: categoryDeployment(),
      futurePolicyField: true,
    } as never),
  );
});
