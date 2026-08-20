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
import {
  marketplaceCategorySuccessorPolicyManifest,
  marketplaceCategorySuccessorPolicySha256,
} from "../src/category-verifier-policy.js";
import {
  categoryDeployment,
  categorySuccessorDeployment,
  categorySuccessorQuotePolicy,
} from "./category-fixture.js";

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
  assert.equal(Object.hasOwn(manifest.profiles, "categoryAdapterSelection"), false);
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
    "b3a22d9628b5ab68e27d973cb1a27b58120647662b7377646f3d8ed56c716372",
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

test("category policy v2 snapshots proxy identity fields exactly once", () => {
  const identity = {
    ...BASE_IDENTITY,
    categoryAdapterDeployment: categoryDeployment(),
  };
  let gets = 0;
  const proxy = new Proxy(identity, {
    get(target, property, receiver) {
      gets += 1;
      if (property === "categoryAdapterDeployment") {
        return categoryDeployment({
          minLiquidityUsdScaled: "2000000000000000000000",
        });
      }
      return Reflect.get(target, property, receiver);
    },
  });

  const manifest = marketplaceVerifierPolicyV2Manifest(proxy);
  assert.equal(gets, 0);
  assert.deepEqual(manifest, marketplaceVerifierPolicyV2Manifest(identity));
});

test("successor policy is a distinct static manifest with the same deployment provenance", () => {
  const identity = {
    ...BASE_IDENTITY,
    categorySuccessorDeployment: categorySuccessorDeployment(),
    quotePolicy: categorySuccessorQuotePolicy(),
  };
  const successor = marketplaceCategorySuccessorPolicyManifest(identity);
  const legacy = marketplaceVerifierPolicyV2Manifest({
    ...BASE_IDENTITY,
    categoryAdapterDeployment: categoryDeployment(),
  });

  assert.equal(successor.schema, "mandatex.marketplace.category-successor-policy.v1");
  assert.equal(
    successor.contracts.categoryDeployment,
    "mandatex.marketplace.category-successor-deployment.v1",
  );
  assert.notDeepEqual(successor.categoryPolicy, legacy.categoryPolicy);
  assert.equal(
    successor.profiles.categoryAdapterSelection,
    "mandatex.agent-supply.category-adapter-selection.explicit-id.v1",
  );
  assert.equal(
    successor.categoryPolicy.deployment.adapters.every(
      (entry) => !Object.hasOwn(entry, "configuration"),
    ),
    true,
  );
  assert.deepEqual(
    successor.categoryPolicy.infrastructure,
    categorySuccessorDeployment().infrastructure,
  );
  assert.deepEqual(
    successor.categoryPolicy.trustRoot,
    categorySuccessorDeployment().trustRoot,
  );
  assert.equal(
    successor.successorPolicy.quote.endpoint,
    categorySuccessorQuotePolicy().endpoint,
  );
  assert.equal(
    successor.successorPolicy.quote.endpointSha256,
    "048f73574750ec0fa344a3900dbc5e37863a24ab769ebd1260e83658af66df32",
  );
  assert.deepEqual(successor.successorPolicy.quote.domain, {
    chainId: 56,
    verifyingContract: categorySuccessorQuotePolicy().verifyingContract,
  });
  assert.equal(successor.successorPolicy.identity.maxAgeSeconds, 300);
  assert.equal(
    successor.successorPolicy.report.unendorsedTargets,
    "disclose_and_allow_observe_only_hireability",
  );
  assert.equal(successor.successorPolicy.release.productionActivation, "disabled");
  assert.equal(Object.isFrozen(successor), true);
  assert.equal(Object.isFrozen(successor.categoryPolicy), true);
  assert.equal(Object.isFrozen(successor.successorPolicy), true);
  assert.equal(
    marketplaceCategorySuccessorPolicySha256(identity),
    canonicalSha256(successor),
  );
  assert.notEqual(
    marketplaceCategorySuccessorPolicySha256(identity),
    marketplaceVerifierPolicyV2Sha256({
      ...BASE_IDENTITY,
      categoryAdapterDeployment: categoryDeployment(),
    }),
  );
});

test("successor policy hash changes with deployment provenance without changing the legacy vector", () => {
  const first = {
    ...BASE_IDENTITY,
    categorySuccessorDeployment: categorySuccessorDeployment(),
    quotePolicy: categorySuccessorQuotePolicy(),
  };
  const second = {
    ...BASE_IDENTITY,
    categorySuccessorDeployment: {
      ...categorySuccessorDeployment(),
      infrastructure: {
        ...categorySuccessorDeployment().infrastructure,
        venusComptroller: "0x9999999999999999999999999999999999999999",
      },
    },
    quotePolicy: categorySuccessorQuotePolicy(),
  };
  assert.notEqual(
    marketplaceCategorySuccessorPolicySha256(first),
    marketplaceCategorySuccessorPolicySha256(second),
  );
  assert.equal(
    marketplaceVerifierPolicyV2Sha256({
      ...BASE_IDENTITY,
      categoryAdapterDeployment: categoryDeployment(),
    }),
    "b3a22d9628b5ab68e27d973cb1a27b58120647662b7377646f3d8ed56c716372",
  );
});

test("successor policy hash binds the managed trust-root identity", () => {
  const first = {
    ...BASE_IDENTITY,
    categorySuccessorDeployment: categorySuccessorDeployment(),
    quotePolicy: categorySuccessorQuotePolicy(),
  };
  const second = {
    ...BASE_IDENTITY,
    categorySuccessorDeployment: {
      ...categorySuccessorDeployment(),
      trustRoot: {
        ...categorySuccessorDeployment().trustRoot,
        keyId: "successor-root-k2",
      },
    },
    quotePolicy: categorySuccessorQuotePolicy(),
  };
  assert.notEqual(
    marketplaceCategorySuccessorPolicySha256(first),
    marketplaceCategorySuccessorPolicySha256(second),
  );
});

test("successor policy hash binds the exact quote endpoint and domain", () => {
  const base = {
    ...BASE_IDENTITY,
    categorySuccessorDeployment: categorySuccessorDeployment(),
    quotePolicy: categorySuccessorQuotePolicy(),
  };
  const endpointMutation = {
    ...base,
    quotePolicy: {
      ...categorySuccessorQuotePolicy(),
      endpoint: "https://candidate.example/other-quote",
    },
  };
  const contractMutation = {
    ...base,
    quotePolicy: {
      ...categorySuccessorQuotePolicy(),
      verifyingContract: "0x4444444444444444444444444444444444444444",
    },
  };
  assert.notEqual(
    marketplaceCategorySuccessorPolicySha256(base),
    marketplaceCategorySuccessorPolicySha256(endpointMutation),
  );
  assert.notEqual(
    marketplaceCategorySuccessorPolicySha256(base),
    marketplaceCategorySuccessorPolicySha256(contractMutation),
  );
  assert.throws(() =>
    marketplaceCategorySuccessorPolicyManifest({
      ...base,
      quotePolicy: {
        ...categorySuccessorQuotePolicy(),
        endpoint: "http://candidate.example/category-quote",
      },
    }),
  );
  assert.throws(() =>
    marketplaceCategorySuccessorPolicyManifest({
      ...base,
      quotePolicy: {
        endpoint: categorySuccessorQuotePolicy().endpoint,
      },
    } as never),
  );
});
