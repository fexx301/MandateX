import assert from "node:assert/strict";

import {
  CATEGORY_ADAPTER_REGISTRY,
  DEFAULT_MIN_HEALTH_FACTOR_SCALED,
  GRID_ADAPTER_ID,
  GRID_EVIDENCE_SCHEMA,
  HEALTH_ADAPTER_ID,
  HEALTH_EVIDENCE_SCHEMA,
  SELECTOR_GET_USER_ACCOUNT_DATA,
  SELECTOR_SLOT0,
  SELECTOR_TOTAL_ASSETS,
  SELECTOR_TOTAL_SUPPLY,
  V3_MAX_TICK,
  V3_MIN_TICK,
  YIELD_ADAPTER_ID,
  YIELD_EVIDENCE_SCHEMA,
} from "../../category-adapters/dist/policy.js";
import {
  marketplaceCategoryDeploymentSha256,
  parseMarketplaceCategoryDeploymentManifest,
} from "../src/category-policy.ts";

const addresses = {
  grid: "0x1111111111111111111111111111111111111111",
  yield: "0x2222222222222222222222222222222222222222",
  healthPool: "0x3333333333333333333333333333333333333333",
  healthAccount: "0x4444444444444444444444444444444444444444",
};

const manifest = {
  schema: "mandatex.marketplace.category-deployment.v1",
  chainId: 56,
  categories: [
    {
      category: "grid",
      enabled: true,
      adapterId: GRID_ADAPTER_ID,
      evidenceSchema: GRID_EVIDENCE_SCHEMA,
      validationProfile: "mandatex.marketplace.category-grid-validation.v1",
      protocol: "pancakeswap-v3",
      metric: "pool slot0().tick versus the declared grid band",
      reads: [{ label: "slot0", selector: SELECTOR_SLOT0 }],
      configuration: {
        poolAddress: addresses.grid,
        lowerTick: V3_MIN_TICK,
        upperTick: V3_MAX_TICK,
      },
    },
    {
      category: "yield",
      enabled: true,
      adapterId: YIELD_ADAPTER_ID,
      evidenceSchema: YIELD_EVIDENCE_SCHEMA,
      validationProfile: "mandatex.marketplace.category-yield-validation.v1",
      protocol: "erc4626",
      metric: "totalAssets/totalSupply share price versus a declared floor",
      reads: [
        { label: "totalAssets", selector: SELECTOR_TOTAL_ASSETS },
        { label: "totalSupply", selector: SELECTOR_TOTAL_SUPPLY },
      ],
      configuration: {
        vaultAddress: addresses.yield,
        minSharePriceScaled: "1000000000000000000",
      },
    },
    {
      category: "health",
      enabled: true,
      adapterId: HEALTH_ADAPTER_ID,
      evidenceSchema: HEALTH_EVIDENCE_SCHEMA,
      validationProfile: "mandatex.marketplace.category-health-validation.v1",
      protocol: "aave-v3",
      metric: "getUserAccountData().healthFactor versus a declared floor",
      reads: [
        {
          label: "getUserAccountData",
          selector: SELECTOR_GET_USER_ACCOUNT_DATA,
        },
      ],
      configuration: {
        poolAddress: addresses.healthPool,
        accountAddress: addresses.healthAccount,
      },
    },
  ],
};

export { manifest };

const parsed = parseMarketplaceCategoryDeploymentManifest(manifest);
assert.deepEqual(
  parsed.categories.map((entry) => entry.category),
  ["grid", "health", "yield"],
);
assert.equal(
  parsed.categories.find((entry) => entry.category === "health")?.configuration
    .minHealthFactorScaled,
  DEFAULT_MIN_HEALTH_FACTOR_SCALED,
);
assert.equal(
  marketplaceCategoryDeploymentSha256(manifest),
  "b2a8aae6a012c687bee16f36a6499d5596293c0f4267a0238216098768b462c1",
);

for (const registryEntry of CATEGORY_ADAPTER_REGISTRY) {
  const entry = parsed.categories.find(
    (candidate) => candidate.category === registryEntry.category,
  );
  assert.ok(entry);
  assert.equal(entry.adapterId, registryEntry.adapterId);
  assert.equal(entry.evidenceSchema, registryEntry.evidenceSchema);
  assert.equal(entry.protocol, registryEntry.protocol);
  assert.equal(entry.metric, registryEntry.metric);
  assert.equal(entry.reads.length, registryEntry.reads);
}

assert.notEqual(
  marketplaceCategoryDeploymentSha256(manifest),
  marketplaceCategoryDeploymentSha256({
    ...manifest,
    categories: manifest.categories.map((entry) =>
      entry.category === "health"
        ? {
            ...entry,
            configuration: {
              ...entry.configuration,
              minHealthFactorScaled: "1100000000000000001",
            },
          }
        : entry,
    ),
  }),
);

const disabledManifest = {
  ...manifest,
  categories: manifest.categories.map(({ configuration: _configuration, ...entry }) => ({
    ...entry,
    enabled: false,
  })),
};
assert.equal(
  parseMarketplaceCategoryDeploymentManifest(disabledManifest).categories.every(
    (entry) => !entry.enabled,
  ),
  true,
);
assert.notEqual(
  marketplaceCategoryDeploymentSha256(manifest),
  marketplaceCategoryDeploymentSha256(disabledManifest),
);

console.log("category adapter/service policy conformance: passed");
