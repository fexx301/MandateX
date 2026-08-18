import assert from "node:assert/strict";

import {
  CATEGORY_ADAPTER_REGISTRY,
  DEFAULT_MIN_HEALTH_FACTOR_SCALED,
  GRID_ADAPTER_ID,
  GRID_EVIDENCE_SCHEMA,
  HEALTH_ADAPTER_ID,
  HEALTH_EVIDENCE_SCHEMA,
  SELECTOR_BORROW_BALANCE_STORED,
  SELECTOR_GET_ACCOUNT_LIQUIDITY,
  SELECTOR_GET_ASSETS_IN,
  SELECTOR_GET_USER_ACCOUNT_DATA,
  SELECTOR_SLOT0,
  SELECTOR_TOTAL_ASSETS,
  SELECTOR_TOTAL_SUPPLY,
  VENUS_HEALTH_ADAPTER_ID,
  VENUS_HEALTH_EVIDENCE_SCHEMA,
  V3_MAX_TICK,
  V3_MIN_TICK,
  YIELD_ADAPTER_ID,
  YIELD_EVIDENCE_SCHEMA,
  venusHealthAdapterConfigSchema,
} from "../../category-adapters/dist/policy.js";
import {
  CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA as VERIFIER_CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA,
  CATEGORY_ADAPTER_VALIDATION_PROFILES as VERIFIER_CATEGORY_ADAPTER_VALIDATION_PROFILES,
  categoryAdapterDeploymentSha256 as verifierCategoryAdapterDeploymentSha256,
  parseCategoryAdapterDeploymentManifest as parseVerifierCategoryAdapterDeploymentManifest,
} from "../../agent-supply-verifier/src/category/policy.ts";
import {
  BSC_CATEGORY_STATE_READ_SELECTORS,
} from "../../agent-supply-verifier/src/transport/http.ts";
import {
  MARKETPLACE_CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA,
  MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES,
  marketplaceCategoryAdapterDeploymentSha256,
  parseMarketplaceCategoryAdapterDeploymentManifest,
} from "../src/category-policy.ts";

const addresses = {
  grid: "0x1111111111111111111111111111111111111111",
  yield: "0x2222222222222222222222222222222222222222",
  healthPool: "0x3333333333333333333333333333333333333333",
  healthAccount: "0x4444444444444444444444444444444444444444",
  venusComptroller: "0x5555555555555555555555555555555555555555",
  venusBorrowMarket: "0x6666666666666666666666666666666666666666",
};

const descriptors = [
  {
    adapterId: GRID_ADAPTER_ID,
    category: "grid",
    evidenceSchema: GRID_EVIDENCE_SCHEMA,
    validationProfile: MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES.grid,
    protocol: "pancakeswap-v3",
    metric: "pool slot0().tick versus the declared grid band",
    reads: [{ label: "slot0", selector: SELECTOR_SLOT0, target: "pool" }],
  },
  {
    adapterId: YIELD_ADAPTER_ID,
    category: "yield",
    evidenceSchema: YIELD_EVIDENCE_SCHEMA,
    validationProfile: MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES.yield,
    protocol: "erc4626",
    metric: "totalAssets/totalSupply share price versus a declared floor",
    reads: [
      { label: "totalAssets", selector: SELECTOR_TOTAL_ASSETS, target: "vault" },
      { label: "totalSupply", selector: SELECTOR_TOTAL_SUPPLY, target: "vault" },
    ],
  },
  {
    adapterId: HEALTH_ADAPTER_ID,
    category: "health",
    evidenceSchema: HEALTH_EVIDENCE_SCHEMA,
    validationProfile:
      MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES.aaveHealth,
    protocol: "aave-v3",
    metric: "getUserAccountData().healthFactor versus a declared floor",
    reads: [
      {
        label: "getUserAccountData",
        selector: SELECTOR_GET_USER_ACCOUNT_DATA,
        target: "pool",
      },
    ],
  },
  {
    adapterId: VENUS_HEALTH_ADAPTER_ID,
    category: "health",
    evidenceSchema: VENUS_HEALTH_EVIDENCE_SCHEMA,
    validationProfile:
      MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES.venusHealth,
    protocol: "venus",
    metric:
      "getAccountLiquidity() excess liquidity and shortfall plus monitored-market borrowBalanceStored() versus a declared floor",
    reads: [
      {
        label: "getAccountLiquidity",
        selector: SELECTOR_GET_ACCOUNT_LIQUIDITY,
        target: "comptroller",
      },
      { label: "getAssetsIn", selector: SELECTOR_GET_ASSETS_IN, target: "comptroller" },
      {
        label: "borrowBalanceStored",
        selector: SELECTOR_BORROW_BALANCE_STORED,
        target: "borrowMarket",
      },
    ],
  },
];

const disabledManifest = {
  schema: MARKETPLACE_CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA,
  chainId: 56,
  adapters: descriptors.map((entry) => ({ ...entry, enabled: false })),
};

const parsed = parseMarketplaceCategoryAdapterDeploymentManifest(disabledManifest);
const verifierParsed = parseVerifierCategoryAdapterDeploymentManifest(disabledManifest);
assert.equal(
  VERIFIER_CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA,
  MARKETPLACE_CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA,
);
assert.deepEqual(
  VERIFIER_CATEGORY_ADAPTER_VALIDATION_PROFILES,
  MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES,
);
assert.deepEqual(verifierParsed, parsed);
assert.equal(
  verifierCategoryAdapterDeploymentSha256(disabledManifest),
  marketplaceCategoryAdapterDeploymentSha256(disabledManifest),
);
assert.deepEqual(
  BSC_CATEGORY_STATE_READ_SELECTORS,
  descriptors.flatMap((entry) => entry.reads.map((read) => read.selector)),
);
assert.deepEqual(
  parsed.adapters.map((entry) => entry.adapterId),
  [
    HEALTH_ADAPTER_ID,
    YIELD_ADAPTER_ID,
    GRID_ADAPTER_ID,
    VENUS_HEALTH_ADAPTER_ID,
  ],
);
assert.deepEqual(
  Object.fromEntries(
    parsed.adapters.map((entry) => [entry.adapterId, entry.evidenceSchema]),
  ),
  {
    [GRID_ADAPTER_ID]: GRID_EVIDENCE_SCHEMA,
    [YIELD_ADAPTER_ID]: YIELD_EVIDENCE_SCHEMA,
    [HEALTH_ADAPTER_ID]: HEALTH_EVIDENCE_SCHEMA,
    [VENUS_HEALTH_ADAPTER_ID]: VENUS_HEALTH_EVIDENCE_SCHEMA,
  },
);

for (const registryEntry of CATEGORY_ADAPTER_REGISTRY) {
  const expected = descriptors.find(
    (candidate) => candidate.adapterId === registryEntry.adapterId,
  );
  const serviceEntry = parsed.adapters.find(
    (candidate) => candidate.adapterId === registryEntry.adapterId,
  );
  assert.ok(expected, `unrecognized adapter registry ID: ${registryEntry.adapterId}`);
  assert.ok(serviceEntry, `service manifest omitted: ${registryEntry.adapterId}`);
  assert.equal(serviceEntry.category, registryEntry.category);
  assert.equal(serviceEntry.evidenceSchema, registryEntry.evidenceSchema);
  assert.equal(serviceEntry.protocol, registryEntry.protocol);
  assert.equal(serviceEntry.metric, registryEntry.metric);
  assert.equal(serviceEntry.reads.length, registryEntry.reads);
  assert.deepEqual(serviceEntry.reads, expected.reads);
}
assert.equal(CATEGORY_ADAPTER_REGISTRY.length, descriptors.length);

const aaveEnabled = {
  ...disabledManifest,
  adapters: disabledManifest.adapters.map((entry) =>
    entry.adapterId === HEALTH_ADAPTER_ID
      ? {
          ...entry,
          enabled: true,
          configuration: {
            poolAddress: addresses.healthPool,
            accountAddress: addresses.healthAccount,
          },
        }
      : entry,
  ),
};
const parsedAave = parseMarketplaceCategoryAdapterDeploymentManifest(aaveEnabled);
assert.equal(
  parsedAave.adapters.find((entry) => entry.adapterId === HEALTH_ADAPTER_ID)
    ?.configuration.minHealthFactorScaled,
  DEFAULT_MIN_HEALTH_FACTOR_SCALED,
);

const venusConfig = {
  adapterId: VENUS_HEALTH_ADAPTER_ID,
  protocol: "venus",
  comptrollerAddress: addresses.venusComptroller,
  accountAddress: addresses.healthAccount,
  borrowMarketAddress: addresses.venusBorrowMarket,
  minLiquidityUsdScaled: "1000000000000000000",
};
assert.equal(venusHealthAdapterConfigSchema.parse(venusConfig).borrowMarketAddress, addresses.venusBorrowMarket);
assert.equal(
  venusHealthAdapterConfigSchema.safeParse(
    Object.fromEntries(
      Object.entries(venusConfig).filter(([key]) => key !== "borrowMarketAddress"),
    ),
  ).success,
  false,
);

const venusEnabled = {
  ...disabledManifest,
  adapters: disabledManifest.adapters.map((entry) =>
    entry.adapterId === VENUS_HEALTH_ADAPTER_ID
      ? {
          ...entry,
          enabled: true,
          configuration: {
            comptrollerAddress: venusConfig.comptrollerAddress,
            accountAddress: venusConfig.accountAddress,
            borrowMarketAddress: venusConfig.borrowMarketAddress,
            minLiquidityUsdScaled: venusConfig.minLiquidityUsdScaled,
          },
        }
      : entry,
  ),
};
assert.notEqual(
  marketplaceCategoryAdapterDeploymentSha256(disabledManifest),
  marketplaceCategoryAdapterDeploymentSha256(venusEnabled),
);
assert.deepEqual(
  parseVerifierCategoryAdapterDeploymentManifest(venusEnabled),
  parseMarketplaceCategoryAdapterDeploymentManifest(venusEnabled),
);
assert.equal(
  verifierCategoryAdapterDeploymentSha256(venusEnabled),
  marketplaceCategoryAdapterDeploymentSha256(venusEnabled),
);

console.log("category adapter/service policy conformance: passed");
