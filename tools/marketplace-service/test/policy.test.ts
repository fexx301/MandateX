import assert from "node:assert/strict";
import test from "node:test";

import { canonicalSha256 } from "@mandatex/marketplace-core";

import { MarketplaceServiceError } from "../src/errors.js";
import {
  MARKETPLACE_CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA,
  MARKETPLACE_CATEGORY_ADAPTER_IDS,
  MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES,
  marketplaceCategoryAdapterDeploymentSha256,
  marketplaceVerifierPolicyManifest,
  marketplaceVerifierPolicySha256,
  parseMarketplaceCategoryAdapterDeploymentManifest,
} from "../src/index.js";

const ADDRESS_A = "0x1111111111111111111111111111111111111111";
const ADDRESS_B = "0x2222222222222222222222222222222222222222";
const ADDRESS_C = "0x3333333333333333333333333333333333333333";
const ADDRESS_D = "0x4444444444444444444444444444444444444444";
const ADDRESS_E = "0x5555555555555555555555555555555555555555";
const ADDRESS_F = "0x6666666666666666666666666666666666666666";

function gridDeployment() {
  return {
    adapterId: "pancakeswap-v3-grid-v1" as const,
    category: "grid" as const,
    enabled: true as const,
    evidenceSchema: "mandatex.category.grid-evidence.v1" as const,
    validationProfile: MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES.grid,
    protocol: "pancakeswap-v3" as const,
    metric: "pool slot0().tick versus the declared grid band" as const,
    reads: [
      { label: "slot0" as const, selector: "0x3850c7bd" as const, target: "pool" as const },
    ],
    configuration: {
      poolAddress: ADDRESS_A,
      lowerTick: -120,
      upperTick: 120,
    },
  };
}

function yieldDeployment() {
  return {
    adapterId: "erc4626-yield-v1" as const,
    category: "yield" as const,
    enabled: true as const,
    evidenceSchema: "mandatex.category.yield-evidence.v1" as const,
    validationProfile: MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES.yield,
    protocol: "erc4626" as const,
    metric:
      "totalAssets/totalSupply share price versus a declared floor" as const,
    reads: [
      {
        label: "totalAssets" as const,
        selector: "0x01e1d114" as const,
        target: "vault" as const,
      },
      {
        label: "totalSupply" as const,
        selector: "0x18160ddd" as const,
        target: "vault" as const,
      },
    ],
    configuration: {
      vaultAddress: ADDRESS_B,
      minSharePriceScaled: "1000000000000000000",
    },
  };
}

function aaveHealthDeployment() {
  return {
    adapterId: "aave-v3-health-v1" as const,
    category: "health" as const,
    enabled: true as const,
    evidenceSchema: "mandatex.category.health-evidence.v1" as const,
    validationProfile: MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES.aaveHealth,
    protocol: "aave-v3" as const,
    metric: "getUserAccountData().healthFactor versus a declared floor" as const,
    reads: [
      {
        label: "getUserAccountData" as const,
        selector: "0xbf92857c" as const,
        target: "pool" as const,
      },
    ],
    configuration: {
      poolAddress: ADDRESS_C,
      accountAddress: ADDRESS_D,
      minHealthFactorScaled: "1100000000000000000",
    },
  };
}

function venusHealthDeployment() {
  return {
    adapterId: "venus-health-v1" as const,
    category: "health" as const,
    enabled: true as const,
    evidenceSchema: "mandatex.category.venus-health-evidence.v1" as const,
    validationProfile: MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES.venusHealth,
    protocol: "venus" as const,
    metric:
      "getAccountLiquidity() excess liquidity and shortfall plus monitored-market borrowBalanceStored() versus a declared floor" as const,
    reads: [
      {
        label: "getAccountLiquidity" as const,
        selector: "0x5ec88c79" as const,
        target: "comptroller" as const,
      },
      {
        label: "getAssetsIn" as const,
        selector: "0xabfceffc" as const,
        target: "comptroller" as const,
      },
      {
        label: "borrowBalanceStored" as const,
        selector: "0x95dd9193" as const,
        target: "borrowMarket" as const,
      },
    ],
    configuration: {
      comptrollerAddress: ADDRESS_E,
      accountAddress: ADDRESS_D,
      borrowMarketAddress: ADDRESS_F,
      minLiquidityUsdScaled: "1000000000000000000",
    },
  };
}

function disabledDeployment<T extends { configuration?: unknown; enabled?: boolean }>(
  entry: T,
): Omit<T, "configuration" | "enabled"> & { enabled: false } {
  const { configuration: _configuration, enabled: _enabled, ...metadata } = entry;
  return { ...metadata, enabled: false };
}

function deploymentManifest(adapters: unknown[]) {
  return {
    schema: MARKETPLACE_CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA,
    chainId: 56,
    adapters,
  };
}

function disabledManifest() {
  return deploymentManifest([
    disabledDeployment(venusHealthDeployment()),
    disabledDeployment(gridDeployment()),
    disabledDeployment(aaveHealthDeployment()),
    disabledDeployment(yieldDeployment()),
  ]);
}

test("the active verifier-policy manifest preserves the locked v1 digest", () => {
  const identity = {
    passivePolicyFingerprint: "aa".repeat(32),
    trustPolicySha256: "bb".repeat(32),
  };
  const manifest = marketplaceVerifierPolicyManifest(identity);
  assert.equal(
    marketplaceVerifierPolicySha256(identity),
    "d8cf9397aaef3d36c805791a96f0d5a4951f4338e1ceb09860db07a299d42195",
  );
  assert.equal(canonicalSha256(manifest), marketplaceVerifierPolicySha256(identity));
  assert.deepEqual(Object.keys(manifest), [
    "schema",
    "passivePolicyFingerprint",
    "trustPolicySha256",
    "profiles",
    "contracts",
    "quotePolicy",
    "previewPolicy",
    "transportPolicy",
    "chainDeployment",
  ]);
  assert.equal(Object.isFrozen(manifest), true);
  assert.throws(
    () =>
      marketplaceVerifierPolicySha256({
        ...identity,
        categoryAdapterDeploymentSha256: "00".repeat(32),
      } as never),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "ATTESTATION_SIGNER_INVALID",
  );
});

test("adapter deployment identity is canonical, explicit, and detached", () => {
  const input = deploymentManifest([
    disabledDeployment(yieldDeployment()),
    disabledDeployment(venusHealthDeployment()),
    aaveHealthDeployment(),
    gridDeployment(),
  ]);
  const parsed = parseMarketplaceCategoryAdapterDeploymentManifest(input);
  assert.equal(parsed.schema, "mandatex.marketplace.category-adapter-deployment.v2");
  assert.deepEqual(
    parsed.adapters.map((entry) => entry.adapterId),
    [...MARKETPLACE_CATEGORY_ADAPTER_IDS],
  );
  assert.deepEqual(
    parsed.adapters.map((entry) => entry.category),
    ["health", "yield", "grid", "health"],
  );
  const aave = parsed.adapters.find(
    (entry) => entry.adapterId === "aave-v3-health-v1",
  );
  assert.ok(aave?.enabled && aave.configuration !== undefined);
  assert.equal(
    aave.configuration.minHealthFactorScaled,
    "1100000000000000000",
  );
  assert.equal(Object.isFrozen(parsed), true);
  assert.equal(Object.isFrozen(parsed.adapters), true);
  assert.equal(Object.isFrozen(aave.configuration), true);

  const missingThreshold = deploymentManifest([
    disabledDeployment(yieldDeployment()),
    disabledDeployment(venusHealthDeployment()),
    {
      ...aaveHealthDeployment(),
      configuration: {
        poolAddress: ADDRESS_C,
        accountAddress: ADDRESS_D,
      },
    },
    gridDeployment(),
  ]);
  assert.throws(
    () => parseMarketplaceCategoryAdapterDeploymentManifest(missingThreshold),
  );

  (input.adapters[0] as any).enabled = true;
  const parsedYield = parsed.adapters.find(
    (entry) => entry.adapterId === "erc4626-yield-v1",
  );
  assert.equal(parsedYield?.enabled, false);
});

test("the closed manifest locks four exact evidence schema strings", () => {
  const parsed = parseMarketplaceCategoryAdapterDeploymentManifest(disabledManifest());
  assert.deepEqual(
    Object.fromEntries(
      parsed.adapters.map((entry) => [entry.adapterId, entry.evidenceSchema]),
    ),
    {
      "aave-v3-health-v1": "mandatex.category.health-evidence.v1",
      "erc4626-yield-v1": "mandatex.category.yield-evidence.v1",
      "pancakeswap-v3-grid-v1": "mandatex.category.grid-evidence.v1",
      "venus-health-v1": "mandatex.category.venus-health-evidence.v1",
    },
  );
});

test("every enabled deployment address and threshold is committed by the hash", () => {
  const aaveBase = deploymentManifest([
    gridDeployment(),
    yieldDeployment(),
    aaveHealthDeployment(),
    disabledDeployment(venusHealthDeployment()),
  ]);
  const aaveBaseline = marketplaceCategoryAdapterDeploymentSha256(aaveBase);
  const aaveVariants = [
    () => {
      const value = structuredClone(aaveBase) as any;
      value.adapters[0].configuration.poolAddress = ADDRESS_F;
      return value;
    },
    () => {
      const value = structuredClone(aaveBase) as any;
      value.adapters[0].configuration.lowerTick = -121;
      return value;
    },
    () => {
      const value = structuredClone(aaveBase) as any;
      value.adapters[1].configuration.vaultAddress = ADDRESS_E;
      return value;
    },
    () => {
      const value = structuredClone(aaveBase) as any;
      value.adapters[1].configuration.minSharePriceScaled = "1000000000000000001";
      return value;
    },
    () => {
      const value = structuredClone(aaveBase) as any;
      value.adapters[2].configuration.accountAddress = ADDRESS_A;
      return value;
    },
    () => {
      const value = structuredClone(aaveBase) as any;
      value.adapters[2].configuration.minHealthFactorScaled =
        "1200000000000000000";
      return value;
    },
  ];
  for (const variant of aaveVariants) {
    assert.notEqual(
      marketplaceCategoryAdapterDeploymentSha256(variant()),
      aaveBaseline,
    );
  }

  const venusBase = deploymentManifest([
    disabledDeployment(gridDeployment()),
    disabledDeployment(yieldDeployment()),
    disabledDeployment(aaveHealthDeployment()),
    venusHealthDeployment(),
  ]);
  const venusBaseline = marketplaceCategoryAdapterDeploymentSha256(venusBase);
  for (const mutate of [
    (configuration: any) => {
      configuration.comptrollerAddress = ADDRESS_A;
    },
    (configuration: any) => {
      configuration.accountAddress = ADDRESS_B;
    },
    (configuration: any) => {
      configuration.borrowMarketAddress = ADDRESS_C;
    },
    (configuration: any) => {
      configuration.minLiquidityUsdScaled = "1000000000000000001";
    },
  ]) {
    const value = structuredClone(venusBase) as any;
    mutate(value.adapters[3].configuration);
    assert.notEqual(
      marketplaceCategoryAdapterDeploymentSha256(value),
      venusBaseline,
    );
  }
});

test("adapter deployment parsing rejects incomplete policy but permits both health adapters", () => {
  const valid = deploymentManifest([
    gridDeployment(),
    yieldDeployment(),
    aaveHealthDeployment(),
    disabledDeployment(venusHealthDeployment()),
  ]);
  const invalid = [
    deploymentManifest([]),
    deploymentManifest([
      gridDeployment(),
      gridDeployment(),
      aaveHealthDeployment(),
      disabledDeployment(venusHealthDeployment()),
    ]),
    deploymentManifest([
      gridDeployment(),
      yieldDeployment(),
      aaveHealthDeployment(),
    ]),
    {
      schema: "mandatex.marketplace.category-deployment.v1",
      chainId: 56,
      categories: [],
    },
    {
      ...valid,
      adapters: [
        {
          ...gridDeployment(),
          configuration: {
            ...gridDeployment().configuration,
            poolAddress: ADDRESS_A.toUpperCase(),
          },
        },
        yieldDeployment(),
        aaveHealthDeployment(),
        disabledDeployment(venusHealthDeployment()),
      ],
    },
    {
      ...valid,
      adapters: [
        { ...gridDeployment(), enabled: false },
        yieldDeployment(),
        aaveHealthDeployment(),
        disabledDeployment(venusHealthDeployment()),
      ],
    },
    deploymentManifest([
      {
        ...gridDeployment(),
        configuration: { ...gridDeployment().configuration, lowerTick: -887_273 },
      },
      yieldDeployment(),
      aaveHealthDeployment(),
      disabledDeployment(venusHealthDeployment()),
    ]),
    deploymentManifest([
      gridDeployment(),
      {
        ...yieldDeployment(),
        configuration: {
          ...yieldDeployment().configuration,
          minSharePriceScaled: (1n << 256n).toString(10),
        },
      },
      aaveHealthDeployment(),
      disabledDeployment(venusHealthDeployment()),
    ]),
    deploymentManifest([
      disabledDeployment(gridDeployment()),
      disabledDeployment(yieldDeployment()),
      {
        ...disabledDeployment(aaveHealthDeployment()),
        configuration: undefined,
      },
      disabledDeployment(venusHealthDeployment()),
    ]),
    deploymentManifest([
      disabledDeployment(gridDeployment()),
      disabledDeployment(yieldDeployment()),
      disabledDeployment(aaveHealthDeployment()),
      {
        ...venusHealthDeployment(),
        configuration: {
          comptrollerAddress: ADDRESS_E,
          accountAddress: ADDRESS_D,
          minLiquidityUsdScaled: "1000000000000000000",
        },
      },
    ]),
    deploymentManifest([
      disabledDeployment(gridDeployment()),
      disabledDeployment(yieldDeployment()),
      disabledDeployment(aaveHealthDeployment()),
      {
        ...venusHealthDeployment(),
        configuration: {
          comptrollerAddress: ADDRESS_E,
          accountAddress: ADDRESS_D,
          borrowMarketAddress: ADDRESS_F,
        },
      },
    ]),
    { ...valid, extra: true },
  ];
  for (const value of invalid) {
    assert.throws(() => parseMarketplaceCategoryAdapterDeploymentManifest(value));
  }

  const staticOnly = deploymentManifest([
    { ...disabledDeployment(gridDeployment()), enabled: true },
    disabledDeployment(yieldDeployment()),
    disabledDeployment(aaveHealthDeployment()),
    disabledDeployment(venusHealthDeployment()),
  ]);
  const parsedStaticOnly = parseMarketplaceCategoryAdapterDeploymentManifest(
    staticOnly,
  );
  const staticGrid = parsedStaticOnly.adapters.find(
    (entry) => entry.adapterId === "pancakeswap-v3-grid-v1",
  );
  assert.equal(staticGrid?.enabled, true);
  assert.equal(
    staticGrid === undefined || Object.hasOwn(staticGrid, "configuration"),
    false,
  );

  const parsedDisabled = parseMarketplaceCategoryAdapterDeploymentManifest(
    disabledManifest(),
  );
  assert.equal(parsedDisabled.adapters.every((entry) => !entry.enabled), true);
  assert.equal(
    parsedDisabled.adapters.some((entry) => Object.hasOwn(entry, "configuration")),
    false,
  );

  const bothHealth = parseMarketplaceCategoryAdapterDeploymentManifest(
    deploymentManifest([
      disabledDeployment(gridDeployment()),
      disabledDeployment(yieldDeployment()),
      aaveHealthDeployment(),
      venusHealthDeployment(),
    ]),
  );
  assert.deepEqual(
    bothHealth.adapters.filter((entry) => entry.category === "health").map((entry) => entry.adapterId),
    ["aave-v3-health-v1", "venus-health-v1"],
  );
});
