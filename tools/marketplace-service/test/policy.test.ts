import assert from "node:assert/strict";
import test from "node:test";

import { canonicalSha256 } from "@mandatex/marketplace-core";

import { MarketplaceServiceError } from "../src/errors.js";
import {
  MARKETPLACE_CATEGORY_DEPLOYMENT_SCHEMA,
  marketplaceCategoryDeploymentSha256,
  marketplaceVerifierPolicyManifest,
  marketplaceVerifierPolicySha256,
  parseMarketplaceCategoryDeploymentManifest,
} from "../src/index.js";

const ADDRESS_A = "0x1111111111111111111111111111111111111111";
const ADDRESS_B = "0x2222222222222222222222222222222222222222";
const ADDRESS_C = "0x3333333333333333333333333333333333333333";
const ADDRESS_D = "0x4444444444444444444444444444444444444444";

function gridDeployment() {
  return {
    category: "grid" as const,
    enabled: true as const,
    adapterId: "pancakeswap-v3-grid-v1" as const,
    evidenceSchema: "mandatex.category.grid-evidence.v1" as const,
    validationProfile: "mandatex.marketplace.category-grid-validation.v1" as const,
    protocol: "pancakeswap-v3" as const,
    metric: "pool slot0().tick versus the declared grid band" as const,
    reads: [{ label: "slot0" as const, selector: "0x3850c7bd" as const }],
    configuration: {
      poolAddress: ADDRESS_A,
      lowerTick: -120,
      upperTick: 120,
    },
  };
}

function yieldDeployment() {
  return {
    category: "yield" as const,
    enabled: true as const,
    adapterId: "erc4626-yield-v1" as const,
    evidenceSchema: "mandatex.category.yield-evidence.v1" as const,
    validationProfile: "mandatex.marketplace.category-yield-validation.v1" as const,
    protocol: "erc4626" as const,
    metric:
      "totalAssets/totalSupply share price versus a declared floor" as const,
    reads: [
      { label: "totalAssets" as const, selector: "0x01e1d114" as const },
      { label: "totalSupply" as const, selector: "0x18160ddd" as const },
    ],
    configuration: {
      vaultAddress: ADDRESS_B,
      minSharePriceScaled: "1000000000000000000",
    },
  };
}

function healthDeployment(includeDefault = false) {
  return {
    category: "health" as const,
    enabled: true as const,
    adapterId: "aave-v3-health-v1" as const,
    evidenceSchema: "mandatex.category.health-evidence.v1" as const,
    validationProfile: "mandatex.marketplace.category-health-validation.v1" as const,
    protocol: "aave-v3" as const,
    metric: "getUserAccountData().healthFactor versus a declared floor" as const,
    reads: [
      {
        label: "getUserAccountData" as const,
        selector: "0xbf92857c" as const,
      },
    ],
    configuration: {
      poolAddress: ADDRESS_C,
      accountAddress: ADDRESS_D,
      ...(includeDefault
        ? { minHealthFactorScaled: "1100000000000000000" }
        : {}),
    },
  };
}

function deploymentManifest(categories: unknown[]) {
  return {
    schema: MARKETPLACE_CATEGORY_DEPLOYMENT_SCHEMA,
    chainId: 56,
    categories,
  };
}

function disabledDeployment<T extends { configuration?: unknown }>(
  entry: T,
): Omit<T, "configuration"> & { enabled: false } {
  const { configuration: _configuration, ...metadata } = entry;
  return { ...metadata, enabled: false };
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
  assert.equal(Object.isFrozen(manifest.contracts), true);
  assert.throws(
    () =>
      marketplaceVerifierPolicySha256({
        ...identity,
        categoryDeploymentSha256: "00".repeat(32),
      } as never),
    (error: unknown) =>
      error instanceof MarketplaceServiceError &&
      error.code === "ATTESTATION_SIGNER_INVALID",
  );
});

test("category deployment identity is canonical, explicit, and detached", () => {
  const input = deploymentManifest([
    yieldDeployment(),
    healthDeployment(),
    gridDeployment(),
  ]);
  const parsed = parseMarketplaceCategoryDeploymentManifest(input);
  assert.deepEqual(
    parsed.categories.map((entry) => entry.category),
    ["grid", "health", "yield"],
  );
  const health = parsed.categories.find((entry) => entry.category === "health");
  assert.ok(health?.category === "health" && health.configuration !== undefined);
  assert.equal(
    health.configuration.minHealthFactorScaled,
    "1100000000000000000",
  );
  assert.equal(Object.isFrozen(parsed), true);
  assert.equal(Object.isFrozen(parsed.categories), true);
  assert.equal(Object.isFrozen(parsed.categories[0]?.configuration), true);

  const explicitDefault = deploymentManifest([
    gridDeployment(),
    healthDeployment(true),
    yieldDeployment(),
  ]);
  assert.equal(
    marketplaceCategoryDeploymentSha256(input),
    marketplaceCategoryDeploymentSha256(explicitDefault),
  );

  (input.categories[0] as any).configuration.minSharePriceScaled = "2";
  const parsedYield = parsed.categories.find((entry) => entry.category === "yield");
  assert.ok(parsedYield?.category === "yield" && parsedYield.configuration !== undefined);
  assert.equal(
    parsedYield.configuration.minSharePriceScaled,
    "1000000000000000000",
  );
});

test("every deployment address and threshold is committed by the category hash", () => {
  const base = deploymentManifest([
    gridDeployment(),
    healthDeployment(true),
    yieldDeployment(),
  ]);
  const baseline = marketplaceCategoryDeploymentSha256(base);
  const variants = [
    () => {
      const value = structuredClone(base) as any;
      value.categories[0].configuration.poolAddress = ADDRESS_D;
      return value;
    },
    () => {
      const value = structuredClone(base) as any;
      value.categories[0].configuration.lowerTick = -121;
      return value;
    },
    () => {
      const value = structuredClone(base) as any;
      value.categories[1].configuration.accountAddress = ADDRESS_A;
      return value;
    },
    () => {
      const value = structuredClone(base) as any;
      value.categories[1].configuration.minHealthFactorScaled =
        "1200000000000000000";
      return value;
    },
    () => {
      const value = structuredClone(base) as any;
      value.categories[2].configuration.vaultAddress = ADDRESS_C;
      return value;
    },
    () => {
      const value = structuredClone(base) as any;
      value.categories[2].configuration.minSharePriceScaled =
        "1000000000000000001";
      return value;
    },
  ];
  for (const variant of variants) {
    assert.notEqual(marketplaceCategoryDeploymentSha256(variant()), baseline);
  }
});

test("category deployment parsing rejects unsafe or ambiguous policy data", () => {
  const valid = deploymentManifest([
    gridDeployment(),
    healthDeployment(true),
    yieldDeployment(),
  ]);
  const gridMissingConfiguration = disabledDeployment(gridDeployment()) as any;
  gridMissingConfiguration.enabled = true;
  const invalid = [
    deploymentManifest([]),
    deploymentManifest([gridDeployment(), gridDeployment(), yieldDeployment()]),
    deploymentManifest([gridDeployment(), healthDeployment(true)]),
    {
      ...valid,
      categories: [
        {
          ...gridDeployment(),
          adapterId: "aave-v3-health-v1",
        },
        healthDeployment(true),
        yieldDeployment(),
      ],
    },
    {
      ...valid,
      categories: [
        {
          ...gridDeployment(),
          configuration: {
            ...gridDeployment().configuration,
            poolAddress: ADDRESS_A.toUpperCase(),
          },
        },
        healthDeployment(true),
        yieldDeployment(),
      ],
    },
    {
      ...valid,
      categories: [
        { ...gridDeployment(), enabled: false },
        healthDeployment(true),
        yieldDeployment(),
      ],
    },
    {
      ...valid,
      categories: [
        {
          ...gridDeployment(),
          configuration: {
            ...gridDeployment().configuration,
            lowerTick: -887_273,
          },
        },
        healthDeployment(true),
        yieldDeployment(),
      ],
    },
    deploymentManifest([
      gridDeployment(),
      healthDeployment(true),
      {
        ...yieldDeployment(),
        configuration: {
          ...yieldDeployment().configuration,
          minSharePriceScaled: (1n << 256n).toString(10),
        },
      },
    ]),
    deploymentManifest([
      gridMissingConfiguration,
      healthDeployment(true),
      yieldDeployment(),
    ]),
    { ...valid, extra: true },
  ];
  for (const value of invalid) {
    assert.throws(() => parseMarketplaceCategoryDeploymentManifest(value));
  }

  const disabled = deploymentManifest([
    disabledDeployment(gridDeployment()),
    disabledDeployment(healthDeployment(true)),
    disabledDeployment(yieldDeployment()),
  ]);
  const parsedDisabled = parseMarketplaceCategoryDeploymentManifest(disabled);
  assert.equal(parsedDisabled.categories.every((entry) => !entry.enabled), true);
  assert.equal(
    parsedDisabled.categories.some((entry) => Object.hasOwn(entry, "configuration")),
    false,
  );
});
