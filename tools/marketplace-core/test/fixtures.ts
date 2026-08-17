import {
  createMarketplaceCore,
  type CapturedDisplaySafeQuoteProjection,
  type DisplaySafeQuoteProjectionPayload,
  type MarketplaceCore,
  type TrustedProjectionIngress,
} from "../src/index.js";

export const ADDRESSES = Object.freeze({
  owner: "0x1111111111111111111111111111111111111111",
  publisher: "0x2222222222222222222222222222222222222222",
  pool: "0x3333333333333333333333333333333333333333",
  manager: "0x4444444444444444444444444444444444444444",
  usdt: "0x5555555555555555555555555555555555555555",
  extra: "0x6666666666666666666666666666666666666666",
});

export const BLOCK_HASH = `0x${"ab".repeat(32)}`;
export const QUOTE_COMMITMENT = "11".repeat(32);
export const PREVIEW_COMMITMENT = "22".repeat(32);

export interface QuoteOptions {
  readonly quoteId?: string;
  readonly tokenId?: string;
  readonly amountAtomic?: string;
  readonly category?: "rebalancing" | "grid" | "yield" | "health";
  readonly gasUsdMicros?: string;
  readonly slippageBps?: number;
  readonly exposureUsdMicros?: string;
  readonly reputationScoreBps?: number;
  readonly sampleSize?: number;
  readonly evidenceConfidenceBps?: number;
  readonly triggerFired?: boolean;
  readonly endpoint?: "pass" | "fail" | "unknown";
  readonly preview?: "passed" | "failed" | "unavailable";
  readonly proposedLowerTick?: number;
  readonly proposedUpperTick?: number;
  readonly permissionsContracts?: readonly string[];
  readonly permissionsCalls?: readonly string[];
  readonly permissionSpendCapUsdMicros?: string;
  readonly permissionExpiresAt?: number;
  readonly mandateId?: string;
  readonly observedAt?: number;
  readonly estimatesObservedAt?: number;
  readonly previewObservedAt?: number;
  readonly reputationObservedAt?: number;
  readonly categoryEvidenceObservedAt?: number;
  readonly currentTick?: number;
  readonly tickSpacing?: number;
  readonly currentLowerTick?: number;
  readonly currentUpperTick?: number;
  readonly expiresAt?: number;
  readonly triggerDistanceToBoundaryTicks?: number;
  readonly capturedAt?: number;
}

export interface TestMarketplaceCore {
  readonly core: MarketplaceCore;
  readonly ingress: TrustedProjectionIngress;
  readonly setClock: (unixSeconds: number) => void;
}

export function createTestMarketplaceCore(
  capturedAt = 1_120,
): TestMarketplaceCore {
  let clock = capturedAt;
  let installedIngress: TrustedProjectionIngress | undefined;
  const core = createMarketplaceCore({
    installTrustedProjectionIngress(ingress) {
      installedIngress = ingress;
    },
    clock: () => clock,
  });
  if (installedIngress === undefined) {
    throw new Error("Marketplace Core did not install its trusted ingress");
  }
  return {
    core,
    ingress: installedIngress,
    setClock(unixSeconds: number) {
      clock = unixSeconds;
    },
  };
}

export const testMarketplace = createTestMarketplaceCore();

export function rawProjection(options: QuoteOptions = {}): Record<string, unknown> {
  const category = options.category ?? "rebalancing";
  const observedAt = options.observedAt ?? 1_100;
  const rebalancing = {
    category: "rebalancing" as const,
    protocol: "pancakeswap-v3" as const,
    position: {
      poolAddress: ADDRESSES.pool,
      positionManagerAddress: ADDRESSES.manager,
      tokenId: "7",
    },
    observedAt: options.categoryEvidenceObservedAt ?? observedAt,
    observedBlock: 123,
    observedBlockHash: BLOCK_HASH,
    currentTick: options.currentTick ?? 19,
    tickSpacing: options.tickSpacing ?? 10,
    currentLowerTick: options.currentLowerTick ?? -20,
    currentUpperTick: options.currentUpperTick ?? 20,
    proposedLowerTick: options.proposedLowerTick ?? -30,
    proposedUpperTick: options.proposedUpperTick ?? 70,
    trigger: {
      fired: options.triggerFired ?? true,
      reason: "near_range_boundary" as const,
      distanceToBoundaryTicks: options.triggerDistanceToBoundaryTicks ?? 1,
    },
  };

  return {
    sourceCommitments: {
      quoteValidationSha256: QUOTE_COMMITMENT,
      previewValidationSha256: PREVIEW_COMMITMENT,
    },
    quoteId: options.quoteId ?? "quote-a",
    mandateId: options.mandateId ?? "mandate-demo",
    category,
    candidate: {
      chainId: 56,
      tokenId: options.tokenId ?? "7",
      owner: ADDRESSES.owner,
      publisher: ADDRESSES.publisher,
      taskInterface: "erc8183",
    },
    observedAt,
    observedBlock: 123,
    observedBlockHash: BLOCK_HASH,
    expiresAt: options.expiresAt ?? 1_500,
    proposedAction: "Rebalance the bounded PancakeSwap V3 position.",
    price: {
      amountAtomic: options.amountAtomic ?? "0",
      currency: ADDRESSES.usdt,
    },
    estimates: {
      gasUsdMicros: options.gasUsdMicros ?? "10",
      slippageBps: options.slippageBps ?? 5,
      exposureUsdMicros: options.exposureUsdMicros ?? "100",
      observedAt: options.estimatesObservedAt ?? observedAt,
    },
    permissions: {
      contracts: options.permissionsContracts ?? [ADDRESSES.manager],
      calls: options.permissionsCalls ?? ["decreaseLiquidity(uint256)"],
      spendCapUsdMicros: options.permissionSpendCapUsdMicros ?? "100",
      expiresAt: options.permissionExpiresAt ?? 1_900,
    },
    verification: {
      identity: "pass",
      publisher: "pass",
      endpoint: options.endpoint ?? "pass",
      taskInterface: "pass",
      category: "pass",
      quoteCompleteness: "pass",
    },
    preview:
      options.preview === "failed"
        ? { status: "failed", errorCode: "EVM_SIMULATION_REVERTED" }
        : options.preview === "unavailable"
          ? { status: "unavailable" }
          : {
              status: "passed",
              observedAt: options.previewObservedAt ?? observedAt,
              observedBlock: 123,
              observedBlockHash: BLOCK_HASH,
            },
    reputation: {
      scoreBps: options.reputationScoreBps ?? 8_000,
      sampleSize: options.sampleSize ?? 20,
      evidenceConfidenceBps: options.evidenceConfidenceBps ?? 9_000,
      observedAt: options.reputationObservedAt ?? observedAt,
    },
    categoryEvidence:
      category === "rebalancing"
        ? rebalancing
        : {
            category,
            observedAt: options.categoryEvidenceObservedAt ?? observedAt,
          },
  };
}

export function capturedQuote(
  options: QuoteOptions = {},
  ingress: TrustedProjectionIngress = testMarketplace.ingress,
): CapturedDisplaySafeQuoteProjection {
  if (ingress === testMarketplace.ingress) {
    testMarketplace.setClock(options.capturedAt ?? 1_120);
  }
  return ingress.capture(
    rawProjection(options) as unknown as DisplaySafeQuoteProjectionPayload,
  );
}

export function rawMandate(): Record<string, unknown> {
  return {
    schema: "mandatex.marketplace.mandate.v1",
    mandateId: "mandate-demo",
    category: "rebalancing",
    chainId: 56,
    createdAt: 1_000,
    expiresAt: 2_000,
    maxClockSkewSeconds: 30,
    maxEvidenceAgeSeconds: 300,
    maxPreviewAgeSeconds: 300,
    budgets: {
      maxAgentFeeUsdMicros: "0",
      maxGasUsdMicros: "50",
      maxSlippageBps: 50,
      maxExposureUsdMicros: "1_000_000".replaceAll("_", ""),
    },
    permissions: {
      allowedProtocols: ["pancakeswap-v3"],
      allowedContracts: [ADDRESSES.manager],
      allowedCalls: ["decreaseLiquidity(uint256)"],
      maxSpendUsdMicros: "1000000",
      expiresAt: 1_900,
    },
    rebalancing: {
      position: {
        protocol: "pancakeswap-v3",
        poolAddress: ADDRESSES.pool,
        positionManagerAddress: ADDRESSES.manager,
        tokenId: "7",
      },
      approvedLowerTick: -100,
      approvedUpperTick: 100,
      targetWidthTicks: 100,
      triggerMode: "boundary_proximity",
      triggerDistanceTicks: 10,
    },
  };
}
