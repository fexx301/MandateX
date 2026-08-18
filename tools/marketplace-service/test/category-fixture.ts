import {
  MARKETPLACE_CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA,
  MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES,
} from "../src/category-policy.js";

export const CATEGORY_ACCOUNT =
  "0x4444444444444444444444444444444444444444" as const;
export const CATEGORY_COMPTROLLER =
  "0x5555555555555555555555555555555555555555" as const;
export const CATEGORY_BORROW_MARKET =
  "0x6666666666666666666666666666666666666666" as const;

export function categoryDeployment(options: {
  readonly minLiquidityUsdScaled?: string;
  readonly venusEnabled?: boolean;
} = {}) {
  const venusEnabled = options.venusEnabled ?? true;
  return {
    schema: MARKETPLACE_CATEGORY_ADAPTER_DEPLOYMENT_SCHEMA,
    chainId: 56 as const,
    adapters: [
      {
        adapterId: "venus-health-v1" as const,
        category: "health" as const,
        enabled: venusEnabled,
        evidenceSchema: "mandatex.category.venus-health-evidence.v1" as const,
        validationProfile:
          MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES.venusHealth,
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
        ...(venusEnabled
          ? {
              configuration: {
                comptrollerAddress: CATEGORY_COMPTROLLER,
                accountAddress: CATEGORY_ACCOUNT,
                borrowMarketAddress: CATEGORY_BORROW_MARKET,
                minLiquidityUsdScaled:
                  options.minLiquidityUsdScaled ?? "1000000000000000000000",
              },
            }
          : {}),
      },
      {
        adapterId: "pancakeswap-v3-grid-v1" as const,
        category: "grid" as const,
        enabled: false as const,
        evidenceSchema: "mandatex.category.grid-evidence.v1" as const,
        validationProfile: MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES.grid,
        protocol: "pancakeswap-v3" as const,
        metric: "pool slot0().tick versus the declared grid band" as const,
        reads: [
          {
            label: "slot0" as const,
            selector: "0x3850c7bd" as const,
            target: "pool" as const,
          },
        ],
      },
      {
        adapterId: "aave-v3-health-v1" as const,
        category: "health" as const,
        enabled: false as const,
        evidenceSchema: "mandatex.category.health-evidence.v1" as const,
        validationProfile:
          MARKETPLACE_CATEGORY_ADAPTER_VALIDATION_PROFILES.aaveHealth,
        protocol: "aave-v3" as const,
        metric:
          "getUserAccountData().healthFactor versus a declared floor" as const,
        reads: [
          {
            label: "getUserAccountData" as const,
            selector: "0xbf92857c" as const,
            target: "pool" as const,
          },
        ],
      },
      {
        adapterId: "erc4626-yield-v1" as const,
        category: "yield" as const,
        enabled: false as const,
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
      },
    ],
  };
}
