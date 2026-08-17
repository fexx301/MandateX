import { UINT256_MAX, addressCalldata, decodeUint256, wordCount } from "./abi.js";
import { healthEvidenceSchema, type HealthEvidence } from "./evidence.js";
import {
  HEALTH_ADAPTER_ID,
  HEALTH_EVIDENCE_SCHEMA,
  SELECTOR_GET_USER_ACCOUNT_DATA,
  healthAdapterConfigSchema,
} from "./policy.js";
import type { PinnedBlockReader } from "./reader.js";
import { failResult, passResult, unknownResult, type AdapterResult } from "./result.js";

/**
 * `getUserAccountData(address)` returns six words. Health factor is the last.
 *
 * These indices are the whole adapter, so they are named rather than inlined —
 * an off-by-one here returns `ltv` as a health factor, which is a plausible
 * 1e4-scaled number that would sail under any floor expressed at 1e18 and report
 * every account as unhealthy. Naming them makes the mistake visible in review
 * instead of arithmetically invisible at runtime.
 */
const WORD_TOTAL_COLLATERAL_BASE = 0;
const WORD_TOTAL_DEBT_BASE = 1;
const WORD_HEALTH_FACTOR = 5;
const EXPECTED_WORDS = 6;

/**
 * Lending-health adapter — one read, one metric.
 *
 * The health factor is the canonical single number for a lending position, and
 * Aave reports it directly, so there is no derivation to get wrong. Below 1.0 the
 * position is liquidatable; the configured floor sits above that (default 1.1,
 * see `policy.ts`).
 *
 * The subtlety this adapter exists to handle correctly is the no-debt sentinel.
 * Aave returns `type(uint256).max` for the health factor of an account with no
 * borrows. Fed to a naive `healthFactor >= floor` comparison that is the largest
 * number representable, so it passes — and it passes *hardest*, reporting an
 * account with nothing at stake as the healthiest position in the market. A
 * mandate to keep a health factor above a floor is not satisfied by having no
 * debt; there is simply nothing to maintain. That is `unknown`, and it is checked
 * from two independent fields so that one of them changing does not silently
 * reopen the hole.
 */
export async function evaluateHealth(
  input: unknown,
  reader: PinnedBlockReader,
): Promise<AdapterResult<HealthEvidence>> {
  const config = healthAdapterConfigSchema.parse(input);

  const outcome = await reader.call({
    label: "getUserAccountData",
    to: config.poolAddress,
    data: addressCalldata(SELECTOR_GET_USER_ACCOUNT_DATA, config.accountAddress),
  });
  if (outcome === undefined) {
    return unknownResult(HEALTH_ADAPTER_ID, "health", "READ_UNAVAILABLE");
  }

  if (wordCount(outcome.data) !== EXPECTED_WORDS) {
    return unknownResult(HEALTH_ADAPTER_ID, "health", "READ_RETURNDATA_MALFORMED");
  }
  const totalCollateralBase = decodeUint256(outcome.data, WORD_TOTAL_COLLATERAL_BASE);
  const totalDebtBase = decodeUint256(outcome.data, WORD_TOTAL_DEBT_BASE);
  const healthFactorScaled = decodeUint256(outcome.data, WORD_HEALTH_FACTOR);
  if (
    totalCollateralBase === undefined ||
    totalDebtBase === undefined ||
    healthFactorScaled === undefined
  ) {
    return unknownResult(HEALTH_ADAPTER_ID, "health", "READ_RETURNDATA_MALFORMED");
  }

  // Either witness is sufficient. `||` rather than `&&` is the fail-closed
  // direction: if the two fields ever disagree, the adapter declines to call the
  // position healthy rather than requiring both to agree before it will.
  if (healthFactorScaled === UINT256_MAX || totalDebtBase === 0n) {
    return unknownResult(HEALTH_ADAPTER_ID, "health", "HEALTH_NO_DEBT_POSITION");
  }

  const evidence = healthEvidenceSchema.parse({
    schema: HEALTH_EVIDENCE_SCHEMA,
    category: "health",
    protocol: config.protocol,
    adapterId: HEALTH_ADAPTER_ID,
    observedAt: reader.anchor.timestamp,
    observedBlock: reader.anchor.number,
    observedBlockHash: reader.anchor.hash,
    subject: {
      poolAddress: config.poolAddress,
      accountAddress: config.accountAddress,
    },
    policy: { minHealthFactorScaled: config.minHealthFactorScaled },
    metric: {
      healthFactorScaled: healthFactorScaled.toString(10),
      totalDebtBase: totalDebtBase.toString(10),
      totalCollateralBase: totalCollateralBase.toString(10),
    },
    reads: [outcome.observation],
  } satisfies HealthEvidence);

  return healthFactorScaled >= BigInt(config.minHealthFactorScaled)
    ? passResult(HEALTH_ADAPTER_ID, "health", evidence)
    : failResult(HEALTH_ADAPTER_ID, "health", "HEALTH_FACTOR_BELOW_FLOOR");
}
