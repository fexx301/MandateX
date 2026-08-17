import { z } from "zod";

import { compareCanonicalStrings } from "./primitives.js";

export const exclusionCodeSchema = z.enum([
  "AGENT_FEE_BUDGET_EXCEEDED",
  "AGENT_UNREACHABLE",
  "CATEGORY_EVIDENCE_PRECEDES_MANDATE",
  "CATEGORY_EVIDENCE_STALE",
  "CATEGORY_UNVERIFIED",
  "EVIDENCE_BLOCK_MISMATCH",
  "ESTIMATE_PRECEDES_MANDATE",
  "ESTIMATE_STALE",
  "EXECUTION_PREVIEW_FAILED",
  "EXPOSURE_BUDGET_EXCEEDED",
  "GAS_BUDGET_EXCEEDED",
  "IDENTITY_UNAVAILABLE",
  "MANDATE_CATEGORY_MISMATCH",
  "MANDATE_EXPIRED",
  "MANDATE_ID_MISMATCH",
  "PERMISSION_CALL_NOT_ALLOWED",
  "PERMISSION_CONTRACT_NOT_ALLOWED",
  "PERMISSION_EXPIRED",
  "PERMISSION_OUTLIVES_MANDATE",
  "PERMISSION_SPEND_CAP_EXCEEDED",
  "POSITION_MISMATCH",
  "PREVIEW_BLOCK_MISMATCH",
  "PREVIEW_PRECEDES_MANDATE",
  "PREVIEW_STALE",
  "PROTOCOL_NOT_ALLOWED",
  "PUBLISHER_UNKNOWN",
  "QUOTE_EXPIRED",
  "QUOTE_INCOMPLETE",
  "QUOTE_OUTLIVES_MANDATE",
  "QUOTE_PRECEDES_MANDATE",
  "QUOTE_STALE",
  "RANGE_OUTSIDE_POLICY",
  "REBALANCE_TRIGGER_NOT_FIRED",
  "REPUTATION_PRECEDES_MANDATE",
  "REPUTATION_STALE",
  "SLIPPAGE_BUDGET_EXCEEDED",
  "TARGET_WIDTH_MISMATCH",
  "TARGET_WIDTH_NOT_TICK_ALIGNED",
  "TASK_INTERFACE_UNSUPPORTED",
  "TICK_ALIGNMENT_INVALID",
  "TRIGGER_EVIDENCE_INVALID",
  "TRIGGER_POLICY_MISMATCH",
]);
export type ExclusionCode = z.infer<typeof exclusionCodeSchema>;

export const inconclusiveCodeSchema = z.enum([
  "CAPTURE_TIMESTAMP_IN_FUTURE",
  "CATEGORY_CHECK_INCONCLUSIVE",
  "CATEGORY_EVIDENCE_TIMESTAMP_IN_FUTURE",
  "ENDPOINT_CHECK_INCONCLUSIVE",
  "ESTIMATE_TIMESTAMP_IN_FUTURE",
  "EXECUTION_PREVIEW_INCONCLUSIVE",
  "IDENTITY_CHECK_INCONCLUSIVE",
  "PRICING_USD_UNAVAILABLE",
  "PUBLISHER_CHECK_INCONCLUSIVE",
  "PREVIEW_TIMESTAMP_IN_FUTURE",
  "QUOTE_COMPLETENESS_INCONCLUSIVE",
  "QUOTE_TIMESTAMP_IN_FUTURE",
  "REPUTATION_TIMESTAMP_IN_FUTURE",
  "TASK_INTERFACE_CHECK_INCONCLUSIVE",
]);
export type InconclusiveCode = z.infer<typeof inconclusiveCodeSchema>;

export const unsupportedCodeSchema = z.enum([
  "CATEGORY_GRID_UNSUPPORTED",
  "CATEGORY_HEALTH_UNSUPPORTED",
  "CATEGORY_YIELD_UNSUPPORTED",
]);
export type UnsupportedCode = z.infer<typeof unsupportedCodeSchema>;

export const findingSchema = z.discriminatedUnion("kind", [
  z
    .object({
      kind: z.literal("exclusion"),
      code: exclusionCodeSchema,
      message: z.string().min(1).max(256),
    })
    .strict(),
  z
    .object({
      kind: z.literal("inconclusive"),
      code: inconclusiveCodeSchema,
      message: z.string().min(1).max(256),
    })
    .strict(),
  z
    .object({
      kind: z.literal("unsupported"),
      code: unsupportedCodeSchema,
      message: z.string().min(1).max(256),
    })
    .strict(),
]);
export type Finding = z.infer<typeof findingSchema>;

const messages: Readonly<Record<ExclusionCode | InconclusiveCode | UnsupportedCode, string>> =
  Object.freeze({
    AGENT_FEE_BUDGET_EXCEEDED: "The normalized agent fee exceeds the mandate budget.",
    AGENT_UNREACHABLE: "The required agent endpoint was not reachable.",
    CATEGORY_EVIDENCE_PRECEDES_MANDATE: "Category evidence predates the mandate.",
    CATEGORY_EVIDENCE_STALE: "Category evidence is older than the mandate permits.",
    CATEGORY_UNVERIFIED: "The agent category capability was not verified.",
    EVIDENCE_BLOCK_MISMATCH: "The rebalancing evidence does not match the quote block.",
    ESTIMATE_PRECEDES_MANDATE: "Cost and exposure estimates predate the mandate.",
    ESTIMATE_STALE: "The cost and exposure estimates are older than the mandate permits.",
    EXECUTION_PREVIEW_FAILED: "The read-only execution preview failed.",
    EXPOSURE_BUDGET_EXCEEDED: "The estimated exposure exceeds the mandate budget.",
    GAS_BUDGET_EXCEEDED: "The estimated gas cost exceeds the mandate budget.",
    IDENTITY_UNAVAILABLE: "A verified BSC agent identity was not available.",
    MANDATE_CATEGORY_MISMATCH: "The quote category does not match the mandate.",
    MANDATE_EXPIRED: "The mandate has expired.",
    MANDATE_ID_MISMATCH: "The quote was not issued for this mandate.",
    PERMISSION_CALL_NOT_ALLOWED: "The quote requests a call outside the mandate allowlist.",
    PERMISSION_CONTRACT_NOT_ALLOWED: "The quote requests a contract outside the mandate allowlist.",
    PERMISSION_EXPIRED: "The requested permission has expired.",
    PERMISSION_OUTLIVES_MANDATE: "The requested permission outlives the mandate policy.",
    PERMISSION_SPEND_CAP_EXCEEDED: "The requested spend cap exceeds the mandate.",
    POSITION_MISMATCH: "The quote targets a different liquidity position.",
    PREVIEW_BLOCK_MISMATCH: "The execution preview does not match the quote block.",
    PREVIEW_PRECEDES_MANDATE: "The execution preview predates the mandate.",
    PREVIEW_STALE: "The execution preview is older than the mandate permits.",
    PROTOCOL_NOT_ALLOWED: "The proposed protocol is not allowed by the mandate.",
    PUBLISHER_UNKNOWN: "The agent publisher could not be verified.",
    QUOTE_EXPIRED: "The quote has expired.",
    QUOTE_INCOMPLETE: "The trusted quote validator marked the quote incomplete.",
    QUOTE_OUTLIVES_MANDATE: "The quote expiry outlives the mandate.",
    QUOTE_PRECEDES_MANDATE: "The quote observation predates the mandate.",
    QUOTE_STALE: "The quote observation is older than the mandate permits.",
    RANGE_OUTSIDE_POLICY: "The proposed range falls outside the approved range.",
    REBALANCE_TRIGGER_NOT_FIRED: "The mandate's rebalance trigger has not fired.",
    REPUTATION_PRECEDES_MANDATE: "Reputation evidence predates the mandate.",
    REPUTATION_STALE: "Reputation evidence is older than the mandate permits.",
    SLIPPAGE_BUDGET_EXCEEDED: "The estimated slippage exceeds the mandate budget.",
    TARGET_WIDTH_MISMATCH: "The proposed range width does not match the mandate.",
    TARGET_WIDTH_NOT_TICK_ALIGNED: "The mandate target width is not divisible by tick spacing.",
    TASK_INTERFACE_UNSUPPORTED: "The agent cannot accept a supported task interface.",
    TICK_ALIGNMENT_INVALID: "A proposed range endpoint is not aligned to tick spacing.",
    TRIGGER_EVIDENCE_INVALID: "The trigger reason or boundary distance contradicts the observed range.",
    TRIGGER_POLICY_MISMATCH: "The fired trigger does not satisfy the mandate trigger mode.",
    CAPTURE_TIMESTAMP_IN_FUTURE: "The in-process capture time is beyond the permitted clock skew.",
    CATEGORY_CHECK_INCONCLUSIVE: "Category capability verification was inconclusive.",
    CATEGORY_EVIDENCE_TIMESTAMP_IN_FUTURE: "Category evidence time is beyond the permitted clock skew.",
    ENDPOINT_CHECK_INCONCLUSIVE: "Endpoint health verification was inconclusive.",
    ESTIMATE_TIMESTAMP_IN_FUTURE: "Estimate time is beyond the permitted clock skew.",
    EXECUTION_PREVIEW_INCONCLUSIVE: "No conclusive read-only execution preview is available.",
    IDENTITY_CHECK_INCONCLUSIVE: "BSC identity verification was inconclusive.",
    PRICING_USD_UNAVAILABLE: "A nonzero token-atomic fee cannot be compared without a trusted USD price.",
    PUBLISHER_CHECK_INCONCLUSIVE: "Publisher verification was inconclusive.",
    PREVIEW_TIMESTAMP_IN_FUTURE: "Preview time is beyond the permitted clock skew.",
    QUOTE_COMPLETENESS_INCONCLUSIVE: "Quote completeness verification was inconclusive.",
    QUOTE_TIMESTAMP_IN_FUTURE: "The quote timestamp is beyond the permitted clock skew.",
    REPUTATION_TIMESTAMP_IN_FUTURE: "Reputation evidence time is beyond the permitted clock skew.",
    TASK_INTERFACE_CHECK_INCONCLUSIVE: "Task-interface verification was inconclusive.",
    CATEGORY_GRID_UNSUPPORTED: "Grid strategy normalization is not implemented in Marketplace Core v1.",
    CATEGORY_HEALTH_UNSUPPORTED: "Health-factor strategy normalization is not implemented in Marketplace Core v1.",
    CATEGORY_YIELD_UNSUPPORTED: "Yield strategy normalization is not implemented in Marketplace Core v1.",
  });

export function exclusionFinding(code: ExclusionCode): Finding {
  return { kind: "exclusion", code, message: messages[code] };
}

export function inconclusiveFinding(code: InconclusiveCode): Finding {
  return { kind: "inconclusive", code, message: messages[code] };
}

export function unsupportedFinding(code: UnsupportedCode): Finding {
  return { kind: "unsupported", code, message: messages[code] };
}

export function sortFindings(findings: readonly Finding[]): Finding[] {
  const unique = new Map<string, Finding>();
  for (const finding of findings) unique.set(`${finding.kind}:${finding.code}`, finding);
  return [...unique.values()].sort((left, right) =>
    compareCanonicalStrings(
      `${left.kind}:${left.code}`,
      `${right.kind}:${right.code}`,
    ),
  );
}
