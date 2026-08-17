import { canonicalJson, canonicalSha256 } from "./canonical.js";
import {
  validateMarketplaceAttestationTrust,
  verifyMarketplaceEvaluationAttestation,
  type MarketplaceAttestationTrust,
  type MarketplaceEvaluationAttestationWire,
} from "./attestation.js";
import {
  createProjectionCapability,
  readCoreClock,
  type CapturedDisplaySafeQuoteProjection,
  type ProjectionCapability,
  type TrustedProjectionIngress,
} from "./capture.js";
import {
  exclusionFinding,
  inconclusiveFinding,
  sortFindings,
  unsupportedFinding,
  type Finding,
} from "./codes.js";
import { MarketplaceCoreError, type MarketplaceErrorCode } from "./errors.js";
import { deepFreeze } from "./immutable.js";
import {
  normalizeCapturedQuote,
  normalizeDisplaySafeQuoteProjection,
} from "./normalize.js";
import {
  MAX_CANDIDATES,
  candidateId,
  compareCandidateKeys,
  compareCanonicalStrings,
  type GateObservation,
} from "./primitives.js";
import { scoreEligibleQuote } from "./ranking.js";
import {
  marketplaceEligibilityDecisionSchema,
  displaySafeQuoteProjectionSchema,
  marketplaceMandateSchema,
  marketplaceQuoteSchema,
  marketplaceReceiptSchema,
  type MarketplaceEligibilityDecision,
  type MarketplaceEvaluationConsistency,
  type MarketplaceEvaluationResult,
  type MarketplaceMandate,
  type MarketplaceQuote,
  type MarketplaceReceipt,
  type DisplaySafeQuoteProjection,
} from "./schemas.js";

type CandidateSetErrorCode =
  | "CANDIDATE_LIMIT_EXCEEDED"
  | "DUPLICATE_CANDIDATE"
  | "DUPLICATE_QUOTE_ID";

export class CandidateSetError extends MarketplaceCoreError {
  constructor(
    code: CandidateSetErrorCode,
    message: string,
  ) {
    super(code, message);
    this.name = "CandidateSetError";
  }
}

export interface EvaluateMarketplaceInput {
  readonly mandate: unknown;
  readonly candidates: readonly CapturedDisplaySafeQuoteProjection[];
}

export interface MarketplaceCoreOptions {
  readonly installTrustedProjectionIngress: (
    ingress: TrustedProjectionIngress,
  ) => undefined;
  readonly clock: () => number;
}

export interface MarketplaceCore {
  readonly evaluateMarketplace: (
    input: EvaluateMarketplaceInput,
  ) => MarketplaceEvaluationResult;
}

export interface EvaluateMarketplaceV2Input {
  readonly mandate: unknown;
  readonly attestations: readonly MarketplaceEvaluationAttestationWire[];
}

export interface MarketplaceCoreV2Options {
  readonly attestationTrust: MarketplaceAttestationTrust;
  readonly maxClockSkewSeconds: number;
  readonly clock: () => number;
}

export interface MarketplaceCoreV2 {
  readonly evaluateMarketplaceV2: (
    input: EvaluateMarketplaceV2Input,
  ) => MarketplaceEvaluationResult;
}

function compareQuotes(left: MarketplaceQuote, right: MarketplaceQuote): number {
  const byCandidate = compareCandidateKeys(left.candidate, right.candidate);
  return byCandidate !== 0
    ? byCandidate
    : compareCanonicalStrings(left.quoteId, right.quoteId);
}

interface CandidateReference {
  readonly quoteId: string;
  readonly candidate: {
    readonly chainId: number;
    readonly tokenId: string;
  };
}

interface CandidateSetIssue {
  readonly code: CandidateSetErrorCode;
  readonly message: string;
}

function inspectCandidateSet(
  candidates: readonly CandidateReference[],
): CandidateSetIssue | undefined {
  if (candidates.length > MAX_CANDIDATES) {
    return {
      code: "CANDIDATE_LIMIT_EXCEEDED",
      message: `Marketplace Core accepts at most ${MAX_CANDIDATES} candidates`,
    };
  }
  const identities = new Set<string>();
  const quoteIds = new Set<string>();
  for (const candidate of candidates) {
    const identity = candidateId(
      candidate.candidate.chainId,
      candidate.candidate.tokenId,
    );
    if (identities.has(identity)) {
      return {
        code: "DUPLICATE_CANDIDATE",
        message: `candidate ${identity} appears more than once`,
      };
    }
    if (quoteIds.has(candidate.quoteId)) {
      return {
        code: "DUPLICATE_QUOTE_ID",
        message: `quote ${candidate.quoteId} appears more than once`,
      };
    }
    identities.add(identity);
    quoteIds.add(candidate.quoteId);
  }
  return undefined;
}

function validateCapturedCandidateSet(
  candidates: readonly CapturedDisplaySafeQuoteProjection[],
  capability: ProjectionCapability,
): void {
  for (const candidate of candidates) capability.assertCaptured(candidate);
  const issue = inspectCandidateSet(candidates);
  if (issue !== undefined) throw new CandidateSetError(issue.code, issue.message);
}

function validateAttestedCandidateSet(
  candidates: readonly CandidateReference[],
): void {
  const issue = inspectCandidateSet(candidates);
  if (issue !== undefined) throw new CandidateSetError(issue.code, issue.message);
}

function validateEvaluationTime(
  mandate: MarketplaceMandate,
  evaluatedAt: number,
): void {
  if (!Number.isSafeInteger(evaluatedAt) || evaluatedAt <= 0) {
    throw new MarketplaceCoreError(
      "EVALUATED_AT_INVALID",
      "evaluatedAt must be positive Unix seconds",
    );
  }
  if (evaluatedAt < mandate.createdAt) {
    throw new MarketplaceCoreError(
      "EVALUATED_AT_BEFORE_MANDATE",
      "evaluatedAt must not precede mandate creation",
    );
  }
}

function gateFinding(
  state: GateObservation,
  failedCode:
    | "IDENTITY_UNAVAILABLE"
    | "PUBLISHER_UNKNOWN"
    | "AGENT_UNREACHABLE"
    | "TASK_INTERFACE_UNSUPPORTED"
    | "CATEGORY_UNVERIFIED"
    | "QUOTE_INCOMPLETE",
  unknownCode:
    | "IDENTITY_CHECK_INCONCLUSIVE"
    | "PUBLISHER_CHECK_INCONCLUSIVE"
    | "ENDPOINT_CHECK_INCONCLUSIVE"
    | "TASK_INTERFACE_CHECK_INCONCLUSIVE"
    | "CATEGORY_CHECK_INCONCLUSIVE"
    | "QUOTE_COMPLETENESS_INCONCLUSIVE",
): Finding | undefined {
  if (state === "fail") return exclusionFinding(failedCode);
  if (state === "unknown") return inconclusiveFinding(unknownCode);
  return undefined;
}

function addIf(
  findings: Finding[],
  condition: boolean,
  finding: Finding,
): void {
  if (condition) findings.push(finding);
}

function addTimestampFindings(
  findings: Finding[],
  mandate: MarketplaceMandate,
  evaluatedAt: number,
  observedAt: number,
  maxAgeSeconds: number,
  codes: {
    readonly precedesMandate:
      | "QUOTE_PRECEDES_MANDATE"
      | "ESTIMATE_PRECEDES_MANDATE"
      | "PREVIEW_PRECEDES_MANDATE"
      | "CATEGORY_EVIDENCE_PRECEDES_MANDATE"
      | "REPUTATION_PRECEDES_MANDATE";
    readonly stale:
      | "QUOTE_STALE"
      | "ESTIMATE_STALE"
      | "PREVIEW_STALE"
      | "CATEGORY_EVIDENCE_STALE"
      | "REPUTATION_STALE";
    readonly future:
      | "QUOTE_TIMESTAMP_IN_FUTURE"
      | "ESTIMATE_TIMESTAMP_IN_FUTURE"
      | "PREVIEW_TIMESTAMP_IN_FUTURE"
      | "CATEGORY_EVIDENCE_TIMESTAMP_IN_FUTURE"
      | "REPUTATION_TIMESTAMP_IN_FUTURE";
  },
): void {
  addIf(
    findings,
    observedAt < mandate.createdAt,
    exclusionFinding(codes.precedesMandate),
  );
  addIf(
    findings,
    observedAt > evaluatedAt + mandate.maxClockSkewSeconds,
    inconclusiveFinding(codes.future),
  );
  addIf(
    findings,
    evaluatedAt - observedAt > maxAgeSeconds,
    exclusionFinding(codes.stale),
  );
}

function rebalancingFindings(
  mandate: MarketplaceMandate,
  quote: MarketplaceQuote,
  evaluatedAt: number,
): Finding[] {
  const findings: Finding[] = [];
  const verificationGates: ReadonlyArray<
    [GateObservation, Parameters<typeof gateFinding>[1], Parameters<typeof gateFinding>[2]]
  > = [
    [quote.verification.identity, "IDENTITY_UNAVAILABLE", "IDENTITY_CHECK_INCONCLUSIVE"],
    [quote.verification.publisher, "PUBLISHER_UNKNOWN", "PUBLISHER_CHECK_INCONCLUSIVE"],
    [quote.verification.endpoint, "AGENT_UNREACHABLE", "ENDPOINT_CHECK_INCONCLUSIVE"],
    [
      quote.verification.taskInterface,
      "TASK_INTERFACE_UNSUPPORTED",
      "TASK_INTERFACE_CHECK_INCONCLUSIVE",
    ],
    [quote.verification.category, "CATEGORY_UNVERIFIED", "CATEGORY_CHECK_INCONCLUSIVE"],
    [
      quote.verification.quoteCompleteness,
      "QUOTE_INCOMPLETE",
      "QUOTE_COMPLETENESS_INCONCLUSIVE",
    ],
  ];
  for (const [state, failedCode, unknownCode] of verificationGates) {
    const finding = gateFinding(state, failedCode, unknownCode);
    if (finding !== undefined) findings.push(finding);
  }

  addIf(
    findings,
    mandate.category !== "rebalancing",
    exclusionFinding("MANDATE_CATEGORY_MISMATCH"),
  );

  addIf(
    findings,
    quote.mandateId !== mandate.mandateId,
    exclusionFinding("MANDATE_ID_MISMATCH"),
  );
  addIf(
    findings,
    quote.category !== mandate.category,
    exclusionFinding("MANDATE_CATEGORY_MISMATCH"),
  );
  addIf(
    findings,
    evaluatedAt >= mandate.expiresAt,
    exclusionFinding("MANDATE_EXPIRED"),
  );
  addTimestampFindings(
    findings,
    mandate,
    evaluatedAt,
    quote.observedAt,
    mandate.maxEvidenceAgeSeconds,
    {
      precedesMandate: "QUOTE_PRECEDES_MANDATE",
      stale: "QUOTE_STALE",
      future: "QUOTE_TIMESTAMP_IN_FUTURE",
    },
  );
  addIf(
    findings,
    quote.capturedAt > evaluatedAt + mandate.maxClockSkewSeconds,
    inconclusiveFinding("CAPTURE_TIMESTAMP_IN_FUTURE"),
  );
  addIf(findings, quote.expiresAt <= evaluatedAt, exclusionFinding("QUOTE_EXPIRED"));
  addIf(
    findings,
    quote.expiresAt > mandate.expiresAt,
    exclusionFinding("QUOTE_OUTLIVES_MANDATE"),
  );
  addTimestampFindings(
    findings,
    mandate,
    evaluatedAt,
    quote.estimates.observedAt,
    mandate.maxEvidenceAgeSeconds,
    {
      precedesMandate: "ESTIMATE_PRECEDES_MANDATE",
      stale: "ESTIMATE_STALE",
      future: "ESTIMATE_TIMESTAMP_IN_FUTURE",
    },
  );
  addTimestampFindings(
    findings,
    mandate,
    evaluatedAt,
    quote.reputation.observedAt,
    mandate.maxEvidenceAgeSeconds,
    {
      precedesMandate: "REPUTATION_PRECEDES_MANDATE",
      stale: "REPUTATION_STALE",
      future: "REPUTATION_TIMESTAMP_IN_FUTURE",
    },
  );

  if (quote.normalization.status === "inconclusive") {
    findings.push(inconclusiveFinding(quote.normalization.code));
  }

  if (quote.preview.status === "failed") {
    findings.push(exclusionFinding("EXECUTION_PREVIEW_FAILED"));
  } else if (quote.preview.status === "unavailable") {
    findings.push(inconclusiveFinding("EXECUTION_PREVIEW_INCONCLUSIVE"));
  } else {
    addTimestampFindings(
      findings,
      mandate,
      evaluatedAt,
      quote.preview.observedAt,
      mandate.maxPreviewAgeSeconds,
      {
        precedesMandate: "PREVIEW_PRECEDES_MANDATE",
        stale: "PREVIEW_STALE",
        future: "PREVIEW_TIMESTAMP_IN_FUTURE",
      },
    );
    addIf(
      findings,
      quote.preview.observedBlock !== quote.observedBlock ||
        quote.preview.observedBlockHash !== quote.observedBlockHash,
      exclusionFinding("PREVIEW_BLOCK_MISMATCH"),
    );
  }

  if (quote.categoryEvidence.category !== "rebalancing") return sortFindings(findings);
  const evidence = quote.categoryEvidence;
  const policy = mandate.rebalancing;
  if (policy === undefined) return sortFindings(findings);
  addTimestampFindings(
    findings,
    mandate,
    evaluatedAt,
    evidence.observedAt,
    mandate.maxEvidenceAgeSeconds,
    {
      precedesMandate: "CATEGORY_EVIDENCE_PRECEDES_MANDATE",
      stale: "CATEGORY_EVIDENCE_STALE",
      future: "CATEGORY_EVIDENCE_TIMESTAMP_IN_FUTURE",
    },
  );
  addIf(
    findings,
    evidence.observedBlock !== quote.observedBlock ||
      evidence.observedBlockHash !== quote.observedBlockHash,
    exclusionFinding("EVIDENCE_BLOCK_MISMATCH"),
  );
  addIf(
    findings,
    evidence.position.poolAddress !== policy.position.poolAddress ||
      evidence.position.positionManagerAddress !==
        policy.position.positionManagerAddress ||
      evidence.position.tokenId !== policy.position.tokenId,
    exclusionFinding("POSITION_MISMATCH"),
  );
  addIf(
    findings,
    !mandate.permissions.allowedProtocols.includes(evidence.protocol),
    exclusionFinding("PROTOCOL_NOT_ALLOWED"),
  );
  addIf(
    findings,
    !evidence.trigger.fired,
    exclusionFinding("REBALANCE_TRIGGER_NOT_FIRED"),
  );
  const isOutside =
    evidence.currentTick < evidence.currentLowerTick ||
    evidence.currentTick >= evidence.currentUpperTick;
  const boundaryDistance = isOutside
    ? 0
    : Math.min(
        evidence.currentTick - evidence.currentLowerTick,
        evidence.currentUpperTick - evidence.currentTick,
      );
  const triggerEvidenceValid =
    evidence.trigger.distanceToBoundaryTicks === boundaryDistance &&
    evidence.trigger.reason ===
      (isOutside ? "outside_current_range" : "near_range_boundary");
  addIf(
    findings,
    !triggerEvidenceValid,
    exclusionFinding("TRIGGER_EVIDENCE_INVALID"),
  );
  addIf(
    findings,
    evidence.trigger.fired &&
      ((policy.triggerMode === "out_of_range" && !isOutside) ||
        (policy.triggerMode === "boundary_proximity" &&
          !isOutside &&
          boundaryDistance > policy.triggerDistanceTicks)),
    exclusionFinding("TRIGGER_POLICY_MISMATCH"),
  );
  const endpointsAligned = [
    evidence.currentLowerTick,
    evidence.currentUpperTick,
    evidence.proposedLowerTick,
    evidence.proposedUpperTick,
  ].every((tick) => tick % evidence.tickSpacing === 0);
  addIf(
    findings,
    !endpointsAligned,
    exclusionFinding("TICK_ALIGNMENT_INVALID"),
  );
  const targetWidthAligned =
    policy.targetWidthTicks % evidence.tickSpacing === 0;
  addIf(
    findings,
    !targetWidthAligned,
    exclusionFinding("TARGET_WIDTH_NOT_TICK_ALIGNED"),
  );
  let expectedLowerTick: number | undefined;
  let expectedUpperTick: number | undefined;
  if (targetWidthAligned) {
    expectedLowerTick =
      Math.floor(
        (2 * evidence.currentTick -
          policy.targetWidthTicks +
          evidence.tickSpacing) /
          (2 * evidence.tickSpacing),
      ) * evidence.tickSpacing;
    expectedUpperTick = expectedLowerTick + policy.targetWidthTicks;
  }
  addIf(
    findings,
    evidence.proposedLowerTick < policy.approvedLowerTick ||
      evidence.proposedUpperTick > policy.approvedUpperTick ||
      evidence.proposedLowerTick >= evidence.proposedUpperTick ||
      evidence.currentTick < evidence.proposedLowerTick ||
      evidence.currentTick >= evidence.proposedUpperTick,
    exclusionFinding("RANGE_OUTSIDE_POLICY"),
  );
  addIf(
    findings,
    targetWidthAligned &&
      (evidence.proposedUpperTick - evidence.proposedLowerTick !==
        policy.targetWidthTicks ||
        evidence.proposedLowerTick !== expectedLowerTick ||
        evidence.proposedUpperTick !== expectedUpperTick),
    exclusionFinding("TARGET_WIDTH_MISMATCH"),
  );
  addIf(
    findings,
    BigInt(quote.estimates.gasUsdMicros) >
      BigInt(mandate.budgets.maxGasUsdMicros),
    exclusionFinding("GAS_BUDGET_EXCEEDED"),
  );
  addIf(
    findings,
    quote.estimates.slippageBps > mandate.budgets.maxSlippageBps,
    exclusionFinding("SLIPPAGE_BUDGET_EXCEEDED"),
  );
  addIf(
    findings,
    BigInt(quote.estimates.exposureUsdMicros) >
      BigInt(mandate.budgets.maxExposureUsdMicros),
    exclusionFinding("EXPOSURE_BUDGET_EXCEEDED"),
  );
  if (quote.pricing.status === "normalized_zero") {
    addIf(
      findings,
      BigInt(quote.pricing.agentFeeUsdMicros) >
        BigInt(mandate.budgets.maxAgentFeeUsdMicros),
      exclusionFinding("AGENT_FEE_BUDGET_EXCEEDED"),
    );
  }
  addIf(
    findings,
    BigInt(quote.permissions.spendCapUsdMicros) >
      BigInt(mandate.permissions.maxSpendUsdMicros),
    exclusionFinding("PERMISSION_SPEND_CAP_EXCEEDED"),
  );
  addIf(
    findings,
    quote.permissions.expiresAt <= evaluatedAt,
    exclusionFinding("PERMISSION_EXPIRED"),
  );
  addIf(
    findings,
    quote.permissions.expiresAt > mandate.permissions.expiresAt,
    exclusionFinding("PERMISSION_OUTLIVES_MANDATE"),
  );
  addIf(
    findings,
    quote.permissions.contracts.some(
      (contract) => !mandate.permissions.allowedContracts.includes(contract),
    ),
    exclusionFinding("PERMISSION_CONTRACT_NOT_ALLOWED"),
  );
  addIf(
    findings,
    quote.permissions.calls.some(
      (call) => !mandate.permissions.allowedCalls.includes(call),
    ),
    exclusionFinding("PERMISSION_CALL_NOT_ALLOWED"),
  );
  return sortFindings(findings);
}

function decide(
  mandate: MarketplaceMandate,
  quote: MarketplaceQuote,
  evaluatedAt: number,
): MarketplaceEligibilityDecision {
  if (quote.category !== mandate.category) {
    return marketplaceEligibilityDecisionSchema.parse({
      schema: "mandatex.marketplace.eligibility-decision.v1",
      mandateId: mandate.mandateId,
      evaluatedAt,
      quoteId: quote.quoteId,
      candidate: quote.candidate,
      quoteSha256: canonicalSha256(quote),
      outcome: "excluded",
      findings: [exclusionFinding("MANDATE_CATEGORY_MISMATCH")],
      score: null,
    });
  }
  if (quote.normalization.status === "unsupported") {
    return marketplaceEligibilityDecisionSchema.parse({
      schema: "mandatex.marketplace.eligibility-decision.v1",
      mandateId: mandate.mandateId,
      evaluatedAt,
      quoteId: quote.quoteId,
      candidate: quote.candidate,
      quoteSha256: canonicalSha256(quote),
      outcome: "unsupported",
      findings: [unsupportedFinding(quote.normalization.code)],
      score: null,
    });
  }

  const findings = rebalancingFindings(mandate, quote, evaluatedAt);
  const hasExclusion = findings.some((finding) => finding.kind === "exclusion");
  const hasInconclusive = findings.some(
    (finding) => finding.kind === "inconclusive",
  );
  const outcome = hasExclusion
    ? "excluded"
    : hasInconclusive
      ? "inconclusive"
      : "eligible";
  const score =
    outcome === "eligible"
      ? scoreEligibleQuote(mandate, quote, evaluatedAt)
      : null;
  return marketplaceEligibilityDecisionSchema.parse({
    schema: "mandatex.marketplace.eligibility-decision.v1",
    mandateId: mandate.mandateId,
    evaluatedAt,
    quoteId: quote.quoteId,
    candidate: quote.candidate,
    quoteSha256: canonicalSha256(quote),
    outcome,
    findings,
    score,
  });
}

function buildReceipt(
  mandate: MarketplaceMandate,
  quotes: readonly MarketplaceQuote[],
  decisions: readonly MarketplaceEligibilityDecision[],
  evaluatedAt: number,
): MarketplaceReceipt {
  const ranked = decisions
    .filter(
      (decision): decision is MarketplaceEligibilityDecision & {
        score: NonNullable<MarketplaceEligibilityDecision["score"]>;
      } => decision.outcome === "eligible" && decision.score !== null,
    )
    .sort((left, right) => {
      const byScore = right.score.weightedTotal - left.score.weightedTotal;
      if (byScore !== 0) return byScore;
      const byCandidate = compareCandidateKeys(left.candidate, right.candidate);
      return byCandidate !== 0
        ? byCandidate
        : compareCanonicalStrings(left.quoteId, right.quoteId);
    })
    .map((decision, index) => ({
      rank: index + 1,
      quoteId: decision.quoteId,
      candidate: decision.candidate,
      score: decision.score,
    }));

  const quoteReferences = quotes.map((quote) => ({
    quoteId: quote.quoteId,
    candidate: quote.candidate,
    sha256: canonicalSha256(quote),
  }));
  const decisionReferences = decisions.map((decision) => ({
    quoteId: decision.quoteId,
    candidate: decision.candidate,
    sha256: canonicalSha256(decision),
  }));
  const commitments = {
    mandateSha256: canonicalSha256(mandate),
    quotesSha256: canonicalSha256(quotes),
    decisionsSha256: canonicalSha256(decisions),
    rankingSha256: canonicalSha256(ranked),
  };
  const summary = {
    candidates: decisions.length,
    eligible: decisions.filter((decision) => decision.outcome === "eligible").length,
    excluded: decisions.filter((decision) => decision.outcome === "excluded").length,
    inconclusive: decisions.filter(
      (decision) => decision.outcome === "inconclusive",
    ).length,
    unsupported: decisions.filter(
      (decision) => decision.outcome === "unsupported",
    ).length,
  };
  const receiptBody = {
    schema: "mandatex.marketplace.receipt.v1" as const,
    effect: "evaluation_only" as const,
    evaluatedAt,
    mandateId: mandate.mandateId,
    category: mandate.category,
    adapter:
      mandate.category === "rebalancing"
        ? {
            status: "supported" as const,
            name: "pancakeswap-v3-rebalancing-v1" as const,
          }
        : {
            status: "unsupported" as const,
            code:
              mandate.category === "grid"
                ? ("CATEGORY_GRID_UNSUPPORTED" as const)
                : mandate.category === "yield"
                  ? ("CATEGORY_YIELD_UNSUPPORTED" as const)
                  : ("CATEGORY_HEALTH_UNSUPPORTED" as const),
          },
    commitments,
    quotes: quoteReferences,
    decisions: decisionReferences,
    ranking: ranked,
    summary,
  };
  return marketplaceReceiptSchema.parse({
    ...receiptBody,
    receiptId: canonicalSha256(receiptBody),
  });
}

function parseEvaluationMandate(input: unknown): MarketplaceMandate {
  const result = marketplaceMandateSchema.safeParse(input);
  if (!result.success) {
    throw new MarketplaceCoreError("MANDATE_INVALID", "mandate is invalid", {
      cause: result.error,
    });
  }
  return result.data;
}

function assertEvaluationInput(input: EvaluateMarketplaceInput): void {
  if (
    input === null ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    !Array.isArray((input as Partial<EvaluateMarketplaceInput>).candidates)
  ) {
    throw new MarketplaceCoreError(
      "EVALUATION_INPUT_INVALID",
      "expected mandate and candidates evaluation input",
    );
  }
  const keys = Reflect.ownKeys(input);
  const stringKeys = keys
    .filter((key): key is string => typeof key === "string")
    .sort(compareCanonicalStrings);
  if (
    keys.length !== 2 ||
    stringKeys.length !== 2 ||
    stringKeys[0] !== "candidates" ||
    stringKeys[1] !== "mandate"
  ) {
    throw new MarketplaceCoreError(
      "EVALUATION_INPUT_INVALID",
      "evaluation input must contain only mandate and candidates",
    );
  }
}

function assertEvaluationV2Input(input: EvaluateMarketplaceV2Input): void {
  if (
    input === null ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    !Array.isArray((input as Partial<EvaluateMarketplaceV2Input>).attestations)
  ) {
    throw new MarketplaceCoreError(
      "EVALUATION_INPUT_INVALID",
      "expected mandate and attestations v2 evaluation input",
    );
  }
  const keys = Reflect.ownKeys(input);
  const stringKeys = keys
    .filter((key): key is string => typeof key === "string")
    .sort(compareCanonicalStrings);
  if (
    keys.length !== 2 ||
    stringKeys.length !== 2 ||
    stringKeys[0] !== "attestations" ||
    stringKeys[1] !== "mandate"
  ) {
    throw new MarketplaceCoreError(
      "EVALUATION_INPUT_INVALID",
      "v2 evaluation input must contain only mandate and attestations",
    );
  }
  if (input.attestations.length > MAX_CANDIDATES) {
    throw new CandidateSetError(
      "CANDIDATE_LIMIT_EXCEEDED",
      `Marketplace Core accepts at most ${MAX_CANDIDATES} candidates`,
    );
  }
}

function evaluateMarketplaceWithCapability(
  input: EvaluateMarketplaceInput,
  capability: ProjectionCapability,
  clock: () => number,
): MarketplaceEvaluationResult {
  assertEvaluationInput(input);
  const mandate = parseEvaluationMandate(input.mandate);
  const evaluatedAt = readCoreClock(clock);
  validateEvaluationTime(mandate, evaluatedAt);
  validateCapturedCandidateSet(input.candidates, capability);
  const quotes = input.candidates
    .map((projection) => normalizeCapturedQuote(projection, capability))
    .sort(compareQuotes);
  const decisions = quotes.map((quote) => decide(mandate, quote, evaluatedAt));
  return deepFreeze({
    mandate,
    quotes,
    decisions,
    receipt: buildReceipt(mandate, quotes, decisions, evaluatedAt),
  });
}

/**
 * @deprecated Use createMarketplaceCoreV2 for portable signed evaluation
 * attestations. This factory accepts only process-local v1 capture objects.
 */
export function createMarketplaceCore(
  options: MarketplaceCoreOptions,
): MarketplaceCore {
  if (options === null || typeof options !== "object") {
    throw new MarketplaceCoreError(
      "TRUSTED_INGRESS_INSTALLER_INVALID",
      "Marketplace Core options must install a trusted projection ingress",
    );
  }
  let installTrustedProjectionIngress: unknown;
  try {
    installTrustedProjectionIngress = options.installTrustedProjectionIngress;
  } catch (cause) {
    throw new MarketplaceCoreError(
      "TRUSTED_INGRESS_INSTALLER_INVALID",
      "the trusted projection ingress installer could not be read",
      { cause },
    );
  }
  let clock: unknown;
  try {
    clock = options.clock;
  } catch (cause) {
    throw new MarketplaceCoreError(
      "CORE_CLOCK_INVALID",
      "the Marketplace Core clock could not be read",
      { cause },
    );
  }
  const capability = createProjectionCapability(
    installTrustedProjectionIngress as MarketplaceCoreOptions["installTrustedProjectionIngress"],
    clock as MarketplaceCoreOptions["clock"],
  );
  return Object.freeze({
    evaluateMarketplace(input: EvaluateMarketplaceInput) {
      return evaluateMarketplaceWithCapability(
        input,
        capability,
        clock as MarketplaceCoreOptions["clock"],
      );
    },
  });
}

/**
 * @deprecated Explicit alias for the v1 process-local capture factory.
 */
export const createLegacyMarketplaceCoreV1 = createMarketplaceCore;

export function createMarketplaceCoreV2(
  options: MarketplaceCoreV2Options,
): MarketplaceCoreV2 {
  if (options === null || typeof options !== "object") {
    throw new MarketplaceCoreError(
      "ATTESTATION_TRUST_INVALID",
      "Marketplace Core v2 requires pinned attestation trust",
    );
  }
  const trust = validateMarketplaceAttestationTrust(options.attestationTrust);
  const maxClockSkewSeconds = options.maxClockSkewSeconds;
  if (
    !Number.isSafeInteger(maxClockSkewSeconds) ||
    maxClockSkewSeconds < 0 ||
    maxClockSkewSeconds > 300
  ) {
    throw new MarketplaceCoreError(
      "ATTESTATION_TRUST_INVALID",
      "Marketplace Core v2 clock skew must be an integer from zero to 300 seconds",
    );
  }
  if (typeof options.clock !== "function") {
    throw new MarketplaceCoreError(
      "CORE_CLOCK_INVALID",
      "Marketplace Core v2 clock must be a function",
    );
  }
  const clock = options.clock;

  return Object.freeze({
    evaluateMarketplaceV2(input: EvaluateMarketplaceV2Input) {
      assertEvaluationV2Input(input);
      const mandate = parseEvaluationMandate(input.mandate);
      const evaluatedAt = readCoreClock(clock);
      validateEvaluationTime(mandate, evaluatedAt);

      const projections: DisplaySafeQuoteProjection[] = input.attestations.map(
        (wire) => {
          const verified = verifyMarketplaceEvaluationAttestation({
            wire,
            mandate,
            evaluatedAt,
            maxClockSkewSeconds,
            trust,
          });
          const projection = displaySafeQuoteProjectionSchema.safeParse({
            schema: "mandatex.marketplace.display-safe-quote-projection.v1",
            captureContext: "trusted-quote-validation-success",
            capturedAt: verified.envelope.issuedAt,
            ...verified.envelope.payload,
          });
          if (!projection.success) {
            throw new MarketplaceCoreError(
              "ATTESTATION_SCHEMA_INVALID",
              "evaluation attestation payload is internally inconsistent",
              { cause: projection.error },
            );
          }
          return projection.data;
        },
      );

      validateAttestedCandidateSet(projections);
      const quotes = projections
        .map(normalizeDisplaySafeQuoteProjection)
        .sort(compareQuotes);
      const decisions = quotes.map((quote) =>
        decide(mandate, quote, evaluatedAt),
      );
      return deepFreeze({
        mandate,
        quotes,
        decisions,
        receipt: buildReceipt(mandate, quotes, decisions, evaluatedAt),
      });
    },
  });
}

type SafeParseResult<T> =
  | { readonly success: true; readonly data: T }
  | { readonly success: false; readonly error: Error };

interface IntegrityArtifactSchema<T> {
  safeParse(input: unknown): SafeParseResult<T>;
}

function parseIntegrityArtifact<T>(
  schema: IntegrityArtifactSchema<T>,
  input: unknown,
  invalidCode: MarketplaceErrorCode,
  label: string,
): T {
  const parsedResult = schema.safeParse(input);
  if (!parsedResult.success) {
    throw new MarketplaceCoreError(invalidCode, `${label} is invalid`, {
      cause: parsedResult.error,
    });
  }
  let inputCanonical: string;
  try {
    inputCanonical = canonicalJson(input);
  } catch (cause) {
    throw new MarketplaceCoreError(
      "INTEGRITY_NONCANONICAL_INPUT",
      `${label} is not canonical JSON data`,
      { cause },
    );
  }
  if (inputCanonical !== canonicalJson(parsedResult.data)) {
    throw new MarketplaceCoreError(
      "INTEGRITY_NONCANONICAL_INPUT",
      `${label} is valid only after normalization`,
    );
  }
  return parsedResult.data;
}

function assertIntegrityResultShape(
  input: unknown,
): asserts input is Record<"mandate" | "quotes" | "decisions" | "receipt", unknown> {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new MarketplaceCoreError(
      "INTEGRITY_RESULT_SHAPE_INVALID",
      "expected a Marketplace Core evaluation result object",
    );
  }
  const prototype = Object.getPrototypeOf(input);
  const keys = Reflect.ownKeys(input);
  const expectedKeys = ["decisions", "mandate", "quotes", "receipt"];
  const stringKeys = keys
    .filter((key): key is string => typeof key === "string")
    .sort(compareCanonicalStrings);
  if (
    (prototype !== Object.prototype && prototype !== null) ||
    stringKeys.length !== expectedKeys.length ||
    keys.length !== expectedKeys.length ||
    stringKeys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new MarketplaceCoreError(
      "INTEGRITY_RESULT_SHAPE_INVALID",
      "evaluation result must contain only mandate, quotes, decisions, and receipt",
    );
  }
}

function assertIntegrityUniqueness(
  references: readonly CandidateReference[],
  label: string,
): void {
  const issue = inspectCandidateSet(references);
  if (issue !== undefined) {
    throw new MarketplaceCoreError(
      "INTEGRITY_UNIQUENESS_INVALID",
      `${label}: ${issue.message}`,
    );
  }
}

export function verifyMarketplaceEvaluationConsistency(
  input: unknown,
): MarketplaceEvaluationConsistency {
  assertIntegrityResultShape(input);
  const record = input as Record<string, unknown>;
  const mandate = parseIntegrityArtifact(
    marketplaceMandateSchema,
    record.mandate,
    "INTEGRITY_MANDATE_INVALID",
    "mandate artifact",
  );
  if (!Array.isArray(record.quotes) || !Array.isArray(record.decisions)) {
    throw new MarketplaceCoreError(
      "INTEGRITY_RESULT_SHAPE_INVALID",
      "evaluation result quotes and decisions must be arrays",
    );
  }
  if (
    record.quotes.length > MAX_CANDIDATES ||
    record.decisions.length > MAX_CANDIDATES
  ) {
    throw new MarketplaceCoreError(
      "INTEGRITY_RESULT_TOO_LARGE",
      `Marketplace Core accepts at most ${MAX_CANDIDATES} candidates`,
    );
  }
  if (record.quotes.length !== record.decisions.length) {
    throw new MarketplaceCoreError(
      "INTEGRITY_RESULT_SHAPE_INVALID",
      "quote and decision artifact counts must match",
    );
  }
  const quotes = Array.from(record.quotes, (quote, index) =>
    parseIntegrityArtifact(
      marketplaceQuoteSchema,
      quote,
      "INTEGRITY_QUOTES_INVALID",
      `quote artifact ${index}`,
    ),
  );
  const decisions = Array.from(record.decisions, (decision, index) =>
    parseIntegrityArtifact(
      marketplaceEligibilityDecisionSchema,
      decision,
      "INTEGRITY_DECISIONS_INVALID",
      `decision artifact ${index}`,
    ),
  );
  const receipt = parseIntegrityArtifact(
    marketplaceReceiptSchema,
    record.receipt,
    "INTEGRITY_RECEIPT_INVALID",
    "receipt artifact",
  );
  validateEvaluationTime(mandate, receipt.evaluatedAt);
  assertIntegrityUniqueness(quotes, "quote artifacts");
  assertIntegrityUniqueness(decisions, "decision artifacts");
  if (receipt.mandateId !== mandate.mandateId) {
    throw new MarketplaceCoreError(
      "INTEGRITY_RECEIPT_INVALID",
      "receipt mandateId does not match the mandate artifact",
    );
  }
  const sortedQuotes = [...quotes].sort(compareQuotes);
  if (canonicalJson(quotes) !== canonicalJson(sortedQuotes)) {
    throw new MarketplaceCoreError(
      "INTEGRITY_RESULT_UNORDERED",
      "quote artifacts are not in canonical candidate order",
    );
  }
  const expectedDecisions = quotes.map((quote) =>
    decide(mandate, quote, receipt.evaluatedAt),
  );
  if (canonicalJson(decisions) !== canonicalJson(expectedDecisions)) {
    throw new MarketplaceCoreError(
      "INTEGRITY_DECISIONS_INVALID",
      "eligibility decisions do not match deterministic evaluation",
    );
  }
  const expectedReceipt = buildReceipt(
    mandate,
    quotes,
    decisions,
    receipt.evaluatedAt,
  );
  if (canonicalJson(receipt) !== canonicalJson(expectedReceipt)) {
    throw new MarketplaceCoreError(
      "INTEGRITY_RECEIPT_INVALID",
      "receipt commitments or ranking do not match the artifacts",
    );
  }
  const result = deepFreeze({ mandate, quotes, decisions, receipt });
  return deepFreeze({ scope: "integrity_only", result });
}
