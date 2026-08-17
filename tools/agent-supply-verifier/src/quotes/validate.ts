import { randomUUID as nodeRandomUUID } from "node:crypto";

import {
  decodeFunctionResult,
  encodeFunctionData,
  type Hex,
} from "viem";

import { DEFAULT_CHAIN_PROFILE, POLICY_FINGERPRINT } from "../policy.js";
import { serializeReport } from "../report.js";
import {
  manifestFileSchema,
  runReportSchema,
  type CandidateReport,
  type ManifestCandidate,
  type ManifestFile,
  type RunReport,
} from "../schema.js";
import {
  parseJsonResponse,
  type BoundedHttpResponse,
  type PinnedHttpsTransport,
} from "../transport/http.js";
import {
  buildQuoteA2aRequest,
  buildQuoteSidecar,
  canonicalQuoteJson,
  computeQuoteReplayKey,
  computeQuoteSha256,
  parseQuoteA2aResponse,
  QuoteProtocolError,
  REBALANCE_FUTURE_TOLERANCE_SECONDS,
  serializeQuoteA2aRequest,
  serializeQuoteTrustFile,
  verifyQuoteMandateBinding,
  verifyQuoteEnvelope,
  type QuoteErc1271Call,
  type VerifiedQuoteEnvelope,
} from "./protocol.js";
import {
  type ReplayMetadata,
  type ReplayStore,
} from "./replay.js";
import {
  MIN_QUOTE_REMAINING_SECONDS,
  quoteAcceptedEnvelopeSchema,
  quoteMandatexRebalanceMandateSchema,
  quoteTrustFileSchema,
  type QuoteEnvelope,
  type QuoteAcceptedEnvelope,
  type QuoteMandate,
  type QuoteMandatexRebalanceMandate,
  type QuoteProtocolErrorCode,
  type QuoteSidecar,
  type QuoteTrustEntry,
  type QuoteTrustFile,
  type QuoteValidationGates,
} from "./schema.js";

const REQUIRED_PASS_GATES = [
  "manifest_identity",
  "bsc_chain",
  "token_ownership",
  "endpoint_origin",
  "endpoint_health",
  "task_interface",
] as const;

export type QuoteCandidateSelector = Readonly<{
  chainId: number;
  tokenId: string;
}>;

export type QuotePreflightErrorCode =
  | "CANDIDATE_NOT_FOUND"
  | "CANDIDATE_AMBIGUOUS"
  | "PASSIVE_POLICY_MISMATCH"
  | "CHAIN_PROFILE_MISMATCH"
  | "CANDIDATE_MISMATCH"
  | "CANDIDATE_NOT_REGISTERED"
  | "PASSIVE_GATE_MISSING"
  | "PASSIVE_GATE_DUPLICATE"
  | "PASSIVE_GATE_NOT_PASSED"
  | "PASSIVE_QUOTE_GATE_NOT_UNKNOWN"
  | "PASSIVE_OBSERVATION_MISSING"
  | "PASSIVE_OBSERVATION_STALE"
  | "PASSIVE_OBSERVATION_IN_FUTURE"
  | "CARD_ENDPOINT_MISMATCH"
  | "QUOTE_ENDPOINT_MISMATCH"
  | "NEGOTIATE_SKILL_MISSING"
  | "NEGOTIATE_SKILL_AMBIGUOUS"
  | "NEGOTIATE_SKILL_INCOMPATIBLE"
  | "TRUSTED_REGISTRY_CONFLICT"
  | "TRUSTED_CATEGORY_CONFLICT"
  | "TRUSTED_PROVIDER_CONFLICT"
  | "MANDATE_INVALID"
  | "MANDATE_EXPIRED"
  | "PREVIEW_INPUT_UNSUPPORTED"
  | "REPLAY_STORE_UNAVAILABLE";

export class QuotePreflightError extends Error {
  readonly code: QuotePreflightErrorCode;

  constructor(code: QuotePreflightErrorCode) {
    super(publicPreflightMessage(code));
    this.name = "QuotePreflightError";
    this.code = code;
  }
}

export type QuotePreflightContext = Readonly<{
  manifest: ManifestFile;
  passiveReport: RunReport;
  trustFile: QuoteTrustFile;
  manifestCandidate: ManifestCandidate;
  passiveCandidate: CandidateReport;
  trust: QuoteTrustEntry;
  passiveReportSha256: string;
  passiveCandidateSha256: string;
  trustPolicySha256: string;
  quoteEndpointSha256: string;
}>;

export interface QuotePreflightOptions {
  readonly manifest: ManifestFile;
  readonly passiveReport: RunReport;
  readonly trustFile: QuoteTrustFile;
  readonly candidate: QuoteCandidateSelector;
  readonly now?: () => Date;
}

export interface TrustedQuoteAttemptOptions extends QuotePreflightOptions {
  readonly mandate: QuoteMandate;
  readonly transport: Pick<PinnedHttpsTransport, "request">;
  readonly randomUUID?: () => string;
}

export interface ValidateTrustedQuoteOptions extends TrustedQuoteAttemptOptions {
  readonly replayStore: ReplayStore;
  readonly preReplayGate?: TrustedQuotePreReplayGate;
  readonly replayCommit?: TrustedQuoteReplayCommit;
}

export type TrustedQuoteReplayCommitResult =
  | "created"
  | "recovered"
  | "duplicate";

export type TrustedQuoteReplayCandidate = Readonly<{
  replayKey: string;
  replayMetadata: ReplayMetadata;
  claimedSidecar: QuoteSidecar;
}>;

export type TrustedQuoteReplayCommit = (
  candidate: TrustedQuoteReplayCandidate,
) => Promise<TrustedQuoteReplayCommitResult>;

export type TrustedQuotePreReplayGateInput = Readonly<{
  context: QuotePreflightContext;
  mandate: QuoteMandatexRebalanceMandate;
  envelope: QuoteAcceptedEnvelope;
  verification: VerifiedQuoteEnvelope;
  binding: ReturnType<typeof verifyQuoteMandateBinding>;
  validationTime: Date;
  transport: Pick<PinnedHttpsTransport, "request">;
  randomUUID: () => string;
}>;

export type TrustedQuotePreReplayGateDecision =
  | Readonly<{
      outcome: "pass";
      commitConstraint?: TrustedQuotePreReplayCommitConstraint;
    }>
  | Readonly<{
      outcome: "invalid" | "inconclusive";
      errorCode: "PREVIEW_GATE_REJECTED" | "PREVIEW_GATE_UNAVAILABLE";
    }>;

export type TrustedQuotePreReplayCommitConstraint = Readonly<{
  validUntil: number;
  minimumRemainingMilliseconds: number;
}>;

export type TrustedQuotePreReplayGate = (
  input: TrustedQuotePreReplayGateInput,
) => Promise<TrustedQuotePreReplayGateDecision>;

export type TrustedQuoteAttemptGateResult<T> = Readonly<{
  decision: TrustedQuotePreReplayGateDecision;
  data: T;
}>;

export type TrustedQuoteAttemptGate<T> = (
  input: TrustedQuotePreReplayGateInput,
) => Promise<TrustedQuoteAttemptGateResult<T>>;

export type PreparedTrustedQuoteAttempt = Readonly<{
  context: QuotePreflightContext;
  mandate: QuoteMandatexRebalanceMandate;
  transport: Pick<PinnedHttpsTransport, "request">;
  now: () => Date;
  randomUUID: () => string;
  request: ReturnType<typeof buildQuoteA2aRequest>;
  requestBody: string;
  requestSha256: string;
}>;

export type TrustedQuoteVerifiedCandidate<T> = Readonly<{
  context: QuotePreflightContext;
  mandate: QuoteMandatexRebalanceMandate;
  envelope: QuoteAcceptedEnvelope;
  verification: VerifiedQuoteEnvelope;
  binding: ReturnType<typeof verifyQuoteMandateBinding>;
  decisionTime: Date;
  requestSha256: string;
  responseSha256: string;
  prospectiveReplayKey: string;
  gateData?: T;
}>;

export type TrustedQuoteAttemptResult<T> =
  | Readonly<{
      status: "terminal";
      sidecar: QuoteSidecar;
      gateData?: T;
    }>
  | Readonly<{
      status: "verified";
      candidate: TrustedQuoteVerifiedCandidate<T>;
    }>;

export function preflightTrustedQuote(
  options: QuotePreflightOptions,
): QuotePreflightContext {
  const manifest = manifestFileSchema.parse(options.manifest);
  const passiveReport = runReportSchema.parse(options.passiveReport);
  const trustFile = quoteTrustFileSchema.parse(options.trustFile);
  const now = (options.now ?? (() => new Date()))();

  if (passiveReport.policyFingerprint !== POLICY_FINGERPRINT) {
    throw new QuotePreflightError("PASSIVE_POLICY_MISMATCH");
  }
  if (!sameChainProfile(passiveReport.chainProfile)) {
    throw new QuotePreflightError("CHAIN_PROFILE_MISMATCH");
  }

  const manifestCandidate = selectExactlyOne(
    manifest.candidates,
    options.candidate,
  );
  const passiveCandidate = selectExactlyOne(
    passiveReport.candidates,
    options.candidate,
  );
  const trust = selectExactlyOne(trustFile.candidates, options.candidate);

  if (
    trust.registryAddress !== DEFAULT_CHAIN_PROFILE.registryAddress ||
    trust.registryAddress !== passiveReport.chainProfile.registryAddress
  ) {
    throw new QuotePreflightError("TRUSTED_REGISTRY_CONFLICT");
  }

  assertCandidateMatches(manifestCandidate, passiveCandidate);
  if (passiveCandidate.status !== "REGISTERED_ONLY") {
    throw new QuotePreflightError("CANDIDATE_NOT_REGISTERED");
  }

  for (const gateName of REQUIRED_PASS_GATES) {
    requireGate(passiveCandidate, gateName, "pass");
  }
  requireGate(passiveCandidate, "quote_signature", "unknown");

  const chain = passiveCandidate.chain;
  const card = passiveCandidate.card;
  if (chain === undefined || card === undefined) {
    throw new QuotePreflightError("PASSIVE_OBSERVATION_MISSING");
  }
  if (
    chain.chainId !== manifestCandidate.chainId ||
    chain.tokenId !== manifestCandidate.tokenId
  ) {
    throw new QuotePreflightError("CANDIDATE_MISMATCH");
  }
  if (chain.registryAddress !== trust.registryAddress) {
    throw new QuotePreflightError("TRUSTED_REGISTRY_CONFLICT");
  }
  if (!manifestCandidate.categories.includes(trust.category)) {
    throw new QuotePreflightError("TRUSTED_CATEGORY_CONFLICT");
  }
  if (chain.owner !== trust.expectedProvider) {
    throw new QuotePreflightError("TRUSTED_PROVIDER_CONFLICT");
  }

  assertFreshTimestamp(
    passiveReport.generatedAt,
    now,
    trust.maxPassiveAgeSeconds,
    trust.maxClockSkewSeconds,
  );
  assertFreshTimestamp(
    chain.observedAt,
    now,
    trust.maxPassiveAgeSeconds,
    trust.maxClockSkewSeconds,
  );
  assertFreshTimestamp(
    card.observedAt,
    now,
    trust.maxPassiveAgeSeconds,
    trust.maxClockSkewSeconds,
  );

  if (
    trust.cardUrl !== manifestCandidate.expectedEndpoint ||
    passiveCandidate.expectedEndpoint !== trust.cardUrl
  ) {
    throw new QuotePreflightError("CARD_ENDPOINT_MISMATCH");
  }
  if (
    card.url !== trust.quoteEndpoint ||
    new URL(trust.quoteEndpoint).origin !== manifestCandidate.expectedOrigin
  ) {
    throw new QuotePreflightError("QUOTE_ENDPOINT_MISMATCH");
  }

  const negotiateSkills = card.skills.filter((skill) => skill.id === "negotiate");
  if (negotiateSkills.length === 0) {
    throw new QuotePreflightError("NEGOTIATE_SKILL_MISSING");
  }
  if (negotiateSkills.length !== 1) {
    throw new QuotePreflightError("NEGOTIATE_SKILL_AMBIGUOUS");
  }
  const negotiate = negotiateSkills[0]!;
  if (
    !negotiate.inputModes.includes("application/json") ||
    !negotiate.outputModes.includes("application/json")
  ) {
    throw new QuotePreflightError("NEGOTIATE_SKILL_INCOMPATIBLE");
  }

  const claimedAgentWallet = passiveCandidate.scan?.agentWallet;
  if (
    claimedAgentWallet !== undefined &&
    claimedAgentWallet !== null &&
    claimedAgentWallet !== trust.expectedProvider
  ) {
    throw new QuotePreflightError("TRUSTED_PROVIDER_CONFLICT");
  }

  return {
    manifest,
    passiveReport,
    trustFile,
    manifestCandidate,
    passiveCandidate,
    trust,
    passiveReportSha256: computeQuoteSha256(serializeReport(passiveReport)),
    passiveCandidateSha256: computeQuoteSha256(
      canonicalQuoteJson(passiveCandidate),
    ),
    trustPolicySha256: computeQuoteSha256(
      serializeQuoteTrustFile(trustFile),
    ),
    quoteEndpointSha256: computeQuoteSha256(trust.quoteEndpoint),
  };
}

export async function validateTrustedQuote(
  options: ValidateTrustedQuoteOptions,
): Promise<QuoteSidecar> {
  const attempt = prepareTrustedQuoteAttempt(options);

  try {
    await options.replayStore.prepare();
  } catch {
    throw new QuotePreflightError("REPLAY_STORE_UNAVAILABLE");
  }

  const result = await executeTrustedQuoteAttempt(
    attempt,
    options.preReplayGate === undefined
      ? undefined
      : async (input) => ({
          decision: await options.preReplayGate!(input),
          data: undefined,
        }),
  );
  if (result.status === "terminal") return result.sidecar;

  const candidate = result.candidate;
  const replayKey = candidate.prospectiveReplayKey;
  const replayMetadata: ReplayMetadata = {
    schema: "mandatex.agent-supply.quote-replay.v1",
    claimedAt: candidate.decisionTime.toISOString(),
    chainId: candidate.context.trust.chainId,
    tokenId: candidate.context.trust.tokenId,
    endpointHash: candidate.context.quoteEndpointSha256,
    provider: candidate.context.trust.expectedProvider,
    commerceContract: candidate.context.trust.commerceContract,
    negotiationHash: candidate.verification.negotiationHash,
  };
  const claimedSidecar = buildQuoteSidecar({
    ...sidecarBase(
      candidate.context,
      candidate.decisionTime,
      candidate.requestSha256,
    ),
    outcome: "valid",
    a2aResponseSha256: candidate.responseSha256,
    replayKey,
    replayStatus: "claimed",
    gates: {
      passivePreflight: "pass",
      endpointBinding: "pass",
      quoteSignature: "pass",
      quotePolicy: "pass",
      replay: "pass",
    },
    envelope: candidate.envelope,
    verification: candidate.verification,
  });

  let claim: TrustedQuoteReplayCommitResult;
  try {
    claim = options.replayCommit === undefined
      ? (await options.replayStore.claim(replayKey, replayMetadata)) === "claimed"
        ? "created"
        : "duplicate"
      : await options.replayCommit({
          replayKey,
          replayMetadata,
          claimedSidecar,
        });
  } catch {
    return failureSidecar({
      context: candidate.context,
      observedAt: candidate.decisionTime,
      requestSha256: candidate.requestSha256,
      responseSha256: candidate.responseSha256,
      outcome: "inconclusive",
      errorCode: "REPLAY_STORE_UNAVAILABLE",
      replayKey,
      gates: {
        ...baseGates(),
        quoteSignature: "pass",
        quotePolicy: "pass",
      },
      envelope: candidate.envelope,
      verification: candidate.verification,
    });
  }

  if (claim === "duplicate") {
    return failureSidecar({
      context: candidate.context,
      observedAt: candidate.decisionTime,
      requestSha256: candidate.requestSha256,
      responseSha256: candidate.responseSha256,
      outcome: "invalid",
      errorCode: "REPLAY_DETECTED",
      replayKey,
      replayStatus: "duplicate",
      gates: {
        ...baseGates(),
        quoteSignature: "pass",
        quotePolicy: "pass",
        replay: "fail",
      },
      envelope: candidate.envelope,
      verification: candidate.verification,
    });
  }

  return claimedSidecar;
}

export function prepareTrustedQuoteAttempt(
  options: TrustedQuoteAttemptOptions,
): PreparedTrustedQuoteAttempt {
  const now = options.now ?? (() => new Date());
  const preflightTime = now();
  const context = preflightTrustedQuote({
    manifest: options.manifest,
    passiveReport: options.passiveReport,
    trustFile: options.trustFile,
    candidate: options.candidate,
    now: () => preflightTime,
  });

  const parsedMandate = quoteMandatexRebalanceMandateSchema.safeParse(
    options.mandate,
  );
  if (!parsedMandate.success) {
    throw new QuotePreflightError("MANDATE_INVALID");
  }
  if (
    parsedMandate.data.category !== context.trust.category ||
    parsedMandate.data.chain_id !== context.trust.chainId
  ) {
    throw new QuotePreflightError("MANDATE_INVALID");
  }
  const mandateTemporalFailure = mandateTemporalPolicyFailure(
    parsedMandate.data,
    preflightTime,
  );
  if (mandateTemporalFailure !== undefined) {
    throw new QuotePreflightError(mandateTemporalFailure);
  }

  const randomUUID = options.randomUUID ?? nodeRandomUUID;
  const request = buildQuoteA2aRequest({
    rpcId: randomUUID(),
    messageId: randomUUID(),
    mandate: parsedMandate.data,
  });
  const requestBody = serializeQuoteA2aRequest(request);
  const requestSha256 = computeQuoteSha256(requestBody);

  return {
    context,
    mandate: parsedMandate.data,
    transport: options.transport,
    now,
    randomUUID,
    request,
    requestBody,
    requestSha256,
  };
}

export async function executeTrustedQuoteAttempt<T>(
  attempt: PreparedTrustedQuoteAttempt,
  gate?: TrustedQuoteAttemptGate<T>,
): Promise<TrustedQuoteAttemptResult<T>> {
  const {
    context,
    mandate,
    transport,
    now,
    randomUUID,
    request,
    requestBody,
    requestSha256,
  } = attempt;

  let response: BoundedHttpResponse;
  try {
    response = await transport.request({
      kind: "a2a-quote",
      method: "POST",
      url: context.trust.quoteEndpoint,
      approvedUrl: context.trust.quoteEndpoint,
      rpcMethod: "message/send",
      body: requestBody,
    });
  } catch {
    return terminalTrustedQuoteResult(failureSidecar({
      context,
      observedAt: now(),
      requestSha256,
      outcome: "inconclusive",
      errorCode: "TRANSPORT_FAILED",
      gates: baseGates(),
    }));
  }

  if (response.status !== 200) {
    return terminalTrustedQuoteResult(failureSidecar({
      context,
      observedAt: now(),
      requestSha256,
      responseSha256: response.responseSha256,
      outcome: "inconclusive",
      errorCode: "HTTP_STATUS_INVALID",
      gates: baseGates(),
    }));
  }

  let responseJson: unknown;
  try {
    responseJson = parseJsonResponse(response);
  } catch {
    return terminalTrustedQuoteResult(failureSidecar({
      context,
      observedAt: now(),
      requestSha256,
      responseSha256: response.responseSha256,
      outcome: "invalid",
      errorCode: "RESPONSE_JSON_INVALID",
      gates: baseGates(),
    }));
  }

  let envelope: QuoteEnvelope;
  try {
    envelope = parseQuoteA2aResponse(responseJson, {
      expectedRpcId: request.id,
    });
  } catch (error) {
    const code = protocolErrorCode(error, "RESPONSE_SCHEMA_INVALID");
    return terminalTrustedQuoteResult(failureSidecar({
      context,
      observedAt: now(),
      requestSha256,
      responseSha256: response.responseSha256,
      outcome: isInconclusiveProtocolCode(code) ? "inconclusive" : "invalid",
      errorCode: code,
      gates: baseGates(),
    }));
  }

  if (!envelope.response.accepted) {
    return terminalTrustedQuoteResult(buildQuoteSidecar({
      ...sidecarBase(context, now(), requestSha256),
      outcome: "refused",
      a2aResponseSha256: response.responseSha256,
      replayStatus: "not_attempted",
      gates: baseGates(),
      refusalCode: refusalCode(envelope),
      envelope,
    }));
  }
  const acceptedEnvelope = quoteAcceptedEnvelopeSchema.parse(envelope);

  const validationTime = now();

  let binding: ReturnType<typeof verifyQuoteMandateBinding>;
  try {
    binding = verifyQuoteMandateBinding({
      envelope,
      mandate,
      codec: context.trust.protocol.signedTaskCodec,
      now: validationTime,
    });
  } catch (error) {
    return terminalTrustedQuoteResult(failureSidecar({
      context,
      observedAt: now(),
      requestSha256,
      responseSha256: response.responseSha256,
      outcome: "invalid",
      errorCode: protocolErrorCode(error, "MANDATE_BINDING_MISMATCH"),
      gates: {
        ...baseGates(),
        quotePolicy: "fail",
      },
      envelope,
    }));
  }

  let verification: VerifiedQuoteEnvelope;
  try {
    verification = await verifyQuoteEnvelope({
      envelope,
      expectedProvider: context.trust.expectedProvider,
      expectedProviderKind: context.trust.providerKind,
      expectedChainId: context.trust.chainId,
      expectedVerifyingContract: context.trust.commerceContract,
      now: validationTime,
      erc1271Call: createErc1271Call(
        transport,
        randomUUID,
        context.passiveCandidate.chain!.observedBlockHash,
        context.trust.commerceContract,
      ),
    });
  } catch (error) {
    const code = protocolErrorCode(error, "PROVIDER_SIGNATURE_INVALID");
    return terminalTrustedQuoteResult(failureSidecar({
      context,
      observedAt: now(),
      requestSha256,
      responseSha256: response.responseSha256,
      outcome: isInconclusiveProtocolCode(code) ? "inconclusive" : "invalid",
      errorCode: code,
      gates: {
        ...baseGates(),
        quoteSignature: code === "ERC1271_UNAVAILABLE" ? "unknown" : "fail",
      },
      envelope,
    }));
  }

  if (
    !quotePolicyAllows(
      context.trust,
      verification,
      mandate,
      validationTime,
    )
  ) {
    return terminalTrustedQuoteResult(failureSidecar({
      context,
      observedAt: now(),
      requestSha256,
      responseSha256: response.responseSha256,
      outcome: "invalid",
      errorCode: "QUOTE_POLICY_REJECTED",
      gates: {
        ...baseGates(),
        quoteSignature: "pass",
        quotePolicy: "fail",
      },
      envelope,
      verification,
    }));
  }

  let preReplayCommitConstraint: TrustedQuotePreReplayCommitConstraint | undefined;
  let gateData: T | undefined;
  if (gate !== undefined) {
    let gateDecision: TrustedQuotePreReplayGateDecision;
    try {
      const gateResult = await gate({
        context,
        mandate,
        envelope: acceptedEnvelope,
        verification,
        binding,
        validationTime,
        transport,
        randomUUID,
      });
      gateDecision = gateResult.decision;
      gateData = gateResult.data;
    } catch {
      gateDecision = {
        outcome: "inconclusive",
        errorCode: "PREVIEW_GATE_UNAVAILABLE",
      };
    }
    if (
      gateDecision.outcome === "pass" &&
      gateDecision.commitConstraint !== undefined
    ) {
      if (!isValidCommitConstraint(gateDecision.commitConstraint)) {
        gateDecision = {
          outcome: "inconclusive",
          errorCode: "PREVIEW_GATE_UNAVAILABLE",
        };
      } else {
        preReplayCommitConstraint = gateDecision.commitConstraint;
      }
    }
    if (gateDecision.outcome !== "pass") {
      return terminalTrustedQuoteResult(failureSidecar({
        context,
        observedAt: now(),
        requestSha256,
        responseSha256: response.responseSha256,
        outcome: gateDecision.outcome,
        errorCode: gateDecision.errorCode,
        gates: {
          ...baseGates(),
          quoteSignature: "pass",
          quotePolicy: "pass",
        },
        envelope,
        verification,
      }), gateData);
    }
  }

  const decisionTime = now();
  if (!passiveEvidenceIsFresh(context, decisionTime)) {
    return terminalTrustedQuoteResult(failureSidecar({
      context,
      observedAt: decisionTime,
      requestSha256,
      responseSha256: response.responseSha256,
      outcome: "invalid",
      errorCode: "PASSIVE_PREFLIGHT_FAILED",
      gates: {
        ...baseGates(),
        passivePreflight: "fail",
        quoteSignature: "pass",
      },
      envelope,
      verification,
    }), gateData);
  }

  if (mandateTemporalPolicyFailure(mandate, decisionTime)) {
    return terminalTrustedQuoteResult(failureSidecar({
      context,
      observedAt: decisionTime,
      requestSha256,
      responseSha256: response.responseSha256,
      outcome: "invalid",
      errorCode: "QUOTE_POLICY_REJECTED",
      gates: {
        ...baseGates(),
        quoteSignature: "pass",
        quotePolicy: "fail",
      },
      envelope,
      verification,
    }), gateData);
  }

  let finalBinding: ReturnType<typeof verifyQuoteMandateBinding>;
  try {
    finalBinding = verifyQuoteMandateBinding({
      envelope,
      mandate,
      codec: context.trust.protocol.signedTaskCodec,
      now: decisionTime,
    });
  } catch (error) {
    return terminalTrustedQuoteResult(failureSidecar({
      context,
      observedAt: decisionTime,
      requestSha256,
      responseSha256: response.responseSha256,
      outcome: "invalid",
      errorCode: protocolErrorCode(error, "MANDATE_BINDING_MISMATCH"),
      gates: {
        ...baseGates(),
        quoteSignature: "pass",
        quotePolicy: "fail",
      },
      envelope,
      verification,
    }), gateData);
  }

  if (
    !quotePolicyAllows(
      context.trust,
      verification,
      mandate,
      decisionTime,
    )
  ) {
    return terminalTrustedQuoteResult(failureSidecar({
      context,
      observedAt: decisionTime,
      requestSha256,
      responseSha256: response.responseSha256,
      outcome: "invalid",
      errorCode: "QUOTE_POLICY_REJECTED",
      gates: {
        ...baseGates(),
        quoteSignature: "pass",
        quotePolicy: "fail",
      },
      envelope,
      verification,
    }), gateData);
  }

  if (
    preReplayCommitConstraint !== undefined &&
    !commitConstraintAllows(preReplayCommitConstraint, decisionTime)
  ) {
    return terminalTrustedQuoteResult(failureSidecar({
      context,
      observedAt: decisionTime,
      requestSha256,
      responseSha256: response.responseSha256,
      outcome: "invalid",
      errorCode: "PREVIEW_GATE_REJECTED",
      gates: {
        ...baseGates(),
        quoteSignature: "pass",
        quotePolicy: "pass",
      },
      envelope,
      verification,
    }), gateData);
  }

  return {
    status: "verified",
    candidate: {
      context,
      mandate,
      envelope: acceptedEnvelope,
      verification,
      binding: finalBinding,
      decisionTime,
      requestSha256,
      responseSha256: response.responseSha256,
      prospectiveReplayKey: computeQuoteReplayKey({
        chainId: context.trust.chainId,
        tokenId: context.trust.tokenId,
        endpointHash: context.quoteEndpointSha256,
        provider: context.trust.expectedProvider,
        commerceContract: context.trust.commerceContract,
        negotiationHash: verification.negotiationHash,
      }),
      ...(gateData === undefined ? {} : { gateData }),
    },
  };
}

function terminalTrustedQuoteResult<T>(
  sidecar: QuoteSidecar,
  gateData?: T,
): TrustedQuoteAttemptResult<T> {
  return {
    status: "terminal",
    sidecar,
    ...(gateData === undefined ? {} : { gateData }),
  };
}

function selectExactlyOne<
  T extends Readonly<{ chainId: number; tokenId: string }>,
>(items: readonly T[], selector: QuoteCandidateSelector): T {
  const matches = items.filter(
    (item) =>
      item.chainId === selector.chainId && item.tokenId === selector.tokenId,
  );
  if (matches.length === 0) {
    throw new QuotePreflightError("CANDIDATE_NOT_FOUND");
  }
  if (matches.length !== 1) {
    throw new QuotePreflightError("CANDIDATE_AMBIGUOUS");
  }
  return matches[0]!;
}

function assertCandidateMatches(
  manifestCandidate: ManifestCandidate,
  passiveCandidate: CandidateReport,
): void {
  if (
    manifestCandidate.chainId !== passiveCandidate.chainId ||
    manifestCandidate.tokenId !== passiveCandidate.tokenId ||
    manifestCandidate.expectedName !== passiveCandidate.expectedName ||
    manifestCandidate.expectedEndpoint !== passiveCandidate.expectedEndpoint ||
    manifestCandidate.expectedOrigin !== passiveCandidate.expectedOrigin ||
    !sameStrings(manifestCandidate.categories, passiveCandidate.categories) ||
    manifestCandidate.provider !== passiveCandidate.provider ||
    manifestCandidate.teamOperatedReference !==
      passiveCandidate.teamOperatedReference
  ) {
    throw new QuotePreflightError("CANDIDATE_MISMATCH");
  }
}

function requireGate(
  candidate: CandidateReport,
  gateName: CandidateReport["gates"][number]["gate"],
  expectedState: CandidateReport["gates"][number]["state"],
): void {
  const gates = candidate.gates.filter((gate) => gate.gate === gateName);
  if (gates.length === 0) {
    throw new QuotePreflightError("PASSIVE_GATE_MISSING");
  }
  if (gates.length !== 1) {
    throw new QuotePreflightError("PASSIVE_GATE_DUPLICATE");
  }
  if (gates[0]!.state !== expectedState) {
    throw new QuotePreflightError(
      gateName === "quote_signature"
        ? "PASSIVE_QUOTE_GATE_NOT_UNKNOWN"
        : "PASSIVE_GATE_NOT_PASSED",
    );
  }
}

function assertFreshTimestamp(
  value: string,
  now: Date,
  maxAgeSeconds: number,
  maxClockSkewSeconds: number,
): void {
  const observedAt = new Date(value).valueOf();
  const nowMs = now.valueOf();
  if (observedAt > nowMs + maxClockSkewSeconds * 1_000) {
    throw new QuotePreflightError("PASSIVE_OBSERVATION_IN_FUTURE");
  }
  if (nowMs - observedAt > maxAgeSeconds * 1_000) {
    throw new QuotePreflightError("PASSIVE_OBSERVATION_STALE");
  }
}

function passiveEvidenceIsFresh(
  context: QuotePreflightContext,
  now: Date,
): boolean {
  const chain = context.passiveCandidate.chain;
  const card = context.passiveCandidate.card;
  if (chain === undefined || card === undefined) return false;
  try {
    assertFreshTimestamp(
      context.passiveReport.generatedAt,
      now,
      context.trust.maxPassiveAgeSeconds,
      context.trust.maxClockSkewSeconds,
    );
    assertFreshTimestamp(
      chain.observedAt,
      now,
      context.trust.maxPassiveAgeSeconds,
      context.trust.maxClockSkewSeconds,
    );
    assertFreshTimestamp(
      card.observedAt,
      now,
      context.trust.maxPassiveAgeSeconds,
      context.trust.maxClockSkewSeconds,
    );
    return true;
  } catch (error) {
    if (error instanceof QuotePreflightError) return false;
    throw error;
  }
}

function mandateTemporalPolicyFailure(
  mandate: QuoteMandatexRebalanceMandate,
  now: Date,
): "MANDATE_INVALID" | "MANDATE_EXPIRED" | undefined {
  const nowMs = now.valueOf();
  const minimumRemainingMs = MIN_QUOTE_REMAINING_SECONDS * 1_000;
  if (
    mandate.expires_at * 1_000 - nowMs < minimumRemainingMs ||
    mandate.permissions.expires_at * 1_000 - nowMs < minimumRemainingMs
  ) {
    return "MANDATE_EXPIRED";
  }

  const estimateAgeSeconds =
    Math.floor(nowMs / 1_000) - mandate.execution_estimate.observed_at;
  if (
    estimateAgeSeconds > mandate.max_evidence_age_seconds ||
    estimateAgeSeconds < -REBALANCE_FUTURE_TOLERANCE_SECONDS
  ) {
    return "MANDATE_INVALID";
  }
  return undefined;
}

function isValidCommitConstraint(
  constraint: TrustedQuotePreReplayCommitConstraint,
): boolean {
  return (
    Number.isSafeInteger(constraint.validUntil) &&
    constraint.validUntil > 0 &&
    Number.isSafeInteger(constraint.minimumRemainingMilliseconds) &&
    constraint.minimumRemainingMilliseconds >= 0
  );
}

function commitConstraintAllows(
  constraint: TrustedQuotePreReplayCommitConstraint,
  decisionTime: Date,
): boolean {
  return (
    BigInt(constraint.validUntil) * 1_000n >=
    BigInt(decisionTime.valueOf()) +
      BigInt(constraint.minimumRemainingMilliseconds)
  );
}

function sameChainProfile(
  profile: RunReport["chainProfile"],
): boolean {
  return (
    profile.name === DEFAULT_CHAIN_PROFILE.name &&
    profile.chainId === DEFAULT_CHAIN_PROFILE.chainId &&
    profile.registryAddress === DEFAULT_CHAIN_PROFILE.registryAddress &&
    profile.rpcOrigin === DEFAULT_CHAIN_PROFILE.rpcOrigin
  );
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return (
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

type SidecarBaseInput = ReturnType<typeof sidecarBase>;

function sidecarBase(
  context: QuotePreflightContext,
  observedAt: Date,
  requestSha256: string,
) {
  return {
    observedAt,
    candidate: {
      chainId: context.trust.chainId,
      tokenId: context.trust.tokenId,
    },
    passiveReportSha256: context.passiveReportSha256,
    passiveCandidateSha256: context.passiveCandidateSha256,
    passivePolicyFingerprint: context.passiveReport.policyFingerprint,
    trustPolicySha256: context.trustPolicySha256,
    quoteEndpoint: context.trust.quoteEndpoint,
    a2aRequestSha256: requestSha256,
    expectedProvider: context.trust.expectedProvider,
    providerKind: context.trust.providerKind,
  } as const;
}

function baseGates(): QuoteValidationGates {
  return {
    passivePreflight: "pass",
    endpointBinding: "pass",
    quoteSignature: "unknown",
    quotePolicy: "unknown",
    replay: "unknown",
  };
}

function failureSidecar(input: Readonly<{
  context: QuotePreflightContext;
  observedAt: Date;
  requestSha256: string;
  responseSha256?: string;
  outcome: "invalid" | "inconclusive";
  errorCode: QuoteProtocolErrorCode;
  replayKey?: string;
  replayStatus?: "duplicate" | "not_attempted";
  gates: QuoteValidationGates;
  envelope?: QuoteEnvelope;
  verification?: VerifiedQuoteEnvelope;
}>): QuoteSidecar {
  const base: SidecarBaseInput = sidecarBase(
    input.context,
    input.observedAt,
    input.requestSha256,
  );
  return buildQuoteSidecar({
    ...base,
    outcome: input.outcome,
    ...(input.responseSha256 === undefined
      ? {}
      : { a2aResponseSha256: input.responseSha256 }),
    ...(input.replayKey === undefined ? {} : { replayKey: input.replayKey }),
    replayStatus: input.replayStatus ?? "not_attempted",
    gates: input.gates,
    errorCode: input.errorCode,
    ...(input.envelope === undefined ? {} : { envelope: input.envelope }),
    ...(input.verification === undefined
      ? {}
      : { verification: input.verification }),
  });
}

function protocolErrorCode(
  error: unknown,
  fallback: QuoteProtocolErrorCode,
): QuoteProtocolErrorCode {
  return error instanceof QuoteProtocolError ? error.code : fallback;
}

function isInconclusiveProtocolCode(code: QuoteProtocolErrorCode): boolean {
  return (
    code === "TRANSPORT_FAILED" ||
    code === "HTTP_STATUS_INVALID" ||
    code === "JSON_RPC_ERROR" ||
    code === "ERC1271_UNAVAILABLE" ||
    code === "PREVIEW_GATE_UNAVAILABLE" ||
    code === "REPLAY_STORE_UNAVAILABLE"
  );
}

function refusalCode(envelope: QuoteEnvelope): string {
  if (envelope.response.accepted) return "QUOTE_REJECTED";
  if (envelope.mandatex !== undefined && "refusal" in envelope.mandatex) {
    return envelope.mandatex.refusal.code;
  }
  return envelope.response.reason_code ?? "QUOTE_REJECTED";
}

function quotePolicyAllows(
  trust: QuoteTrustEntry,
  verification: VerifiedQuoteEnvelope,
  mandate: QuoteMandate,
  now: Date,
): boolean {
  const nowMs = now.valueOf();
  if (
    verification.quoteExpiresAt - verification.negotiatedAt >
      trust.maxQuoteTtlSeconds ||
    verification.negotiatedAt * 1_000 >
      nowMs + trust.maxClockSkewSeconds * 1_000 ||
    verification.quoteExpiresAt * 1_000 - nowMs <
      MIN_QUOTE_REMAINING_SECONDS * 1_000 ||
    BigInt(verification.price) > BigInt(trust.maxPrice) ||
    !trust.allowedCurrencies.includes(verification.currency)
  ) {
    return false;
  }

  const mandateExpiry = trustedMandateExpiry(mandate);
  return mandateExpiry === undefined || verification.quoteExpiresAt <= mandateExpiry;
}

function trustedMandateExpiry(mandate: QuoteMandate): number | undefined {
  const expiries: number[] = [];
  addUnixExpiry(expiries, mandate.expires_at);
  const permissions = mandate.permissions;
  if (isRecord(permissions)) addUnixExpiry(expiries, permissions.expires_at);
  return expiries.length === 0 ? undefined : Math.min(...expiries);
}

function addUnixExpiry(expiries: number[], value: unknown): void {
  if (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) {
    expiries.push(value);
  }
}

function createErc1271Call(
  transport: Pick<PinnedHttpsTransport, "request">,
  randomUUID: () => string,
  blockHash: string,
  expectedChecker: string,
): QuoteErc1271Call {
  return async (input) => {
    if (input.checker.toLowerCase() !== expectedChecker.toLowerCase()) {
      return false;
    }
    const block = { blockHash, requireCanonical: true } as const;
    const code = await quoteRpcResult(
      transport,
      `quote-erc1271-code-${randomUUID()}`,
      "eth_getCode",
      [input.provider, block],
      input.provider,
      blockHash,
    );
    if (typeof code !== "string" || !/^0x(?:[a-fA-F0-9]{2})*$/.test(code)) {
      throw new Error("ERC-1271 code response is invalid");
    }
    if (code === "0x" || /^0x0+$/.test(code)) return false;

    const data = encodeFunctionData({
      abi: ERC1271_ABI,
      functionName: "isValidSignature",
      args: [input.hash, input.signature],
    });
    const id = `quote-erc1271-${randomUUID()}`;
    const result = await quoteRpcResult(
      transport,
      id,
      "eth_call",
      [{ to: input.provider, data }, block],
      input.provider,
      blockHash,
    );
    if (typeof result !== "string") {
      throw new Error("ERC-1271 RPC response is invalid");
    }
    const magic = decodeFunctionResult({
      abi: ERC1271_ABI,
      functionName: "isValidSignature",
      data: result as Hex,
    });
    return magic.toLowerCase() === ERC1271_MAGIC_VALUE;
  };
}

async function quoteRpcResult(
  transport: Pick<PinnedHttpsTransport, "request">,
  id: string,
  method: "eth_getCode" | "eth_call",
  params: readonly unknown[],
  approvedProvider: string,
  approvedBlockHash: string,
): Promise<unknown> {
  const body = JSON.stringify({ jsonrpc: "2.0", id, method, params });
  const response = await transport.request({
    kind: "bsc-quote-rpc",
    method: "POST",
    url: DEFAULT_CHAIN_PROFILE.rpcOrigin,
    rpcMethod: method,
    approvedProvider,
    approvedBlockHash,
    body,
  });
  if (response.status !== 200) throw new Error("ERC-1271 RPC unavailable");
  const parsed = parseJsonResponse(response);
  if (
    !isRecord(parsed) ||
    parsed.jsonrpc !== "2.0" ||
    parsed.id !== id ||
    !("result" in parsed) ||
    "error" in parsed
  ) {
    throw new Error("ERC-1271 RPC response is invalid");
  }
  return parsed.result;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const ERC1271_MAGIC_VALUE = "0x1626ba7e";
const ERC1271_ABI = [
  {
    type: "function",
    name: "isValidSignature",
    stateMutability: "view",
    inputs: [
      { name: "hash", type: "bytes32" },
      { name: "signature", type: "bytes" },
    ],
    outputs: [{ name: "magicValue", type: "bytes4" }],
  },
] as const;

function publicPreflightMessage(code: QuotePreflightErrorCode): string {
  switch (code) {
    case "CANDIDATE_NOT_FOUND":
    case "CANDIDATE_AMBIGUOUS":
      return "the selected quote candidate is not uniquely configured";
    case "PASSIVE_POLICY_MISMATCH":
    case "CHAIN_PROFILE_MISMATCH":
      return "the passive report does not use the current verifier policy";
    case "PASSIVE_OBSERVATION_STALE":
    case "PASSIVE_OBSERVATION_IN_FUTURE":
      return "the passive evidence is outside the trusted freshness window";
    case "CARD_ENDPOINT_MISMATCH":
    case "QUOTE_ENDPOINT_MISMATCH":
      return "the active quote endpoint does not match trusted policy";
    case "TRUSTED_PROVIDER_CONFLICT":
      return "the trusted quote provider conflicts with passive discovery evidence";
    case "TRUSTED_REGISTRY_CONFLICT":
      return "the trusted ERC-8004 registry conflicts with the configured BSC registry";
    case "TRUSTED_CATEGORY_CONFLICT":
      return "the trusted quote category conflicts with the selected candidate";
    case "MANDATE_INVALID":
      return "the quote mandate is invalid";
    case "MANDATE_EXPIRED":
      return "the quote mandate or its permissions expire too soon";
    case "PREVIEW_INPUT_UNSUPPORTED":
      return "the transaction preview requires the trusted EOA provider as caller";
    case "REPLAY_STORE_UNAVAILABLE":
      return "the replay store is unavailable";
    default:
      return "the selected candidate did not pass trusted quote preflight";
  }
}
