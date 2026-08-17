import { createHash } from "node:crypto";
import { deflateRawSync } from "node:zlib";

import {
  encodeAbiParameters,
  encodeFunctionResult,
  parseAbiParameters,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  BSC_PANCAKE_V3,
  DEFAULT_CHAIN_PROFILE,
  POLICY_FINGERPRINT,
  QUOTE_TRUST_SCHEMA,
  buildReport,
  canonicalQuoteJson,
  computeQuoteNegotiationHash,
  computeQuoteRequestHash,
  computeQuoteResponseHash,
  computeQuoteSha256,
  manifestFileSchema,
  previewCollectAbi,
  previewDecreaseLiquidityAbi,
  previewMintAbi,
  previewMulticallAbi,
  quoteMandatexSignedRebalanceTaskSchema,
  quoteTrustFileSchema,
  serializeQuoteTrustFile,
  validateTransportRoute,
  validateTrustedPreviewForMarketplaceEvaluation,
  type BoundedHttpResponse,
  type CandidateReportInput,
  type GateResult,
  type PancakeStateResult,
  type QuoteAcceptedEnvelope,
  type TransportRoute,
  type TrustedPreviewMarketplaceEvaluationSuccess,
} from "@mandatex/agent-supply-verifier";

import { marketplaceVerifierPolicySha256 } from "../src/issuer.js";
import type { MarketplaceVerifierInvocation } from "../src/runtime.js";
import {
  marketplaceEvaluationRequestSchema,
  type MarketplaceEvaluationRequest,
} from "../src/schema.js";
import {
  CURRENCY,
  ISSUED_AT,
  POOL,
  POSITION_MANAGER,
  PROVIDER,
  TOKEN0,
  TOKEN1,
  fixtureRequest,
  fixtureSuccess,
} from "./fixture.js";

const TEST_PRIVATE_KEY = `0x${"11".repeat(32)}` as const;
const TEST_ACCOUNT = privateKeyToAccount(TEST_PRIVATE_KEY);
const BLOCK_HASH = `0x${"a".repeat(64)}`;
const CODE_HASH = "b".repeat(64);
const RESPONSE_HASH = "c".repeat(64);
const SIGNED_BLOCK_HASH = `0x${"d".repeat(64)}`;
const FRESH_BLOCK_HASH = `0x${"f".repeat(64)}`;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

export const DEFAULT_SIGNED_BLOCK_HASH = SIGNED_BLOCK_HASH;
export const DEFAULT_FRESH_BLOCK_HASH = FRESH_BLOCK_HASH;

export interface BrandedVerifierFixture {
  readonly request: MarketplaceEvaluationRequest;
  readonly result: TrustedPreviewMarketplaceEvaluationSuccess;
  readonly verifier: MarketplaceVerifierInvocation;
  readonly verifierPolicySha256: string;
}

export interface DefaultRuntimeFixture {
  readonly request: MarketplaceEvaluationRequest;
  readonly verifier: MarketplaceVerifierInvocation;
  readonly verifierPolicySha256: string;
  readonly routes: readonly TransportRoute[];
}

export function decimalUnicodeRequest(): MarketplaceEvaluationRequest {
  const request = fixtureRequest();
  return marketplaceEvaluationRequestSchema.parse({
    ...request,
    mandate: {
      ...request.mandate,
      limits: {
        ...request.mandate.limits,
        max_gas_usd: 10.75,
        max_exposure_usd: 1_000.5,
      },
      execution_estimate: {
        ...request.mandate.execution_estimate,
        gas_usd: 5.5,
        exposure_usd: 500.25,
      },
      permissions: {
        ...request.mandate.permissions,
        spend_cap_usd: 500.25,
      },
    },
  });
}

export function verifierInvocationFixture(
  transport: MarketplaceVerifierInvocation["transport"],
): MarketplaceVerifierInvocation {
  const manifest = manifestFileSchema.parse({
    version: 1,
    candidates: [
      {
        chainId: 56,
        tokenId: "1",
        expectedName: "agent candidate",
        expectedEndpoint:
          "https://agent.example/.well-known/agent-card.json",
        expectedOrigin: "https://agent.example",
        categories: ["rebalancing"],
        source: "8004scan",
      },
    ],
  });
  const passiveReport = buildReport({
    generatedAt: new Date((ISSUED_AT - 15) * 1_000).toISOString(),
    chainProfile: DEFAULT_CHAIN_PROFILE,
    policyFingerprint: POLICY_FINGERPRINT,
    candidates: [selectedReportCandidate()],
  });
  const trustFile = quoteTrustFileSchema.parse({
    schema: QUOTE_TRUST_SCHEMA,
    candidates: [
      {
        chainId: 56,
        registryAddress: DEFAULT_CHAIN_PROFILE.registryAddress,
        tokenId: "1",
        category: "rebalancing",
        cardUrl: "https://agent.example/.well-known/agent-card.json",
        quoteEndpoint: "https://agent.example/",
        expectedProvider: PROVIDER,
        providerKind: "eoa",
        commerceContract: CURRENCY,
        protocol: {
          a2a: "0.3.x",
          method: "message/send",
          skill: "negotiate",
          signature: "eip191-negotiation-hash-string",
          signedTaskCodec: "mandatex-rebalance:v1",
        },
        maxPassiveAgeSeconds: 300,
        maxQuoteTtlSeconds: 900,
        maxClockSkewSeconds: 30,
        allowedCurrencies: [CURRENCY],
        maxPrice: "0",
      },
    ],
  });
  return {
    manifest,
    passiveReport,
    trustFile,
    transport,
    now: () => new Date(ISSUED_AT * 1_000),
    randomUUID: () => "quote-id-1",
  };
}

export function verifierPolicySha256ForInvocation(
  verifier: MarketplaceVerifierInvocation,
): string {
  return marketplaceVerifierPolicySha256({
    passivePolicyFingerprint: verifier.passiveReport.policyFingerprint,
    trustPolicySha256: computeQuoteSha256(
      serializeQuoteTrustFile(verifier.trustFile),
    ),
  });
}

export async function brandedVerifierFixture(): Promise<BrandedVerifierFixture> {
  const request = decimalUnicodeRequest();
  const envelope = await signedEnvelope(request);
  const verifier = verifierInvocationFixture(
    quoteTransport((requestId) => successA2aResponse(requestId, envelope)),
  );
  const synthetic = fixtureSuccess(request);
  const result = await validateTrustedPreviewForMarketplaceEvaluation(
    {
      ...verifier,
      mandate: request.mandate,
      candidate: request.candidate.selector,
      transactionPlan: request.candidate.transactionPlan,
    },
    {
      stateVerifier: async (options): Promise<PancakeStateResult> => ({
        status: "verified",
        snapshot:
          options.target?.mode === "exact"
            ? synthetic.signedSnapshot
            : synthetic.preview.snapshot,
      }),
      simulate: async () => ({
        rawResult: previewSimulationResult(),
        requestSha256: "d".repeat(64),
        responseSha256: "e".repeat(64),
      }),
      assertCanonical: async () => undefined,
    },
  );
  if (result.outcome !== "verified_unreserved") {
    throw new Error(
      `expected branded verifier success, got ${JSON.stringify(result)}`,
    );
  }
  return {
    request,
    result,
    verifier,
    verifierPolicySha256: verifierPolicySha256ForInvocation(verifier),
  };
}

export async function defaultRuntimeFixture(): Promise<DefaultRuntimeFixture> {
  const request = decimalUnicodeRequest();
  const envelope = await signedEnvelope(request);
  const routes: TransportRoute[] = [];
  const verifier = verifierInvocationFixture(
    defaultPathTransport(routes, envelope),
  );
  return {
    request,
    verifier,
    verifierPolicySha256: verifierPolicySha256ForInvocation(verifier),
    routes,
  };
}

async function signedEnvelope(
  request: MarketplaceEvaluationRequest,
): Promise<QuoteAcceptedEnvelope> {
  const synthetic = fixtureSuccess(request);
  const signedTask = {
    ...synthetic.signedTask,
    proposal: {
      ...synthetic.signedTask.proposal,
      estimated_gas_usd: 5.5,
      estimated_exposure_usd: 500.25,
      permissions: {
        ...synthetic.signedTask.proposal.permissions,
        calls: [
          "decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
          "collect((uint256,address,uint128,uint128))",
          "mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))",
        ],
        spend_cap_usd: 500.25,
      },
      break_even: {
        status: "not_calculated" as const,
        reason: "Reputation unavailable; caf\u00e9 evidence is not inferred.",
      },
    },
  };
  const parsedSignedTask =
    quoteMandatexSignedRebalanceTaskSchema.parse(signedTask);
  if (
    canonicalQuoteJson(parsedSignedTask.mandate) !==
    canonicalQuoteJson(request.mandate)
  ) {
    throw new Error("signed task fixture mandate diverges before encoding");
  }
  const taskDescription = `mandatex-rebalance:v1:${deflateRawSync(
    Buffer.from(canonicalQuoteJson(parsedSignedTask), "utf8"),
  ).toString("base64url")}`;
  const quoteRequest = {
    task_description: taskDescription,
    terms: {
      deliverables: "rebalance position",
      quality_standards: "match the signed mandate for the caf\u00e9 pool",
      evaluation_required: true,
      evaluator_type: "uma_oov3",
      success_criteria: ["position is rebalanced"],
    },
  };
  const response = {
    accepted: true as const,
    terms: {
      ...quoteRequest.terms,
      price: "0",
      currency: CURRENCY,
    },
    estimated_completion_seconds: 300,
    quote_expires_at: ISSUED_AT + 600,
    negotiated_at: ISSUED_AT,
  };
  let envelope: QuoteAcceptedEnvelope = {
    request: quoteRequest,
    request_hash: computeQuoteRequestHash(quoteRequest),
    response,
    response_hash: computeQuoteResponseHash(response),
    negotiation_hash: `0x${"0".repeat(64)}`,
    provider_sig: "0x00",
    chain_id: 56,
    verifying_contract: CURRENCY,
  };
  envelope = {
    ...envelope,
    negotiation_hash: computeQuoteNegotiationHash(envelope),
  };
  return {
    ...envelope,
    provider_sig: await TEST_ACCOUNT.signMessage({
      message: envelope.negotiation_hash,
    }),
  };
}

function selectedReportCandidate(): CandidateReportInput {
  return {
    chainId: 56,
    tokenId: "1",
    expectedName: "agent candidate",
    expectedEndpoint: "https://agent.example/.well-known/agent-card.json",
    expectedOrigin: "https://agent.example",
    categories: ["rebalancing"],
    status: "REGISTERED_ONLY",
    gates: [
      passGate("manifest_identity", "claimed", "manifest.candidate"),
      passGate("bsc_chain", "verified", "chain.owner-of"),
      passGate("token_ownership", "verified", "chain.owner-of"),
      passGate("endpoint_origin", "claimed", "manifest.candidate"),
      passGate("endpoint_health", "detected", "card.http"),
      passGate("task_interface", "detected", "card.http"),
      {
        gate: "quote_signature",
        state: "unknown",
        evidence: [],
        evidenceRefs: [],
      },
    ],
    chain: {
      chainId: 56,
      registryAddress: DEFAULT_CHAIN_PROFILE.registryAddress,
      tokenId: "1",
      owner: PROVIDER,
      observedBlock: 100,
      observedBlockHash: BLOCK_HASH,
      confirmationDepth: 2,
      registryCodeHash: CODE_HASH,
      observedAt: new Date((ISSUED_AT - 30) * 1_000).toISOString(),
      responseHash: RESPONSE_HASH,
    },
    card: {
      url: "https://agent.example/",
      observedAt: new Date((ISSUED_AT - 25) * 1_000).toISOString(),
      responseHash: RESPONSE_HASH,
      protocolVersion: "0.3.0",
      preferredTransport: "JSONRPC",
      skills: [
        {
          id: "negotiate",
          name: "Negotiate",
          description: "Return a signed quote.",
          tags: ["erc8183"],
          inputModes: ["application/json"],
          outputModes: ["application/json"],
        },
      ],
      inputModes: ["application/json"],
      outputModes: ["application/json"],
    },
    scan: {
      indexed: true,
      observedAt: new Date((ISSUED_AT - 35) * 1_000).toISOString(),
      agentWallet: PROVIDER,
    },
  };
}

function passGate(
  gate: GateResult["gate"],
  evidence: "claimed" | "detected" | "verified",
  evidenceRef: string,
): GateResult {
  return {
    gate,
    state: "pass" as const,
    evidence: [evidence],
    evidenceRefs: [evidenceRef],
  };
}

function successA2aResponse(
  requestId: string,
  envelope: QuoteAcceptedEnvelope,
): unknown {
  return {
    jsonrpc: "2.0",
    id: requestId,
    result: {
      kind: "message",
      role: "agent",
      messageId: "server-message",
      parts: [{ kind: "data", data: envelope }],
    },
  };
}

function quoteTransport(
  respond: (requestId: string) => unknown,
): MarketplaceVerifierInvocation["transport"] {
  return {
    async request(route: TransportRoute): Promise<BoundedHttpResponse> {
      if (route.kind !== "a2a-quote") {
        throw new Error(`unexpected route ${route.kind}`);
      }
      const request = JSON.parse(route.body) as { id: string };
      return boundedJsonResponse(respond(request.id));
    },
  };
}

function defaultPathTransport(
  routes: TransportRoute[],
  envelope: QuoteAcceptedEnvelope,
): MarketplaceVerifierInvocation["transport"] {
  return {
    async request(route: TransportRoute): Promise<BoundedHttpResponse> {
      validateTransportRoute(route);
      routes.push(route);
      if (route.kind === "a2a-quote") {
        const request = JSON.parse(route.body) as { id: string };
        return boundedJsonResponse(successA2aResponse(request.id, envelope));
      }
      if (route.kind !== "bsc-preview-rpc") {
        throw new Error(`unexpected default-path route ${route.kind}`);
      }

      const request = JSON.parse(route.body) as {
        id: string;
        method: string;
        params: unknown[];
      };
      return boundedJsonResponse({
        jsonrpc: "2.0",
        id: request.id,
        result: previewRpcResult(route.purpose, request),
      });
    },
  };
}

function previewRpcResult(
  purpose: Extract<TransportRoute, { kind: "bsc-preview-rpc" }>["purpose"],
  request: { readonly method: string; readonly params: readonly unknown[] },
): unknown {
  switch (purpose) {
    case "chain-id":
      return "0x38";
    case "head-block-number":
      return "0x69";
    case "block-header":
      return blockHeader(request.params[0]);
    case "contract-code":
      return request.params[0] === PROVIDER ? "0x" : "0x60006000";
    case "state-read":
      return stateReadResult(request);
    case "simulation":
      return previewSimulationResult();
  }
}

function blockHeader(blockNumber: unknown): unknown {
  if (blockNumber === "0x64") {
    return {
      number: blockNumber,
      hash: SIGNED_BLOCK_HASH,
      timestamp: `0x${(ISSUED_AT - 20).toString(16)}`,
    };
  }
  if (blockNumber === "0x67") {
    return {
      number: blockNumber,
      hash: FRESH_BLOCK_HASH,
      timestamp: `0x${ISSUED_AT.toString(16)}`,
    };
  }
  throw new Error(`unexpected preview block ${String(blockNumber)}`);
}

function stateReadResult(request: {
  readonly method: string;
  readonly params: readonly unknown[];
}): Hex {
  if (request.method !== "eth_call") {
    throw new Error(`unexpected state-read method ${request.method}`);
  }
  const call = request.params[0] as { readonly to: string; readonly data: string };
  const selector = call.data.slice(0, 10);
  const target = call.to.toLowerCase();
  const blockSelector = request.params[1] as { readonly blockHash?: unknown };
  const currentTick = blockSelector.blockHash === FRESH_BLOCK_HASH ? 96 : 95;

  switch (selector) {
    case "0x6352211e":
      return encode("address", [PROVIDER]);
    case "0x081812fc":
      return encode("address", [ZERO_ADDRESS]);
    case "0xe985e9c5":
      return encode("bool", [false]);
    case "0xc45a0155":
      return encode("address", [BSC_PANCAKE_V3.factory]);
    case "0xd5f39488":
      return encode("address", [BSC_PANCAKE_V3.deployer]);
    case "0x99fbab88":
      return encode(
        "uint96,address,address,address,uint24,int24,int24,uint128,uint256,uint256,uint128,uint128",
        [
          0n,
          ZERO_ADDRESS,
          TOKEN0,
          TOKEN1,
          500,
          -100,
          100,
          1_000n,
          0n,
          0n,
          0n,
          0n,
        ],
      );
    case "0x3850c7bd":
      return encode("uint160,int24,uint16,uint16,uint16,uint32,bool", [
        79_228_162_514_264_337_593_543_950_336n,
        currentTick,
        1,
        2,
        3,
        0,
        true,
      ]);
    case "0x1a686502":
      return encode("uint128", [1_000_000n]);
    case "0x0dfe1681":
      return encode("address", [TOKEN0]);
    case "0xd21220a7":
      return encode("address", [TOKEN1]);
    case "0xddca3f43":
      return encode("uint24", [500]);
    case "0xd0c93a7c":
      return encode("int24", [10]);
    case "0x1698ee82":
      return encode("address", [POOL]);
    case "0x22afcccb":
      return encode("int24", [10]);
    case "0x313ce567":
      return encode("uint8", [18]);
    case "0x70a08231":
    case "0xdd62ed3e":
      return encode("uint256", [10_000n]);
    default:
      throw new Error(`unexpected state-read selector ${selector} for ${target}`);
  }
}

function encode(types: string, values: readonly unknown[]): Hex {
  return encodeAbiParameters(parseAbiParameters(types), values as never);
}

function boundedJsonResponse(value: unknown): BoundedHttpResponse {
  const body = Buffer.from(JSON.stringify(value));
  return {
    status: 200,
    contentType: "application/json",
    retryAfter: null,
    rateLimitRemaining: null,
    body,
    responseSha256: createHash("sha256").update(body).digest("hex"),
    resolvedAddress: "93.184.216.34",
    startedAt: new Date(ISSUED_AT * 1_000).toISOString(),
    finishedAt: new Date(ISSUED_AT * 1_000 + 10).toISOString(),
    latencyMs: 10,
  };
}

function previewSimulationResult(): Hex {
  const decrease = encodeFunctionResult({
    abi: previewDecreaseLiquidityAbi,
    functionName: "decreaseLiquidity",
    result: [900n, 1_800n],
  });
  const collect = encodeFunctionResult({
    abi: previewCollectAbi,
    functionName: "collect",
    result: [1_000n, 2_000n],
  });
  const mint = encodeFunctionResult({
    abi: previewMintAbi,
    functionName: "mint",
    result: [10n, 500n, 1_000n, 2_000n],
  });
  return encodeFunctionResult({
    abi: previewMulticallAbi,
    functionName: "multicall",
    result: [decrease, collect, mint],
  });
}
