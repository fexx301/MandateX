import { createHash } from "node:crypto";
import { isIP } from "node:net";

import {
  hashMessage,
  keccak256,
  recoverMessageAddress,
  stringToBytes,
  type Hex,
} from "viem";
import { z } from "zod";

import { canonicalQuoteJson } from "../quotes/protocol.js";
import {
  parseJsonResponse,
  type BoundedHttpResponse,
  type TransportRoute,
} from "../transport/http.js";
import {
  CATEGORY_CANDIDATE_IDENTITY_PROFILE,
  type CategoryCandidateIdentityCapability,
  type VerifiedCategoryCandidateIdentity,
} from "./identity.js";

export const CATEGORY_QUOTE_CHALLENGE_SCHEMA =
  "mandatex.agent-supply.category-quote-challenge.v1" as const;
export const CATEGORY_QUOTE_RESPONSE_SCHEMA =
  "mandatex.agent-supply.category-quote-response.v1" as const;
export const CATEGORY_QUOTE_ENVELOPE_SCHEMA =
  "mandatex.agent-supply.category-quote-envelope.v1" as const;
export const CATEGORY_QUOTE_SIGNED_CONTENT_SCHEMA =
  "mandatex.agent-supply.category-quote-signed-content.v1" as const;
export const CATEGORY_QUOTE_VERIFICATION_PROFILE =
  "mandatex.agent-supply.category-quote-verification.v1" as const;
export const CATEGORY_QUOTE_AUDIENCE =
  "mandatex-category-quote-verifier" as const;
export const CATEGORY_QUOTE_SIGNING_DOMAIN =
  "MandateX Category Quote v1" as const;
export const CATEGORY_QUOTE_EIP191_PREFIX =
  "MandateX Category Quote v1\n" as const;
export const MAX_CATEGORY_QUOTE_TTL_SECONDS = 300 as const;
export const MAX_CATEGORY_IDENTITY_AGE_SECONDS = 300 as const;

const sha256Schema = z.string().regex(/^[a-f0-9]{64}$/);
const bytes32Schema = z.string().regex(/^0x[a-f0-9]{64}$/);
const canonicalHexSchema = z
  .string()
  .regex(/^0x(?:[a-f0-9]{2})+$/)
  .max(8_194);
const eoaSignatureSchema = z.string().regex(/^0x[a-f0-9]{130}$/);
const addressSchema = z
  .string()
  .regex(/^0x[a-f0-9]{40}$/)
  .refine((value) => !/^0x0{40}$/.test(value), "zero address is invalid");
const identifierSchema = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/);
const uint256DecimalSchema = z
  .string()
  .regex(/^(?:0|[1-9][0-9]*)$/)
  .refine((value) => BigInt(value) < 1n << 256n, "outside uint256");
const unixSecondsSchema = z
  .number()
  .int()
  .positive()
  .max(Number.MAX_SAFE_INTEGER);
const providerKindSchema = z.enum(["eoa", "erc1271"]);

const candidateSchema = z
  .object({ chainId: z.literal(56), tokenId: uint256DecimalSchema })
  .strict();

export const CATEGORY_QUOTE_A2A_REQUEST_SCHEMA =
  "mandatex.agent-supply.category-quote-a2a-request.v1" as const;

const categoryQuoteA2aRequestSchema = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: identifierSchema,
    method: z.literal("message/send"),
    params: z
      .object({
        message: z
          .object({
            kind: z.literal("message"),
            messageId: identifierSchema,
            role: z.literal("user"),
            parts: z
              .tuple([
                z
                  .object({
                    kind: z.literal("data"),
                    data: z
                      .object({
                        challenge: z.unknown(),
                        skill: z.literal("negotiate"),
                      })
                      .strict(),
                  })
                  .strict(),
              ])
              .rest(z.never()),
          })
          .strict(),
      })
      .strict(),
  })
  .strict();

const categoryQuoteA2aResponseSchema = z
  .object({
    jsonrpc: z.literal("2.0"),
    id: identifierSchema,
    result: z
      .object({
        kind: z.literal("message"),
        messageId: identifierSchema,
        role: z.literal("agent"),
        parts: z
          .tuple([
            z
              .object({ kind: z.literal("data"), data: z.unknown() })
              .strict(),
          ])
          .rest(z.never()),
      })
      .strict(),
  })
  .strict();


const expectedRequestSchema = z
  .object({
    requestId: identifierSchema,
    mandateSha256: sha256Schema,
    categoryQuoteRequestSha256: sha256Schema,
    candidate: candidateSchema,
    category: z.enum(["grid", "yield", "health"]),
    adapterId: z.enum([
      "pancakeswap-v3-grid-v1",
      "erc4626-yield-v1",
      "aave-v3-health-v1",
      "venus-health-v1",
    ]),
    protocol: identifierSchema,
    serviceMode: z.enum(["observe_only", "transactional"]),
    subjectSha256: sha256Schema,
    conditionPolicySha256: sha256Schema,
    actionPermissionsSha256: sha256Schema,
    maxSpendUsdMicros: uint256DecimalSchema,
    permissionsExpiresAt: unixSecondsSchema,
    quoteEndpointSha256: sha256Schema,
    nonce: identifierSchema,
    issuedAt: unixSecondsSchema,
    expiresAt: unixSecondsSchema,
    maxClockSkewSeconds: z.number().int().min(0).max(300),
  })
  .strict()
  .superRefine((request, context) => {
    if (request.issuedAt >= request.expiresAt) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["expiresAt"],
        message: "expected request expiry must follow issuance",
      });
    }
    if (
      request.permissionsExpiresAt <= request.issuedAt ||
      request.permissionsExpiresAt > request.expiresAt
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["permissionsExpiresAt"],
        message: "expected request permission expiry is invalid",
      });
    }
    if (
      (request.category === "grid" && request.adapterId !== "pancakeswap-v3-grid-v1") ||
      (request.category === "yield" && request.adapterId !== "erc4626-yield-v1") ||
      (request.category === "health" &&
        request.adapterId !== "aave-v3-health-v1" &&
        request.adapterId !== "venus-health-v1")
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["adapterId"],
        message: "expected request adapter does not belong to its category",
      });
    }
  });

const EMPTY_ACTION_PERMISSIONS_SHA256 = sha256Canonical([]);

export const categoryQuoteChallengeSchema = z
  .object({
    schema: z.literal(CATEGORY_QUOTE_CHALLENGE_SCHEMA),
    verificationProfile: z.literal(CATEGORY_QUOTE_VERIFICATION_PROFILE),
    audience: z.literal(CATEGORY_QUOTE_AUDIENCE),
    signingDomain: z.literal(CATEGORY_QUOTE_SIGNING_DOMAIN),
    chainId: z.literal(56),
    verifyingContract: addressSchema,
    scope: z.literal("evaluation_only"),
    activationAuthorization: z.literal("none"),
    reservation: z.literal("none"),
    replayPolicy: z.literal("reusable_until_expiry"),
    relation: z.literal("candidate_accepts_service_for_subject"),
    providerAuthority: z.literal("erc8004_registered_owner"),
    requestId: identifierSchema,
    mandateSha256: sha256Schema,
    categoryQuoteRequestSha256: sha256Schema,
    candidate: candidateSchema,
    identityVerificationProfile: z.literal(
      CATEGORY_CANDIDATE_IDENTITY_PROFILE,
    ),
    candidateIdentitySha256: sha256Schema,
    registryAddress: addressSchema,
    registryCodeSha256: sha256Schema,
    registeredOwner: addressSchema,
    providerKind: providerKindSchema,
    providerCodeSha256: sha256Schema,
    category: z.enum(["grid", "yield", "health"]),
    adapterId: identifierSchema,
    protocol: identifierSchema,
    serviceMode: z.enum(["observe_only", "transactional"]),
    subjectSha256: sha256Schema,
    conditionPolicySha256: sha256Schema,
    actionPermissionsSha256: sha256Schema,
    maxSpendUsdMicros: uint256DecimalSchema,
    permissionsExpiresAt: unixSecondsSchema,
    quoteEndpointSha256: sha256Schema,
    nonce: identifierSchema,
    issuedAt: unixSecondsSchema,
    expiresAt: unixSecondsSchema,
    maxClockSkewSeconds: z.number().int().min(0).max(300),
  })
  .strict()
  .superRefine((challenge, context) => {
    if (challenge.candidate.chainId !== challenge.chainId) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["candidate", "chainId"],
        message: "candidate chain must match the quote trust domain",
      });
    }
    if (
      challenge.expiresAt <= challenge.issuedAt ||
      challenge.expiresAt - challenge.issuedAt >
        MAX_CATEGORY_QUOTE_TTL_SECONDS
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["expiresAt"],
        message: "category quote challenge lifetime is invalid",
      });
    }
    if (
      challenge.permissionsExpiresAt <= challenge.issuedAt ||
      challenge.permissionsExpiresAt > challenge.expiresAt
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["permissionsExpiresAt"],
        message: "category quote permission expiry is invalid",
      });
    }
    if (
      challenge.serviceMode === "observe_only" &&
      (challenge.maxSpendUsdMicros !== "0" ||
        challenge.actionPermissionsSha256 !==
          EMPTY_ACTION_PERMISSIONS_SHA256)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["serviceMode"],
        message: "observe-only quotes cannot bind spend or action authority",
      });
    }
    if (
      challenge.serviceMode === "transactional" &&
      challenge.actionPermissionsSha256 === EMPTY_ACTION_PERMISSIONS_SHA256
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["actionPermissionsSha256"],
        message: "transactional quotes require explicit action permissions",
      });
    }
  });

export const categoryQuoteResponseSchema = z
  .object({
    schema: z.literal(CATEGORY_QUOTE_RESPONSE_SCHEMA),
    accepted: z.literal(true),
    relation: z.literal("candidate_accepts_service_for_subject"),
    providerAuthority: z.literal("erc8004_registered_owner"),
    providerAddress: addressSchema,
    providerKind: providerKindSchema,
    requestKeccak256: bytes32Schema,
    negotiatedAt: unixSecondsSchema,
    quoteExpiresAt: unixSecondsSchema,
  })
  .strict()
  .superRefine((response, context) => {
    if (response.quoteExpiresAt <= response.negotiatedAt) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["quoteExpiresAt"],
        message: "category quote expiry must follow negotiation",
      });
    }
  });

export const categoryQuoteEnvelopeSchema = z
  .object({
    schema: z.literal(CATEGORY_QUOTE_ENVELOPE_SCHEMA),
    challenge: categoryQuoteChallengeSchema,
    response: categoryQuoteResponseSchema,
    requestKeccak256: bytes32Schema,
    responseKeccak256: bytes32Schema,
    negotiationKeccak256: bytes32Schema,
    providerSignature: canonicalHexSchema,
  })
  .strict();

export const categoryQuoteSignedContentSchema = z
  .object({
    schema: z.literal(CATEGORY_QUOTE_SIGNED_CONTENT_SCHEMA),
    signingDomain: z.literal(CATEGORY_QUOTE_SIGNING_DOMAIN),
    audience: z.literal(CATEGORY_QUOTE_AUDIENCE),
    chainId: z.literal(56),
    verifyingContract: addressSchema,
    challenge: categoryQuoteChallengeSchema,
    response: categoryQuoteResponseSchema,
    requestKeccak256: bytes32Schema,
    responseKeccak256: bytes32Schema,
  })
  .strict()
  .superRefine((content, context) => {
    if (
      content.challenge.signingDomain !== content.signingDomain ||
      content.challenge.audience !== content.audience ||
      content.challenge.chainId !== content.chainId ||
      content.challenge.verifyingContract !== content.verifyingContract
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["challenge"],
        message: "signed-content trust domain does not match the challenge",
      });
    }
    if (content.response.requestKeccak256 !== content.requestKeccak256) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["response", "requestKeccak256"],
        message: "signed response does not bind the signed request",
      });
    }
  });

export type CategoryQuoteChallenge = Readonly<
  z.infer<typeof categoryQuoteChallengeSchema>
>;
export type CategoryQuoteResponse = Readonly<
  z.infer<typeof categoryQuoteResponseSchema>
>;
export type CategoryQuoteEnvelope = Readonly<
  z.infer<typeof categoryQuoteEnvelopeSchema>
>;
export type CategoryQuoteExpectedRequest = Readonly<
  z.infer<typeof expectedRequestSchema>
>;

export type CategoryQuoteA2aRequest = Readonly<
  z.infer<typeof categoryQuoteA2aRequestSchema>
>;

export interface CategoryQuoteFetchCapability {
  readonly endpoint: string;
  readonly endpointSha256: string;
  readonly fetch: (challenge: unknown) => Promise<CategoryQuoteEnvelope>;
}

/** Build the exact category negotiation request sent to the pinned endpoint. */
export function buildCategoryQuoteA2aRequest(input: {
  readonly rpcId: string;
  readonly messageId: string;
  readonly challenge: unknown;
}): CategoryQuoteA2aRequest {
  assertExactDataObject(input, ["challenge", "messageId", "rpcId"], "category quote A2A input");
  const rpcId = identifierSchema.parse(readDataProperty(input, "rpcId"));
  const messageId = identifierSchema.parse(readDataProperty(input, "messageId"));
  const challenge = parseCanonicalChallenge(readDataProperty(input, "challenge"));
  return deepFreeze(
    categoryQuoteA2aRequestSchema.parse({
      jsonrpc: "2.0",
      id: rpcId,
      method: "message/send",
      params: {
        message: {
          kind: "message",
          messageId,
          role: "user",
          parts: [{ kind: "data", data: { challenge, skill: "negotiate" } }],
        },
      },
    }),
  );
}

export function serializeCategoryQuoteA2aRequest(
  input: unknown,
): string {
  return canonicalQuoteJson(categoryQuoteA2aRequestSchema.parse(input));
}

export function parseCategoryQuoteA2aResponse(
  value: unknown,
  options: { readonly expectedRpcId?: string } = {},
): CategoryQuoteEnvelope {
  let parsedValue = value;
  if (typeof value === "string") {
    try {
      parsedValue = JSON.parse(value) as unknown;
    } catch (cause) {
      throw new TypeError("category quote A2A response is not valid JSON", {
        cause,
      });
    }
  }
  const parsed = categoryQuoteA2aResponseSchema.parse(parsedValue);
  if (options.expectedRpcId !== undefined && parsed.id !== options.expectedRpcId) {
    throw new Error("category quote A2A response ID does not match the request");
  }
  return parseCanonicalEnvelope(parsed.result.parts[0]!.data);
}

/**
 * Service-owned quote transport. The endpoint and transport are captured at
 * construction; callers can provide a challenge, but cannot supply an
 * envelope or redirect the request to another origin.
 */
export function createCategoryQuoteFetchCapability(options: {
  readonly endpoint: string;
  readonly transport: {
    readonly request: (route: TransportRoute) => Promise<BoundedHttpResponse>;
  };
  readonly randomUUID: () => string;
}): CategoryQuoteFetchCapability {
  assertExactDataObject(options, ["endpoint", "randomUUID", "transport"], "category quote fetch options");
  const endpoint = parseCategoryQuoteEndpoint(readDataProperty(options, "endpoint"));
  const transport = readDataProperty(options, "transport") as {
    readonly request: (route: TransportRoute) => Promise<BoundedHttpResponse>;
  };
  const randomUUID = readDataProperty(options, "randomUUID");
  if (typeof transport?.request !== "function" || typeof randomUUID !== "function") {
    throw new TypeError("category quote fetch transport and UUID source are invalid");
  }
  const request = transport.request;
  const endpointSha256 = createHash("sha256").update(endpoint, "utf8").digest("hex");
  const capability = Object.freeze({
    endpoint,
    endpointSha256,
    async fetch(challengeInput: unknown): Promise<CategoryQuoteEnvelope> {
      const challenge = parseCanonicalChallenge(challengeInput);
      if (challenge.quoteEndpointSha256 !== endpointSha256) {
        throw new Error("category quote challenge is bound to another endpoint");
      }
      const rpcId = identifierSchema.parse(String(randomUUID()));
      const messageId = identifierSchema.parse(String(randomUUID()));
      const a2a = buildCategoryQuoteA2aRequest({ rpcId, messageId, challenge });
      const body = serializeCategoryQuoteA2aRequest(a2a);
      const route: TransportRoute = {
        kind: "a2a-quote",
        method: "POST",
        url: endpoint,
        approvedUrl: endpoint,
        rpcMethod: "message/send",
        body,
      };
      let response: BoundedHttpResponse;
      try {
        response = await request(route);
      } catch (cause) {
        throw new Error("category quote endpoint request failed", { cause });
      }
      if (
        response.status !== 200 ||
        !(response.body instanceof Uint8Array) ||
        response.responseSha256 !==
          createHash("sha256").update(response.body).digest("hex")
      ) {
        throw new Error("category quote endpoint returned an invalid response");
      }
      return parseCategoryQuoteA2aResponse(parseJsonResponse(response), {
        expectedRpcId: rpcId,
      });
    },
  }) satisfies CategoryQuoteFetchCapability;
  return capability;
}

export type VerifiedAcceptedCategoryQuote = Readonly<{
  verificationProfile: typeof CATEGORY_QUOTE_VERIFICATION_PROFILE;
  relation: "candidate_accepts_service_for_subject";
  providerAuthority: "erc8004_registered_owner";
  scope: "evaluation_only";
  activationAuthorization: "none";
  reservation: "none";
  replayPolicy: "reusable_until_expiry";
  providerKind: "eoa" | "erc1271";
  providerCodeSha256: string;
  signatureMethod: "eip191" | "erc1271";
  expectedProvider: string;
  registeredOwner: string;
  validatedProvider: string;
  validatedSigner: string;
  chainId: 56;
  verifyingContract: string;
  requestId: string;
  mandateSha256: string;
  categoryQuoteRequestSha256: string;
  candidate: Readonly<{ chainId: 56; tokenId: string }>;
  candidateIdentitySha256: string;
  category: "grid" | "yield" | "health";
  adapterId: string;
  protocol: string;
  serviceMode: "observe_only" | "transactional";
  subjectSha256: string;
  conditionPolicySha256: string;
  actionPermissionsSha256: string;
  maxSpendUsdMicros: string;
  permissionsExpiresAt: number;
  quoteEndpointSha256: string;
  nonce: string;
  issuedAt: number;
  challengeExpiresAt: number;
  negotiatedAt: number;
  quoteExpiresAt: number;
  requestKeccak256: Hex;
  responseKeccak256: Hex;
  negotiationKeccak256: Hex;
}>;

export type CategoryQuoteErc1271Check = (input: {
  readonly provider: string;
  readonly messageDigest: Hex;
  readonly signature: Hex;
  readonly verifyingContract: string;
  readonly identityBlock: number;
  readonly identityBlockHash: string;
}) => Promise<boolean>;

export interface CategoryQuoteVerificationCapability {
  readonly verifyAccepted: (input: {
    readonly envelope: unknown;
    readonly identity: VerifiedCategoryCandidateIdentity;
    readonly expectedProvider: string;
    readonly expectedRequest: CategoryQuoteExpectedRequest;
  }) => Promise<VerifiedAcceptedCategoryQuote>;
  readonly assertVerified: (
    value: unknown,
    input: {
      readonly identity: VerifiedCategoryCandidateIdentity;
      readonly expectedRequest: CategoryQuoteExpectedRequest;
    },
  ) => asserts value is VerifiedAcceptedCategoryQuote;
}

type QuoteProvenance = Readonly<{
  capability: CategoryQuoteVerificationCapability;
  identity: VerifiedCategoryCandidateIdentity;
  expectedRequestCanonical: string;
}>;

const verifiedQuoteInstances = new WeakSet<object>();
const verifiedQuotes = new WeakMap<object, QuoteProvenance>();

export function createCategoryQuoteVerificationCapability(options: {
  readonly identityCapability: CategoryCandidateIdentityCapability;
  readonly verifyingContract: string;
  readonly clock: () => number;
  readonly erc1271Check: CategoryQuoteErc1271Check;
}): CategoryQuoteVerificationCapability {
  assertExactDataObject(
    options,
    [
      "clock",
      "erc1271Check",
      "identityCapability",
      "verifyingContract",
    ],
    "category quote capability options",
  );
  const identityCapability: CategoryCandidateIdentityCapability =
    readDataProperty(
      options,
      "identityCapability",
    ) as CategoryCandidateIdentityCapability;
  if (
    identityCapability === null ||
    typeof identityCapability !== "object" ||
    typeof identityCapability.assertVerified !== "function"
  ) {
    throw new TypeError("category quote identity capability is invalid");
  }
  const verifyingContract = addressSchema.parse(
    readDataProperty(options, "verifyingContract"),
  );
  const clock = readDataProperty(options, "clock") as () => number;
  const erc1271Check = readDataProperty(
    options,
    "erc1271Check",
  ) as CategoryQuoteErc1271Check;
  if (typeof clock !== "function" || typeof erc1271Check !== "function") {
    throw new TypeError("category quote capability callbacks are invalid");
  }

  let capability: CategoryQuoteVerificationCapability;
  capability = Object.freeze({
    async verifyAccepted(
      input: Parameters<
        CategoryQuoteVerificationCapability["verifyAccepted"]
      >[0],
    ): Promise<VerifiedAcceptedCategoryQuote> {
      assertExactDataObject(
        input,
        [
          "envelope",
          "expectedProvider",
          "expectedRequest",
          "identity",
        ],
        "category quote verification input",
      );
      const identity = readDataProperty(
        input,
        "identity",
      ) as VerifiedCategoryCandidateIdentity;
      const envelope = parseCanonicalEnvelope(
        readDataProperty(input, "envelope"),
      );
      const expectedProvider = addressSchema.parse(
        readDataProperty(input, "expectedProvider"),
      );
      const expectedRequest = parseExpectedRequest(
        readDataProperty(input, "expectedRequest"),
      );
      const challenge = envelope.challenge;
      const response = envelope.response;

      identityCapability.assertVerified(identity, challenge.candidate);
      const provider = identityCapability.providerFor(identity, challenge.candidate);
      assertExpectedRequest(challenge, expectedRequest);
      assertChallengeIdentity(
        challenge,
        identity,
        expectedProvider,
        provider,
        verifyingContract,
      );
      assertProviderAuthority(
        challenge,
        response,
        identity,
        provider.providerKind,
        expectedProvider,
      );
      assertChronology(challenge, response, identity, readClock(clock));

      const commitments = categoryQuoteCommitments({ challenge, response });
      if (
        envelope.requestKeccak256 !== commitments.requestKeccak256 ||
        envelope.responseKeccak256 !== commitments.responseKeccak256 ||
        envelope.negotiationKeccak256 !== commitments.negotiationKeccak256
      ) {
        throw new Error(
          "category quote Keccak-256 commitment does not match its content",
        );
      }

      const signedMessage = categoryQuoteEip191Message(
        commitments.negotiationKeccak256,
      );
      let signatureMethod: "eip191" | "erc1271";
      let validatedSigner: string;
      if (provider.providerKind === "eoa") {
        const signature = eoaSignatureSchema.parse(envelope.providerSignature);
        try {
          validatedSigner = (
            await recoverMessageAddress({
              message: signedMessage,
              signature: signature as Hex,
            })
          ).toLowerCase();
        } catch {
          throw new Error("category quote EIP-191 signature is invalid");
        }
        if (validatedSigner !== identity.ownerAddress) {
          throw new Error(
            "category quote signer is not the verifier-observed registered owner",
          );
        }
        signatureMethod = "eip191";
      } else {
        let valid: boolean;
        try {
          valid = await erc1271Check({
            provider: identity.ownerAddress,
            messageDigest: hashMessage(signedMessage),
            signature: envelope.providerSignature as Hex,
            verifyingContract,
            identityBlock: identity.observedBlock,
            identityBlockHash: identity.observedBlockHash,
          });
        } catch (error) {
          throw new Error(
            "category quote ERC-1271 verification is unavailable",
            { cause: error },
          );
        }
        if (!valid) {
          throw new Error("category quote ERC-1271 signature is invalid");
        }
        validatedSigner = identity.ownerAddress;
        signatureMethod = "erc1271";
      }

      assertChronology(challenge, response, identity, readClock(clock));
      if (
        expectedProvider !== identity.ownerAddress ||
        validatedSigner !== identity.ownerAddress
      ) {
        throw new Error(
          "expected provider, validated signer, and registered owner must be identical",
        );
      }

      const verified = deepFreeze({
        verificationProfile: CATEGORY_QUOTE_VERIFICATION_PROFILE,
        relation: challenge.relation,
        providerAuthority: challenge.providerAuthority,
        scope: challenge.scope,
        activationAuthorization: challenge.activationAuthorization,
        reservation: challenge.reservation,
        replayPolicy: challenge.replayPolicy,
        providerKind: provider.providerKind,
        providerCodeSha256: provider.providerCodeSha256,
        signatureMethod,
        expectedProvider,
        registeredOwner: identity.ownerAddress,
        validatedProvider: expectedProvider,
        validatedSigner,
        chainId: challenge.chainId,
        verifyingContract,
        requestId: challenge.requestId,
        mandateSha256: challenge.mandateSha256,
        categoryQuoteRequestSha256: challenge.categoryQuoteRequestSha256,
        candidate: challenge.candidate,
        candidateIdentitySha256: identity.identitySha256,
        category: challenge.category,
        adapterId: challenge.adapterId,
        protocol: challenge.protocol,
        serviceMode: challenge.serviceMode,
        subjectSha256: challenge.subjectSha256,
        conditionPolicySha256: challenge.conditionPolicySha256,
        actionPermissionsSha256: challenge.actionPermissionsSha256,
        maxSpendUsdMicros: challenge.maxSpendUsdMicros,
        permissionsExpiresAt: challenge.permissionsExpiresAt,
        quoteEndpointSha256: challenge.quoteEndpointSha256,
        nonce: challenge.nonce,
        issuedAt: challenge.issuedAt,
        challengeExpiresAt: challenge.expiresAt,
        negotiatedAt: response.negotiatedAt,
        quoteExpiresAt: response.quoteExpiresAt,
        requestKeccak256: commitments.requestKeccak256,
        responseKeccak256: commitments.responseKeccak256,
        negotiationKeccak256: commitments.negotiationKeccak256,
      });
      verifiedQuoteInstances.add(verified);
      verifiedQuotes.set(verified, {
        capability,
        identity,
        expectedRequestCanonical: canonicalQuoteJson(expectedRequest),
      });
      return verified;
    },
    assertVerified(
      value: unknown,
      input: Parameters<
        CategoryQuoteVerificationCapability["assertVerified"]
      >[1],
    ): asserts value is VerifiedAcceptedCategoryQuote {
      assertExactDataObject(
        input,
        ["expectedRequest", "identity"],
        "category quote assertion input",
      );
      const identity = readDataProperty(
        input,
        "identity",
      ) as VerifiedCategoryCandidateIdentity;
      const expectedRequest = parseExpectedRequest(
        readDataProperty(input, "expectedRequest"),
      );
      const provenance =
        value !== null && typeof value === "object"
          ? verifiedQuotes.get(value)
          : undefined;
      if (
        provenance === undefined ||
        !verifiedQuoteInstances.has(value as object) ||
        provenance.capability !== capability ||
        provenance.identity !== identity ||
        provenance.expectedRequestCanonical !==
          canonicalQuoteJson(expectedRequest)
      ) {
        throw new Error(
          "category quote lacks verifier-owned acceptance provenance for this request and identity",
        );
      }
    },
  });
  return capability;
}

export function categoryQuoteRequestKeccak256(challenge: unknown): Hex {
  return keccakCanonical(parseCanonicalChallenge(challenge));
}

export function categoryQuoteEip191Message(
  negotiationKeccak256: string,
): string {
  return `${CATEGORY_QUOTE_EIP191_PREFIX}${bytes32Schema.parse(
    negotiationKeccak256,
  )}`;
}

export function categoryQuoteCommitments(input: {
  readonly challenge: unknown;
  readonly response: unknown;
}): Readonly<{
  requestKeccak256: Hex;
  responseKeccak256: Hex;
  negotiationKeccak256: Hex;
}> {
  assertExactDataObject(
    input,
    ["challenge", "response"],
    "category quote commitment input",
  );
  const challenge = parseCanonicalChallenge(
    readDataProperty(input, "challenge"),
  );
  const response = parseCanonicalResponse(
    readDataProperty(input, "response"),
  );
  const requestKeccak256 = keccakCanonical(challenge);
  if (response.requestKeccak256 !== requestKeccak256) {
    throw new Error("category quote response is bound to another request");
  }
  const responseKeccak256 = keccakCanonical(response);
  const signedContent = categoryQuoteSignedContentSchema.parse({
    schema: CATEGORY_QUOTE_SIGNED_CONTENT_SCHEMA,
    signingDomain: CATEGORY_QUOTE_SIGNING_DOMAIN,
    audience: CATEGORY_QUOTE_AUDIENCE,
    chainId: challenge.chainId,
    verifyingContract: challenge.verifyingContract,
    challenge,
    response,
    requestKeccak256,
    responseKeccak256,
  });
  return Object.freeze({
    requestKeccak256,
    responseKeccak256,
    negotiationKeccak256: keccakCanonical(signedContent),
  });
}

function assertExpectedRequest(
  challenge: CategoryQuoteChallenge,
  expected: CategoryQuoteExpectedRequest,
): void {
  if (
    challenge.requestId !== expected.requestId ||
    challenge.mandateSha256 !== expected.mandateSha256 ||
    challenge.categoryQuoteRequestSha256 !== expected.categoryQuoteRequestSha256 ||
    canonicalQuoteJson(challenge.candidate) !== canonicalQuoteJson(expected.candidate) ||
    challenge.category !== expected.category ||
    challenge.adapterId !== expected.adapterId ||
    challenge.protocol !== expected.protocol ||
    challenge.serviceMode !== expected.serviceMode ||
    challenge.subjectSha256 !== expected.subjectSha256 ||
    challenge.conditionPolicySha256 !== expected.conditionPolicySha256 ||
    challenge.actionPermissionsSha256 !== expected.actionPermissionsSha256 ||
    challenge.maxSpendUsdMicros !== expected.maxSpendUsdMicros ||
    challenge.permissionsExpiresAt !== expected.permissionsExpiresAt ||
    challenge.quoteEndpointSha256 !== expected.quoteEndpointSha256 ||
    challenge.nonce !== expected.nonce ||
    challenge.issuedAt !== expected.issuedAt ||
    challenge.expiresAt !== expected.expiresAt ||
    challenge.maxClockSkewSeconds !== expected.maxClockSkewSeconds
  ) {
    throw new Error("category quote is bound to another marketplace request");
  }
}

function assertChallengeIdentity(
  challenge: CategoryQuoteChallenge,
  identity: VerifiedCategoryCandidateIdentity,
  expectedProvider: string,
  provider: Readonly<{
    providerKind: "eoa" | "erc1271";
    providerCodeSha256: string;
  }>,
  verifyingContract: string,
): void {
  if (
    challenge.candidate.chainId !== identity.chainId ||
    challenge.candidate.tokenId !== identity.tokenId ||
    challenge.identityVerificationProfile !== CATEGORY_CANDIDATE_IDENTITY_PROFILE ||
    challenge.candidateIdentitySha256 !== identity.identitySha256 ||
    challenge.registryAddress !== identity.registryAddress ||
    challenge.registryCodeSha256 !== identity.registryCodeSha256 ||
    challenge.registeredOwner !== identity.ownerAddress ||
    challenge.providerKind !== provider.providerKind ||
    challenge.providerCodeSha256 !== provider.providerCodeSha256
  ) {
    throw new Error("category quote challenge is bound to another identity");
  }
  if (
    challenge.verifyingContract !== verifyingContract ||
    expectedProvider !== identity.ownerAddress
  ) {
    throw new Error("category quote challenge uses an untrusted quote domain");
  }
}

function assertProviderAuthority(
  challenge: CategoryQuoteChallenge,
  response: CategoryQuoteResponse,
  identity: VerifiedCategoryCandidateIdentity,
  providerKind: "eoa" | "erc1271",
  expectedProvider: string,
): void {
  if (
    response.relation !== challenge.relation ||
    response.providerAuthority !== challenge.providerAuthority ||
    challenge.providerKind !== providerKind ||
    response.providerKind !== challenge.providerKind ||
    response.providerAddress !== expectedProvider ||
    response.providerAddress !== identity.ownerAddress ||
    challenge.registeredOwner !== expectedProvider
  ) {
    throw new Error(
      "category quote provider must be the verifier-observed registered owner",
    );
  }
}

function assertChronology(
  challenge: CategoryQuoteChallenge,
  response: CategoryQuoteResponse,
  identity: VerifiedCategoryCandidateIdentity,
  now: number,
): void {
  if (
    challenge.issuedAt > now + challenge.maxClockSkewSeconds ||
    challenge.expiresAt <= now ||
    response.quoteExpiresAt <= now
  ) {
    throw new Error("category quote is outside its validity window");
  }
  if (
    challenge.issuedAt < identity.observedAt - challenge.maxClockSkewSeconds ||
    response.negotiatedAt < challenge.issuedAt - challenge.maxClockSkewSeconds ||
    response.negotiatedAt > now + challenge.maxClockSkewSeconds ||
    response.quoteExpiresAt > challenge.expiresAt ||
    response.quoteExpiresAt > challenge.permissionsExpiresAt ||
    response.quoteExpiresAt - response.negotiatedAt >
      MAX_CATEGORY_QUOTE_TTL_SECONDS
  ) {
    throw new Error("category quote response chronology is invalid");
  }
  if (
    identity.observedAt > now + challenge.maxClockSkewSeconds ||
    now - identity.observedAt > MAX_CATEGORY_IDENTITY_AGE_SECONDS
  ) {
    throw new Error("category quote identity snapshot is stale or in the future");
  }
}

function parseCanonicalEnvelope(value: unknown): CategoryQuoteEnvelope {
  const snapshot = snapshotCanonicalJson(value, "category quote envelope");
  const parsed = categoryQuoteEnvelopeSchema.parse(snapshot);
  assertCanonicalEquality(snapshot, parsed, "category quote envelope");
  return deepFreeze(parsed);
}

function parseCategoryQuoteEndpoint(value: unknown): string {
  if (typeof value !== "string") {
    throw new TypeError("category quote endpoint must be an HTTPS URL");
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch (cause) {
    throw new TypeError("category quote endpoint must be an HTTPS URL", {
      cause,
    });
  }
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.hostname.endsWith(".") ||
    isIP(url.hostname) !== 0 ||
    (url.port !== "" && url.port !== "443") ||
    url.href !== value
  ) {
    throw new TypeError("category quote endpoint must be a canonical HTTPS URL");
  }
  return url.href;
}

function parseCanonicalChallenge(value: unknown): CategoryQuoteChallenge {
  const snapshot = snapshotCanonicalJson(value, "category quote challenge");
  const parsed = categoryQuoteChallengeSchema.parse(snapshot);
  assertCanonicalEquality(snapshot, parsed, "category quote challenge");
  return deepFreeze(parsed);
}

function parseCanonicalResponse(value: unknown): CategoryQuoteResponse {
  const snapshot = snapshotCanonicalJson(value, "category quote response");
  const parsed = categoryQuoteResponseSchema.parse(snapshot);
  assertCanonicalEquality(snapshot, parsed, "category quote response");
  return deepFreeze(parsed);
}

function parseExpectedRequest(value: unknown): CategoryQuoteExpectedRequest {
  const snapshot = snapshotCanonicalJson(
    value,
    "expected category quote request",
  );
  const parsed = expectedRequestSchema.parse(snapshot);
  assertCanonicalEquality(snapshot, parsed, "expected category quote request");
  return deepFreeze(parsed);
}

function assertCanonicalEquality(
  input: unknown,
  parsed: unknown,
  label: string,
): void {
  if (canonicalQuoteJson(input) !== canonicalQuoteJson(parsed)) {
    throw new TypeError(`${label} is not canonical`);
  }
}

function snapshotCanonicalJson(
  value: unknown,
  label: string,
  seen = new WeakSet<object>(),
): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError(`${label} contains a non-finite number`);
    }
    return value;
  }
  if (typeof value !== "object") {
    throw new TypeError(`${label} contains a non-JSON value`);
  }
  if (seen.has(value)) {
    throw new TypeError(`${label} contains a cycle`);
  }
  seen.add(value);

  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      throw new TypeError(`${label} contains a non-canonical array`);
    }
    const keys = Reflect.ownKeys(value);
    if (
      keys.some(
        (key) =>
          typeof key !== "string" ||
          (key !== "length" && !/^(?:0|[1-9][0-9]*)$/.test(key)),
      )
    ) {
      throw new TypeError(`${label} contains unsupported array properties`);
    }
    const result: unknown[] = [];
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        !descriptor.enumerable
      ) {
        throw new TypeError(`${label} contains a sparse or accessor array`);
      }
      result.push(snapshotCanonicalJson(descriptor.value, label, seen));
    }
    seen.delete(value);
    return result;
  }

  if (Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must contain plain objects only`);
  }
  const result: Record<string, unknown> = {};
  for (const key of Reflect.ownKeys(value)) {
    if (
      typeof key !== "string" ||
      /^(?:0|[1-9][0-9]*)$/.test(key)
    ) {
      throw new TypeError(`${label} contains a non-canonical object key`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    ) {
      throw new TypeError(`${label} must contain enumerable data properties`);
    }
    result[key] = snapshotCanonicalJson(descriptor.value, label, seen);
  }
  seen.delete(value);
  return result;
}

function sha256Canonical(value: unknown): string {
  return createHash("sha256")
    .update(canonicalQuoteJson(value), "utf8")
    .digest("hex");
}

function keccakCanonical(value: unknown): Hex {
  return keccak256(stringToBytes(canonicalQuoteJson(value)));
}

function readClock(clock: () => number): number {
  const value = clock();
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError("category quote clock must return positive Unix seconds");
  }
  return value;
}

function assertExactDataObject(
  value: unknown,
  keys: readonly string[],
  label: string,
): asserts value is object {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError(`${label} must be a plain object`);
  }
  const actual = Reflect.ownKeys(value);
  if (
    actual.length !== keys.length ||
    actual.some((key) => typeof key !== "string" || !keys.includes(key))
  ) {
    throw new TypeError(`${label} has unsupported or missing fields`);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor)) {
      throw new TypeError(`${label} must contain data properties`);
    }
  }
}

function readDataProperty(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor)) {
    throw new TypeError(`missing data property ${key}`);
  }
  return descriptor.value;
}

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object") return value;
  const object = value as object;
  if (seen.has(object)) return value;
  seen.add(object);
  for (const key of Reflect.ownKeys(object)) {
    deepFreeze((object as Record<PropertyKey, unknown>)[key], seen);
  }
  return Object.freeze(value);
}
