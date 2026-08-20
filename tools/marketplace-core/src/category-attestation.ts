import {
  createHash,
  createPublicKey,
  verify as verifyEd25519,
  type KeyObject,
} from "node:crypto";
import { TextDecoder } from "node:util";

import { z } from "zod";

import { canonicalJson, canonicalSha256 } from "./canonical.js";
import {
  CATEGORY_ADAPTER_REGISTRY,
  MARKETPLACE_AAVE_HEALTH_ADAPTER,
  MARKETPLACE_GRID_ADAPTER,
  MARKETPLACE_HEALTH_EVIDENCE_SCHEMA,
  MARKETPLACE_GRID_EVIDENCE_SCHEMA,
  MARKETPLACE_VENUS_HEALTH_ADAPTER,
  MARKETPLACE_VENUS_HEALTH_EVIDENCE_SCHEMA,
  MARKETPLACE_YIELD_ADAPTER,
  MARKETPLACE_YIELD_EVIDENCE_SCHEMA,
  type MarketplaceCategoryAdapterId,
} from "./category-policy.js";
import { MarketplaceCoreError } from "./errors.js";
import { deepFreeze, type DeepReadonly } from "./immutable.js";
import {
  addressSchema,
  blockNumberSchema,
  bytes32Schema,
  canonicalIdentifierSchema,
  marketplaceCategorySchema,
  sha256Schema,
  tickSchema,
  uint256DecimalSchema,
  unixSecondsSchema,
} from "./primitives.js";
import {
  marketplaceCandidateSchema,
  marketplaceMandateSchema,
} from "./schemas.js";

export const MARKETPLACE_CATEGORY_ATTESTATION_SCHEMA =
  "mandatex.marketplace.category-condition-attestation.v1" as const;
export const MARKETPLACE_CATEGORY_ATTESTATION_SIGNATURE_PROFILE =
  "mandatex-ed25519-category-condition-v1" as const;
export const MARKETPLACE_CATEGORY_ATTESTATION_ISSUER =
  "mandatex-agent-supply-category-verifier" as const;
export const MARKETPLACE_CATEGORY_ATTESTATION_AUDIENCE =
  "mandatex-marketplace-core-category" as const;
export const MARKETPLACE_CATEGORY_ATTESTATION_EVIDENCE_MODE =
  "verifier_commitment_only" as const;
export const MARKETPLACE_CATEGORY_ATTESTATION_SIGNING_DOMAIN =
  "MandateX Marketplace Category Condition Attestation v1\0" as const;
export const MAX_MARKETPLACE_CATEGORY_ATTESTATION_BYTES = 131_072 as const;
export const MAX_MARKETPLACE_CATEGORY_ATTESTATION_TTL_SECONDS = 300 as const;

const signatureSchema = z
  .string()
  .regex(/^[a-f0-9]{128}$/, "expected a 64-byte lowercase hex signature");

const gridSubjectAndPolicySchema = z
  .object({
    adapterId: z.literal(MARKETPLACE_GRID_ADAPTER),
    category: z.literal("grid"),
    evidenceSchema: z.literal(MARKETPLACE_GRID_EVIDENCE_SCHEMA),
    protocol: z.literal("pancakeswap-v3"),
    subject: z.object({ poolAddress: addressSchema }).strict(),
    policy: z
      .object({ lowerTick: tickSchema, upperTick: tickSchema })
      .strict()
      .superRefine((value, context) => {
        if (value.lowerTick >= value.upperTick) {
          context.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["upperTick"],
            message: "lowerTick must be less than upperTick",
          });
        }
      }),
  })
  .strict();

const yieldSubjectAndPolicySchema = z
  .object({
    adapterId: z.literal(MARKETPLACE_YIELD_ADAPTER),
    category: z.literal("yield"),
    evidenceSchema: z.literal(MARKETPLACE_YIELD_EVIDENCE_SCHEMA),
    protocol: z.literal("erc4626"),
    subject: z.object({ vaultAddress: addressSchema }).strict(),
    policy: z.object({ minSharePriceScaled: uint256DecimalSchema }).strict(),
  })
  .strict();

const aaveSubjectAndPolicySchema = z
  .object({
    adapterId: z.literal(MARKETPLACE_AAVE_HEALTH_ADAPTER),
    category: z.literal("health"),
    evidenceSchema: z.literal(MARKETPLACE_HEALTH_EVIDENCE_SCHEMA),
    protocol: z.literal("aave-v3"),
    subject: z
      .object({ poolAddress: addressSchema, accountAddress: addressSchema })
      .strict(),
    policy: z
      .object({ minHealthFactorScaled: uint256DecimalSchema })
      .strict(),
  })
  .strict();

const venusSubjectAndPolicySchema = z
  .object({
    adapterId: z.literal(MARKETPLACE_VENUS_HEALTH_ADAPTER),
    category: z.literal("health"),
    evidenceSchema: z.literal(MARKETPLACE_VENUS_HEALTH_EVIDENCE_SCHEMA),
    protocol: z.literal("venus"),
    subject: z
      .object({
        comptrollerAddress: addressSchema,
        accountAddress: addressSchema,
        borrowMarketAddress: addressSchema,
      })
      .strict(),
    policy: z
      .object({ minLiquidityUsdScaled: uint256DecimalSchema })
      .strict(),
  })
  .strict();

const categoryEvaluationRequestBaseShape = {
  schema: z.literal("mandatex.marketplace.category-evaluation-request.v1"),
  requestId: canonicalIdentifierSchema,
  mandate: marketplaceMandateSchema,
  candidate: marketplaceCandidateSchema,
} as const;

const categoryEvaluationRequestVariantSchema = z.discriminatedUnion("adapterId", [
  z.object({ ...categoryEvaluationRequestBaseShape, ...gridSubjectAndPolicySchema.shape }).strict(),
  z.object({ ...categoryEvaluationRequestBaseShape, ...yieldSubjectAndPolicySchema.shape }).strict(),
  z.object({ ...categoryEvaluationRequestBaseShape, ...aaveSubjectAndPolicySchema.shape }).strict(),
  z.object({ ...categoryEvaluationRequestBaseShape, ...venusSubjectAndPolicySchema.shape }).strict(),
]);

export const marketplaceCategoryEvaluationRequestSchema = categoryEvaluationRequestVariantSchema.superRefine(
  (request, context) => {
    if (request.mandate.category !== request.category) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["mandate", "category"],
        message: "mandate category must match the adapter category",
      });
    }
  },
);

/** Alias retained for callers that prefer the contract's noun form. */
export const marketplaceCategoryEvaluationRequest =
  marketplaceCategoryEvaluationRequestSchema;

export type MarketplaceCategoryEvaluationRequest = DeepReadonly<
  z.infer<typeof marketplaceCategoryEvaluationRequest>
>;

const categoryAttestationPayloadSchema = z
  .object({
    schema: z.literal("mandatex.marketplace.category-condition-payload.v1"),
    requestId: canonicalIdentifierSchema,
    mandateId: canonicalIdentifierSchema,
    category: marketplaceCategorySchema,
    candidate: z
      .object({ chainId: z.literal(56), tokenId: z.string().regex(/^(?:0|[1-9][0-9]*)$/) })
      .strict(),
    adapterId: z.string(),
    evidenceSchema: z.string(),
    protocol: z.string(),
    subjectSha256: sha256Schema,
    policySha256: sha256Schema,
    deploymentSha256: sha256Schema,
    artifactSha256: sha256Schema,
    evidenceSha256: sha256Schema,
    observedAt: unixSecondsSchema,
    observedBlock: blockNumberSchema,
    observedBlockHash: bytes32Schema,
    status: z.literal("pass"),
  })
  .strict()
  .superRefine((payload, context) => {
    const entry = CATEGORY_ADAPTER_REGISTRY[payload.adapterId as MarketplaceCategoryAdapterId];
    if (entry === undefined) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["adapterId"],
        message: "category payload adapter ID is not registered",
      });
      return;
    }
    if (entry.category !== payload.category || entry.evidenceSchema !== payload.evidenceSchema) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["adapterId"],
        message: "category payload adapter identity is inconsistent",
      });
    }
  });

export type MarketplaceCategoryAttestationPayload = DeepReadonly<
  z.infer<typeof categoryAttestationPayloadSchema>
>;

const unsignedShape = {
  schema: z.literal(MARKETPLACE_CATEGORY_ATTESTATION_SCHEMA),
  signatureProfile: z.literal(MARKETPLACE_CATEGORY_ATTESTATION_SIGNATURE_PROFILE),
  issuer: z.literal(MARKETPLACE_CATEGORY_ATTESTATION_ISSUER),
  audience: z.literal(MARKETPLACE_CATEGORY_ATTESTATION_AUDIENCE),
  keyId: canonicalIdentifierSchema,
  attestationId: canonicalIdentifierSchema,
  scope: z.literal("evaluation_only"),
  activationAuthorization: z.literal("none"),
  reservation: z.literal("none"),
  replayPolicy: z.literal("reusable_until_expiry"),
  replayScope: z.literal("request_id"),
  evidenceMode: z.literal(MARKETPLACE_CATEGORY_ATTESTATION_EVIDENCE_MODE),
  issuedAt: unixSecondsSchema,
  expiresAt: unixSecondsSchema,
  mandateSha256: sha256Schema,
  requestSha256: sha256Schema,
  verifierPolicySha256: sha256Schema,
  payload: categoryAttestationPayloadSchema,
} as const;

export const marketplaceCategoryAttestationUnsignedSchema = z
  .object(unsignedShape)
  .strict();
export const marketplaceCategoryAttestationSchema = z
  .object({ ...unsignedShape, signature: signatureSchema })
  .strict();

export type MarketplaceCategoryAttestationUnsigned = DeepReadonly<
  z.infer<typeof marketplaceCategoryAttestationUnsignedSchema>
>;
export type MarketplaceCategoryAttestation = DeepReadonly<
  z.infer<typeof marketplaceCategoryAttestationSchema>
>;
export type MarketplaceCategoryAttestationWire = string | Uint8Array;

export type MarketplaceCategoryAttestationTrust = Readonly<{
  keyId: string;
  publicKeySpkiDer: Uint8Array;
  publicKeyFingerprintSha256: string;
  verifierPolicySha256: string;
  categoryDeploymentSha256: string;
}>;

export type ValidatedMarketplaceCategoryAttestationTrust = Readonly<{
  keyId: string;
  publicKey: KeyObject;
  publicKeyFingerprintSha256: string;
  verifierPolicySha256: string;
  categoryDeploymentSha256: string;
}>;

export type VerifiedMarketplaceCategoryAttestation = DeepReadonly<{
  envelope: MarketplaceCategoryAttestation;
  attestationSha256: string;
  publicKeyFingerprintSha256: string;
  validUntil: number;
}>;

export function validateMarketplaceCategoryAttestationTrust(
  input: MarketplaceCategoryAttestationTrust,
): ValidatedMarketplaceCategoryAttestationTrust {
  if (input === null || typeof input !== "object") {
    throw categoryError("ATTESTATION_TRUST_INVALID", "category attestation trust must be an object");
  }
  if (typeof input.keyId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(input.keyId)) {
    throw categoryError("ATTESTATION_TRUST_INVALID", "category attestation key ID is invalid");
  }
  if (!(input.publicKeySpkiDer instanceof Uint8Array)) {
    throw categoryError("ATTESTATION_TRUST_INVALID", "category attestation public key must be SPKI DER bytes");
  }
  for (const [value, label] of [
    [input.publicKeyFingerprintSha256, "public-key fingerprint"],
    [input.verifierPolicySha256, "verifier policy"],
    [input.categoryDeploymentSha256, "category deployment"],
  ] as const) {
    if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
      throw categoryError("ATTESTATION_TRUST_INVALID", `category attestation ${label} is invalid`);
    }
  }
  try {
    const der = Buffer.from(input.publicKeySpkiDer);
    const publicKey = createPublicKey({ key: der, format: "der", type: "spki" });
    if (publicKey.asymmetricKeyType !== "ed25519") throw new TypeError("not Ed25519");
    const exported = publicKey.export({ format: "der", type: "spki" });
    if (!Buffer.isBuffer(exported) || !exported.equals(der)) throw new TypeError("noncanonical SPKI");
    const fingerprint = createHash("sha256").update(exported).digest("hex");
    if (fingerprint !== input.publicKeyFingerprintSha256) throw new TypeError("fingerprint mismatch");
    return Object.freeze({
      keyId: input.keyId,
      publicKey,
      publicKeyFingerprintSha256: fingerprint,
      verifierPolicySha256: input.verifierPolicySha256,
      categoryDeploymentSha256: input.categoryDeploymentSha256,
    });
  } catch (cause) {
    throw categoryError("ATTESTATION_TRUST_INVALID", "category attestation public key is invalid", cause);
  }
}

export function marketplaceCategoryAttestationSigningMessage(input: unknown): Uint8Array {
  const unsigned = marketplaceCategoryAttestationUnsignedSchema.parse(input);
  return Buffer.concat([
    Buffer.from(MARKETPLACE_CATEGORY_ATTESTATION_SIGNING_DOMAIN, "utf8"),
    Buffer.from(canonicalJson(unsigned), "utf8"),
  ]);
}

export function serializeMarketplaceCategoryAttestation(input: unknown): string {
  return canonicalJson(marketplaceCategoryAttestationSchema.parse(input));
}

export function verifyMarketplaceCategoryAttestation(input: {
  readonly wire: MarketplaceCategoryAttestationWire;
  readonly request: MarketplaceCategoryEvaluationRequest;
  readonly evaluatedAt: number;
  readonly maxClockSkewSeconds: number;
  readonly trust: ValidatedMarketplaceCategoryAttestationTrust;
}): VerifiedMarketplaceCategoryAttestation {
  const requestResult = marketplaceCategoryEvaluationRequestSchema.safeParse(
    input.request,
  );
  if (!requestResult.success) {
    throw categoryError(
      "CATEGORY_REQUEST_INVALID",
      "category evaluation request does not match the strict request schema",
      requestResult.error,
    );
  }
  const request = requestResult.data;
  const envelope = parseCategoryWire(input.wire);
  if (envelope.keyId !== input.trust.keyId)
    throw categoryError("ATTESTATION_KEY_MISMATCH", "category attestation key ID is not pinned");
  if (envelope.verifierPolicySha256 !== input.trust.verifierPolicySha256)
    throw categoryError("ATTESTATION_POLICY_MISMATCH", "category attestation policy is not pinned");
  if (envelope.mandateSha256 !== canonicalSha256(request.mandate))
    throw categoryError("ATTESTATION_MANDATE_HASH_MISMATCH", "category attestation mandate hash does not match the request");
  if (envelope.requestSha256 !== canonicalSha256(request))
    throw categoryError("CATEGORY_ATTESTATION_REQUEST_HASH_MISMATCH", "category attestation request hash does not match the request");
  if (envelope.payload.category !== request.category || envelope.payload.adapterId !== request.adapterId)
    throw categoryError("CATEGORY_ATTESTATION_ADAPTER_MISMATCH", "category attestation adapter does not match the request");
  if (
    envelope.payload.evidenceSchema !== request.evidenceSchema ||
    envelope.payload.protocol !== request.protocol
  )
    throw categoryError("CATEGORY_ATTESTATION_ADAPTER_MISMATCH", "category attestation protocol or evidence schema does not match the request");
  if (envelope.payload.mandateId !== request.mandate.mandateId || envelope.payload.requestId !== request.requestId)
    throw categoryError("CATEGORY_ATTESTATION_REQUEST_MISMATCH", "category attestation request identity does not match");
  if (envelope.payload.candidate.chainId !== request.candidate.chainId || envelope.payload.candidate.tokenId !== request.candidate.tokenId)
    throw categoryError("CATEGORY_ATTESTATION_CANDIDATE_MISMATCH", "category attestation candidate does not match the request");
  if (envelope.payload.subjectSha256 !== canonicalSha256(request.subject))
    throw categoryError("CATEGORY_ATTESTATION_SUBJECT_MISMATCH", "category attestation subject does not match the request");
  if (envelope.payload.policySha256 !== canonicalSha256(request.policy))
    throw categoryError("CATEGORY_ATTESTATION_POLICY_BINDING_MISMATCH", "category attestation adapter policy does not match the request");
  if (envelope.payload.deploymentSha256 !== input.trust.categoryDeploymentSha256)
    throw categoryError("CATEGORY_ATTESTATION_DEPLOYMENT_MISMATCH", "category attestation deployment is not pinned");
  if (!Number.isSafeInteger(input.maxClockSkewSeconds) || input.maxClockSkewSeconds < 0 || input.maxClockSkewSeconds > 300)
    throw categoryError("ATTESTATION_TRUST_INVALID", "category evaluation clock skew is invalid");
  if (!Number.isSafeInteger(input.evaluatedAt) || input.evaluatedAt <= 0)
    throw categoryError("EVALUATED_AT_INVALID", "category evaluation time is invalid");
  if (envelope.issuedAt > input.evaluatedAt + input.maxClockSkewSeconds)
    throw categoryError("ATTESTATION_NOT_YET_VALID", "category attestation is not yet valid");
  if (
    envelope.issuedAt >= request.mandate.expiresAt ||
    envelope.expiresAt <= envelope.issuedAt ||
    envelope.expiresAt > request.mandate.expiresAt
  )
    throw categoryError("ATTESTATION_EXPIRY_INVALID", "category attestation expiry is outside the mandate lifetime");
  if (envelope.expiresAt > envelope.issuedAt + MAX_MARKETPLACE_CATEGORY_ATTESTATION_TTL_SECONDS)
    throw categoryError("ATTESTATION_TTL_EXCEEDED", "category attestation exceeds the maximum TTL");
  if (envelope.expiresAt <= input.evaluatedAt)
    throw categoryError("ATTESTATION_EXPIRED", "category attestation has expired");
  if (envelope.payload.observedAt > envelope.issuedAt)
    throw categoryError("ATTESTATION_OBSERVATION_AFTER_ISSUANCE", "category evidence was observed after issuance");
  if (envelope.payload.observedAt < request.mandate.createdAt)
    throw categoryError("CATEGORY_ATTESTATION_EVIDENCE_STALE", "category evidence predates the mandate");
  if (envelope.payload.observedAt > input.evaluatedAt + request.mandate.maxClockSkewSeconds)
    throw categoryError("ATTESTATION_NOT_YET_VALID", "category evidence is observed after the evaluation window");
  if (
    input.evaluatedAt - envelope.payload.observedAt >
    request.mandate.maxEvidenceAgeSeconds
  )
    throw categoryError("CATEGORY_ATTESTATION_EVIDENCE_STALE", "category evidence is older than the mandate permits");
  if (input.evaluatedAt < request.mandate.createdAt)
    throw categoryError("EVALUATED_AT_INVALID", "category evaluation predates the mandate");

  const { signature: _signature, ...unsigned } = envelope;
  let validSignature = false;
  try {
    validSignature = verifyEd25519(
      null,
      marketplaceCategoryAttestationSigningMessage(unsigned),
      input.trust.publicKey,
      Buffer.from(envelope.signature, "hex"),
    );
  } catch {
    validSignature = false;
  }
  if (!validSignature)
    throw categoryError("ATTESTATION_SIGNATURE_INVALID", "category attestation signature is invalid");
  // Both bounds are exclusive. Evidence is valid through maxEvidenceAgeSeconds,
  // so the next whole Unix second is the first stale one.
  const validUntil = Math.min(
    envelope.expiresAt,
    envelope.payload.observedAt + request.mandate.maxEvidenceAgeSeconds + 1,
  );
  return deepFreeze({
    envelope,
    attestationSha256: canonicalSha256(envelope),
    publicKeyFingerprintSha256: input.trust.publicKeyFingerprintSha256,
    validUntil,
  });
}

function parseCategoryWire(wire: MarketplaceCategoryAttestationWire): MarketplaceCategoryAttestation {
  if (!(typeof wire === "string" || wire instanceof Uint8Array)) throw categoryError("ATTESTATION_INPUT_INVALID", "category attestation wire must be UTF-8 text or bytes");
  const bytes = typeof wire === "string" ? Buffer.from(wire, "utf8") : Buffer.from(wire);
  if (bytes.byteLength > MAX_MARKETPLACE_CATEGORY_ATTESTATION_BYTES) throw categoryError("ATTESTATION_TOO_LARGE", "category attestation exceeds the byte limit");
  let text: string;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch (cause) { throw categoryError("ATTESTATION_UTF8_INVALID", "category attestation is not valid UTF-8", cause); }
  if (text.charCodeAt(0) === 0xfeff) throw categoryError("ATTESTATION_UTF8_INVALID", "category attestation must not contain a BOM");
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch (cause) { throw categoryError("ATTESTATION_JSON_INVALID", "category attestation is not valid JSON", cause); }
  let envelope: MarketplaceCategoryAttestation;
  try { envelope = marketplaceCategoryAttestationSchema.parse(parsed); } catch (cause) { throw categoryError("ATTESTATION_SCHEMA_INVALID", "category attestation does not match the strict wire schema", cause); }
  if (canonicalJson(envelope) !== text) throw categoryError("ATTESTATION_NONCANONICAL", "category attestation is not canonical JSON");
  return envelope;
}

type CategoryErrorCode =
  | "ATTESTATION_TRUST_INVALID"
  | "ATTESTATION_KEY_MISMATCH"
  | "ATTESTATION_POLICY_MISMATCH"
  | "ATTESTATION_MANDATE_HASH_MISMATCH"
  | "CATEGORY_ATTESTATION_REQUEST_HASH_MISMATCH"
  | "CATEGORY_ATTESTATION_ADAPTER_MISMATCH"
  | "CATEGORY_ATTESTATION_REQUEST_MISMATCH"
  | "CATEGORY_ATTESTATION_CANDIDATE_MISMATCH"
  | "CATEGORY_REQUEST_INVALID"
  | "CATEGORY_ATTESTATION_SUBJECT_MISMATCH"
  | "CATEGORY_ATTESTATION_POLICY_BINDING_MISMATCH"
  | "CATEGORY_ATTESTATION_DEPLOYMENT_MISMATCH"
  | "CATEGORY_ATTESTATION_EVIDENCE_STALE"
  | "EVALUATED_AT_INVALID"
  | "ATTESTATION_NOT_YET_VALID"
  | "ATTESTATION_EXPIRY_INVALID"
  | "ATTESTATION_TTL_EXCEEDED"
  | "ATTESTATION_EXPIRED"
  | "ATTESTATION_OBSERVATION_AFTER_ISSUANCE"
  | "ATTESTATION_SIGNATURE_INVALID"
  | "ATTESTATION_INPUT_INVALID"
  | "ATTESTATION_TOO_LARGE"
  | "ATTESTATION_UTF8_INVALID"
  | "ATTESTATION_JSON_INVALID"
  | "ATTESTATION_SCHEMA_INVALID"
  | "ATTESTATION_NONCANONICAL";

function categoryError(code: CategoryErrorCode, message: string, cause?: unknown): MarketplaceCoreError {
  return new MarketplaceCoreError(code, message, cause === undefined ? undefined : { cause });
}
