import {
  createHash,
  createPublicKey,
  verify as verifyEd25519,
  type KeyObject,
} from "node:crypto";

import { z } from "zod";

import { canonicalJson, canonicalSha256 } from "./canonical.js";
import { MarketplaceCoreError } from "./errors.js";
import { deepFreeze, type DeepReadonly } from "./immutable.js";
import {
  canonicalIdentifierSchema,
  sha256Schema,
  unixSecondsSchema,
} from "./primitives.js";
import {
  displaySafeQuoteProjectionPayloadSchema,
  type DisplaySafeQuoteProjectionPayload,
  type MarketplaceMandate,
} from "./schemas.js";

export const MARKETPLACE_EVALUATION_ATTESTATION_SCHEMA =
  "mandatex.marketplace.evaluation-attestation.v1" as const;
export const MARKETPLACE_ATTESTATION_SIGNATURE_PROFILE =
  "mandatex-ed25519-v1" as const;
export const MARKETPLACE_ATTESTATION_ISSUER =
  "mandatex-agent-supply-verifier" as const;
export const MARKETPLACE_ATTESTATION_AUDIENCE =
  "mandatex-marketplace-core" as const;
export const MARKETPLACE_ATTESTATION_SIGNING_DOMAIN =
  "MandateX Marketplace Evaluation Attestation v1\0" as const;
export const MAX_MARKETPLACE_ATTESTATION_BYTES = 131_072 as const;
export const MAX_MARKETPLACE_ATTESTATION_TTL_SECONDS = 300 as const;

const signatureSchema = z
  .string()
  .regex(/^[a-f0-9]{128}$/, "expected a 64-byte lowercase hex signature");

const unsignedShape = {
  schema: z.literal(MARKETPLACE_EVALUATION_ATTESTATION_SCHEMA),
  signatureProfile: z.literal(MARKETPLACE_ATTESTATION_SIGNATURE_PROFILE),
  issuer: z.literal(MARKETPLACE_ATTESTATION_ISSUER),
  audience: z.literal(MARKETPLACE_ATTESTATION_AUDIENCE),
  keyId: canonicalIdentifierSchema,
  attestationId: canonicalIdentifierSchema,
  scope: z.literal("evaluation_only"),
  activationAuthorization: z.literal("none"),
  reservation: z.literal("none"),
  replayPolicy: z.literal("reusable_until_expiry"),
  issuedAt: unixSecondsSchema,
  expiresAt: unixSecondsSchema,
  mandateSha256: sha256Schema,
  payloadSha256: sha256Schema,
  verifierPolicySha256: sha256Schema,
  payload: displaySafeQuoteProjectionPayloadSchema,
} as const;

export const marketplaceEvaluationAttestationUnsignedSchema = z
  .object(unsignedShape)
  .strict();

export const marketplaceEvaluationAttestationSchema = z
  .object({ ...unsignedShape, signature: signatureSchema })
  .strict();

export type MarketplaceEvaluationAttestationUnsigned = DeepReadonly<
  z.infer<typeof marketplaceEvaluationAttestationUnsignedSchema>
>;
export type MarketplaceEvaluationAttestation = DeepReadonly<
  z.infer<typeof marketplaceEvaluationAttestationSchema>
>;
export type MarketplaceEvaluationAttestationWire = string | Uint8Array;

export type MarketplaceAttestationTrust = Readonly<{
  keyId: string;
  publicKeySpkiDer: Uint8Array;
  publicKeyFingerprintSha256: string;
  verifierPolicySha256: string;
}>;

export type ValidatedMarketplaceAttestationTrust = Readonly<{
  keyId: string;
  publicKey: KeyObject;
  publicKeyFingerprintSha256: string;
  verifierPolicySha256: string;
}>;

export type VerifiedMarketplaceEvaluationAttestation = DeepReadonly<{
  envelope: MarketplaceEvaluationAttestation;
  attestationSha256: string;
  publicKeyFingerprintSha256: string;
}>;

export function validateMarketplaceAttestationTrust(
  input: MarketplaceAttestationTrust,
): ValidatedMarketplaceAttestationTrust {
  if (input === null || typeof input !== "object") {
    throw trustError("pinned attestation trust must be an object");
  }
  if (
    typeof input.keyId !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(input.keyId)
  ) {
    throw trustError("pinned attestation key ID is invalid");
  }
  if (!(input.publicKeySpkiDer instanceof Uint8Array)) {
    throw trustError("pinned Ed25519 public key must be SPKI DER bytes");
  }
  if (!/^[a-f0-9]{64}$/.test(input.publicKeyFingerprintSha256)) {
    throw trustError("pinned public-key fingerprint is invalid");
  }
  if (!/^[a-f0-9]{64}$/.test(input.verifierPolicySha256)) {
    throw trustError("pinned verifier-policy hash is invalid");
  }

  try {
    const suppliedDer = Buffer.from(input.publicKeySpkiDer);
    const publicKey = createPublicKey({
      key: suppliedDer,
      format: "der",
      type: "spki",
    });
    if (publicKey.asymmetricKeyType !== "ed25519") {
      throw new TypeError("pinned public key is not Ed25519");
    }
    const exported = publicKey.export({ format: "der", type: "spki" });
    if (!Buffer.isBuffer(exported) || !exported.equals(suppliedDer)) {
      throw new TypeError("pinned public key is not canonical SPKI DER");
    }
    const fingerprint = createHash("sha256").update(exported).digest("hex");
    if (fingerprint !== input.publicKeyFingerprintSha256) {
      throw new TypeError("pinned public-key fingerprint does not match");
    }
    return Object.freeze({
      keyId: input.keyId,
      publicKey,
      publicKeyFingerprintSha256: fingerprint,
      verifierPolicySha256: input.verifierPolicySha256,
    });
  } catch (cause) {
    if (cause instanceof MarketplaceCoreError) throw cause;
    throw trustError("pinned Ed25519 public key is invalid", cause);
  }
}

export function marketplaceEvaluationAttestationSigningMessage(
  input: unknown,
): Uint8Array {
  const unsigned = marketplaceEvaluationAttestationUnsignedSchema.parse(input);
  return Buffer.concat([
    Buffer.from(MARKETPLACE_ATTESTATION_SIGNING_DOMAIN, "utf8"),
    Buffer.from(canonicalJson(unsigned), "utf8"),
  ]);
}

export function serializeMarketplaceEvaluationAttestation(
  input: unknown,
): string {
  return canonicalJson(marketplaceEvaluationAttestationSchema.parse(input));
}

export function verifyMarketplaceEvaluationAttestation(input: {
  readonly wire: MarketplaceEvaluationAttestationWire;
  readonly mandate: MarketplaceMandate;
  readonly evaluatedAt: number;
  readonly maxClockSkewSeconds: number;
  readonly trust: ValidatedMarketplaceAttestationTrust;
}): VerifiedMarketplaceEvaluationAttestation {
  const wireText = decodeWire(input.wire);
  const raw = parseCanonicalJson(wireText);
  const parsed = marketplaceEvaluationAttestationSchema.safeParse(raw);
  if (!parsed.success) {
    throw new MarketplaceCoreError(
      "ATTESTATION_SCHEMA_INVALID",
      "evaluation attestation does not match the fixed v2 wire schema",
      { cause: parsed.error },
    );
  }
  const envelope = parsed.data;
  if (canonicalJson(envelope) !== wireText) {
    throw new MarketplaceCoreError(
      "ATTESTATION_NONCANONICAL",
      "evaluation attestation is not canonical wire JSON",
    );
  }
  if (envelope.keyId !== input.trust.keyId) {
    throw new MarketplaceCoreError(
      "ATTESTATION_KEY_MISMATCH",
      "evaluation attestation does not use the pinned verifier key",
    );
  }
  if (envelope.verifierPolicySha256 !== input.trust.verifierPolicySha256) {
    throw new MarketplaceCoreError(
      "ATTESTATION_POLICY_MISMATCH",
      "evaluation attestation verifier-policy hash is not pinned",
    );
  }

  const skew = input.maxClockSkewSeconds;
  if (!Number.isSafeInteger(skew) || skew < 0 || skew > 300) {
    throw new MarketplaceCoreError(
      "ATTESTATION_TRUST_INVALID",
      "attestation clock skew must be an integer from zero to 300 seconds",
    );
  }
  if (envelope.issuedAt > input.evaluatedAt + skew) {
    throw new MarketplaceCoreError(
      "ATTESTATION_NOT_YET_VALID",
      "evaluation attestation issuance time is in the future",
    );
  }
  if (envelope.expiresAt <= envelope.issuedAt) {
    throw new MarketplaceCoreError(
      "ATTESTATION_EXPIRY_INVALID",
      "evaluation attestation expiry must follow issuance",
    );
  }
  if (
    envelope.expiresAt - envelope.issuedAt >
    MAX_MARKETPLACE_ATTESTATION_TTL_SECONDS
  ) {
    throw new MarketplaceCoreError(
      "ATTESTATION_TTL_EXCEEDED",
      "evaluation attestation exceeds the 300-second maximum TTL",
    );
  }
  if (envelope.expiresAt > envelope.payload.expiresAt) {
    throw new MarketplaceCoreError(
      "ATTESTATION_EXPIRY_INVALID",
      "evaluation attestation outlives its quote payload",
    );
  }
  if (envelope.expiresAt <= input.evaluatedAt) {
    throw new MarketplaceCoreError(
      "ATTESTATION_EXPIRED",
      "evaluation attestation has expired",
    );
  }
  if (envelope.mandateSha256 !== canonicalSha256(input.mandate)) {
    throw new MarketplaceCoreError(
      "ATTESTATION_MANDATE_HASH_MISMATCH",
      "evaluation attestation is bound to a different mandate",
    );
  }
  if (envelope.payloadSha256 !== canonicalSha256(envelope.payload)) {
    throw new MarketplaceCoreError(
      "ATTESTATION_PAYLOAD_HASH_MISMATCH",
      "evaluation attestation payload hash does not match its payload",
    );
  }
  assertObservationChronology(envelope.payload, envelope.issuedAt);

  const unsigned = unsignedEnvelope(envelope);
  let validSignature = false;
  try {
    validSignature = verifyEd25519(
      null,
      marketplaceEvaluationAttestationSigningMessage(unsigned),
      input.trust.publicKey,
      Buffer.from(envelope.signature, "hex"),
    );
  } catch {
    validSignature = false;
  }
  if (!validSignature) {
    throw new MarketplaceCoreError(
      "ATTESTATION_SIGNATURE_INVALID",
      "evaluation attestation Ed25519 signature is invalid",
    );
  }

  return deepFreeze({
    envelope,
    attestationSha256: createHash("sha256")
      .update(wireText, "utf8")
      .digest("hex"),
    publicKeyFingerprintSha256: input.trust.publicKeyFingerprintSha256,
  });
}

function unsignedEnvelope(
  envelope: MarketplaceEvaluationAttestation,
): MarketplaceEvaluationAttestationUnsigned {
  return marketplaceEvaluationAttestationUnsignedSchema.parse({
    schema: envelope.schema,
    signatureProfile: envelope.signatureProfile,
    issuer: envelope.issuer,
    audience: envelope.audience,
    keyId: envelope.keyId,
    attestationId: envelope.attestationId,
    scope: envelope.scope,
    activationAuthorization: envelope.activationAuthorization,
    reservation: envelope.reservation,
    replayPolicy: envelope.replayPolicy,
    issuedAt: envelope.issuedAt,
    expiresAt: envelope.expiresAt,
    mandateSha256: envelope.mandateSha256,
    payloadSha256: envelope.payloadSha256,
    verifierPolicySha256: envelope.verifierPolicySha256,
    payload: envelope.payload,
  });
}

function decodeWire(wire: MarketplaceEvaluationAttestationWire): string {
  if (typeof wire !== "string" && !(wire instanceof Uint8Array)) {
    throw new MarketplaceCoreError(
      "ATTESTATION_INPUT_INVALID",
      "evaluation attestation input must be a UTF-8 string or byte array",
    );
  }
  const encodedBytes =
    typeof wire === "string" ? Buffer.byteLength(wire, "utf8") : wire.byteLength;
  if (encodedBytes > MAX_MARKETPLACE_ATTESTATION_BYTES) {
    throw new MarketplaceCoreError(
      "ATTESTATION_TOO_LARGE",
      "evaluation attestation exceeds 131072 encoded bytes",
    );
  }
  const bytes =
    typeof wire === "string" ? Buffer.from(wire, "utf8") : Buffer.from(wire);
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (typeof wire === "string" && decoded !== wire) {
      throw new TypeError("string is not stable UTF-8");
    }
    return decoded;
  } catch (cause) {
    throw new MarketplaceCoreError(
      "ATTESTATION_UTF8_INVALID",
      "evaluation attestation is not canonical UTF-8",
      { cause },
    );
  }
}

function parseCanonicalJson(wire: string): unknown {
  let raw: unknown;
  try {
    raw = JSON.parse(wire) as unknown;
  } catch (cause) {
    throw new MarketplaceCoreError(
      "ATTESTATION_JSON_INVALID",
      "evaluation attestation is not valid JSON",
      { cause },
    );
  }
  assertBoundedJsonShape(raw);
  let canonical: string;
  try {
    canonical = canonicalJson(raw);
  } catch (cause) {
    throw new MarketplaceCoreError(
      "ATTESTATION_NONCANONICAL",
      "evaluation attestation contains unsupported canonical JSON data",
      { cause },
    );
  }
  if (canonical !== wire) {
    throw new MarketplaceCoreError(
      "ATTESTATION_NONCANONICAL",
      "evaluation attestation contains whitespace, alternate spelling, duplicate keys, or noncanonical ordering",
    );
  }
  return raw;
}

function assertBoundedJsonShape(root: unknown): void {
  const pending: Array<Readonly<{ value: unknown; depth: number }>> = [
    { value: root, depth: 0 },
  ];
  let nodes = 0;
  while (pending.length > 0) {
    const current = pending.pop()!;
    nodes += 1;
    if (nodes > 4_096 || current.depth > 32) {
      throw new MarketplaceCoreError(
        "ATTESTATION_INPUT_INVALID",
        "evaluation attestation JSON structure exceeds safety bounds",
      );
    }
    if (current.value === null || typeof current.value !== "object") continue;
    const values = Array.isArray(current.value)
      ? current.value
      : Object.values(current.value as Record<string, unknown>);
    for (const value of values) {
      pending.push({ value, depth: current.depth + 1 });
    }
  }
}

function assertObservationChronology(
  payload: DisplaySafeQuoteProjectionPayload,
  issuedAt: number,
): void {
  const observations = [
    payload.observedAt,
    payload.estimates.observedAt,
    payload.reputation.observedAt,
    payload.categoryEvidence.observedAt,
    ...(payload.preview.status === "passed" ? [payload.preview.observedAt] : []),
  ];
  if (observations.some((observedAt) => observedAt > issuedAt)) {
    throw new MarketplaceCoreError(
      "ATTESTATION_OBSERVATION_AFTER_ISSUANCE",
      "evaluation attestation evidence was observed after issuance",
    );
  }
}

function trustError(message: string, cause?: unknown): MarketplaceCoreError {
  return new MarketplaceCoreError(
    "ATTESTATION_TRUST_INVALID",
    message,
    cause === undefined ? undefined : { cause },
  );
}
