import assert from "node:assert/strict";
import test from "node:test";

import {
  buildQuoteSidecar,
  serializeQuoteSidecar,
  serializeQuoteTrustFile,
} from "../src/quotes/protocol.js";
import { DEFAULT_CHAIN_PROFILE } from "../src/policy.js";
import {
  MAX_CLOCK_SKEW_SECONDS,
  MAX_PASSIVE_AGE_SECONDS,
  MIN_QUOTE_REMAINING_SECONDS,
  QUOTE_TRUST_SCHEMA,
  quoteAcceptedEnvelopeSchema,
  quoteSidecarSchema,
  quoteTrustFileSchema,
  type QuoteValidationGates,
} from "../src/quotes/schema.js";

const PROVIDER = `0x${"1".repeat(40)}`;
const COMMERCE = `0x${"2".repeat(40)}`;
const CURRENCY = `0x${"3".repeat(40)}`;
const REQUEST_HASH = `0x${"a".repeat(64)}`;
const RESPONSE_HASH = `0x${"b".repeat(64)}`;
const NEGOTIATION_HASH = `0x${"c".repeat(64)}`;
const RAW_TASK = "RAW_TASK_SECRET";
const RAW_TERMS = "RAW_TERMS_SECRET";
const RAW_SIGNATURE = "0xfeedface";
const RAW_REFUSAL = "RAW_REFUSAL_SECRET";

test("quote sidecar serialization is deterministic and contains only redacted verification evidence", () => {
  const envelope = acceptedEnvelope();
  const sidecar = buildQuoteSidecar({
    ...baseInput(),
    outcome: "valid",
    a2aResponseSha256: "7".repeat(64),
    validatedProvider: PROVIDER,
    signatureMethod: "eip191",
    replayKey: "8".repeat(64),
    replayStatus: "claimed",
    gates: passGates(),
    envelope,
  });

  const first = serializeQuoteSidecar(sidecar);
  const second = serializeQuoteSidecar(structuredClone(sidecar));
  assert.equal(first, second);
  assert.ok(first.endsWith("\n"));
  assert.equal(
    sidecar.schema,
    "mandatex.agent-supply.quote-validation.v1",
  );
  assert.equal(sidecar.requestHash, REQUEST_HASH);
  assert.equal(sidecar.responseHash, RESPONSE_HASH);
  assert.equal(sidecar.negotiationHash, NEGOTIATION_HASH);

  for (const secret of [
    RAW_TASK,
    RAW_TERMS,
    RAW_SIGNATURE,
    "987654321",
    CURRENCY,
  ]) {
    assert.equal(first.includes(secret), false, secret);
  }
  assert.doesNotMatch(
    first,
    /"(?:mandate|request|response|task_description|terms|price|currency|estimated_completion_seconds|provider_sig|messageId|taskId|contextId|rpcId|reason)"/i,
  );
});

test("strict sidecar schema rejects raw quote material and protocol identifiers", () => {
  const sidecar = buildQuoteSidecar({
    ...baseInput(),
    outcome: "inconclusive",
    replayStatus: "not_attempted",
    gates: incompleteGates(),
    errorCode: "TRANSPORT_FAILED",
  });

  for (const injected of [
    { mandate: { secret: true } },
    { task_description: RAW_TASK },
    { terms: { deliverables: RAW_TERMS } },
    { price: "1" },
    { currency: CURRENCY },
    { provider_sig: RAW_SIGNATURE },
    { rawBody: "raw response body" },
    { messageId: "message-secret" },
    { taskId: "task-secret" },
    { contextId: "context-secret" },
    { refusalReason: RAW_REFUSAL },
  ]) {
    assert.throws(() => quoteSidecarSchema.parse({ ...sidecar, ...injected }));
  }
});

test("transport failures produce valid incomplete sidecars without response material", () => {
  const sidecar = buildQuoteSidecar({
    ...baseInput(),
    outcome: "inconclusive",
    replayStatus: "not_attempted",
    gates: incompleteGates(),
    errorCode: "TRANSPORT_FAILED",
  });
  assert.equal(sidecar.outcome, "inconclusive");
  assert.equal(sidecar.errorCode, "TRANSPORT_FAILED");
  assert.equal(sidecar.a2aResponseSha256, undefined);
  assert.equal(sidecar.requestHash, undefined);
  assert.equal(sidecar.negotiationHash, undefined);
  assert.equal(sidecar.replayKey, undefined);
  assert.doesNotThrow(() => serializeQuoteSidecar(sidecar));
});

test("valid sidecars retain the minimum quote lifetime at observation", () => {
  const envelope = acceptedEnvelope();
  const sidecar = buildQuoteSidecar({
    ...baseInput(),
    outcome: "valid",
    a2aResponseSha256: "7".repeat(64),
    validatedProvider: PROVIDER,
    signatureMethod: "eip191",
    replayKey: "8".repeat(64),
    replayStatus: "claimed",
    gates: passGates(),
    envelope,
  });
  const quoteExpiresAt = sidecar.quoteExpiresAt!;
  const boundaryObservedAt = new Date(
    (quoteExpiresAt - MIN_QUOTE_REMAINING_SECONDS) * 1_000,
  ).toISOString();
  const lateObservedAt = new Date(
    (quoteExpiresAt - MIN_QUOTE_REMAINING_SECONDS + 1) * 1_000,
  ).toISOString();

  assert.doesNotThrow(() =>
    quoteSidecarSchema.parse({ ...sidecar, observedAt: boundaryObservedAt }),
  );
  assert.throws(() =>
    quoteSidecarSchema.parse({ ...sidecar, observedAt: lateObservedAt }),
  );
});

test("refused sidecars retain only a stable code, never refusal text or the raw request", () => {
  const envelope = {
    request: { mandate: { private_note: "RAW_MANDATE_SECRET" } },
    request_hash: "",
    response: {
      accepted: false as const,
      reason_code: "0x03",
      reason: RAW_REFUSAL,
    },
    response_hash: "",
    negotiation_hash: "" as const,
    provider_sig: "" as const,
    mandatex: {
      eligible: false as const,
      refusal: {
        code: "RANGE_OUTSIDE_MANDATE",
        message: RAW_REFUSAL,
      },
    },
  };
  const sidecar = buildQuoteSidecar({
    ...baseInput(),
    outcome: "refused",
    a2aResponseSha256: "7".repeat(64),
    replayStatus: "not_attempted",
    gates: incompleteGates(),
    envelope,
  });
  const serialized = serializeQuoteSidecar(sidecar);
  assert.equal(sidecar.refusalCode, "RANGE_OUTSIDE_MANDATE");
  assert.equal(serialized.includes(RAW_REFUSAL), false);
  assert.equal(serialized.includes("RAW_MANDATE_SECRET"), false);
  assert.doesNotMatch(serialized, /"reason"|"request"|"mandate"/i);
});

test("quote trust files are strict, canonical, BSC-mainnet-only, and deterministic", () => {
  const trust = quoteTrustFileSchema.parse({
    schema: QUOTE_TRUST_SCHEMA,
    candidates: [trustEntry("10", "b"), trustEntry("2", "a")],
  });
  assert.deepEqual(
    trust.candidates.map((candidate) => candidate.tokenId),
    ["2", "10"],
  );
  assert.deepEqual(trust.candidates[0]?.allowedCurrencies, [
    `0x${"a".repeat(40)}`,
    `0x${"f".repeat(40)}`,
  ]);
  assert.equal(
    trust.candidates[0]?.registryAddress,
    DEFAULT_CHAIN_PROFILE.registryAddress,
  );
  assert.equal(
    serializeQuoteTrustFile(trust),
    serializeQuoteTrustFile(structuredClone(trust)),
  );

  assert.throws(() =>
    quoteTrustFileSchema.parse({
      schema: QUOTE_TRUST_SCHEMA,
      candidates: [{ ...trustEntry("1", "a"), chainId: 97 }],
    }),
  );
  assert.throws(() => {
    const { registryAddress: _registryAddress, ...missingRegistry } =
      trustEntry("1", "a");
    quoteTrustFileSchema.parse({
      schema: QUOTE_TRUST_SCHEMA,
      candidates: [missingRegistry],
    });
  });
  assert.throws(() =>
    quoteTrustFileSchema.parse({
      schema: QUOTE_TRUST_SCHEMA,
      candidates: [
        { ...trustEntry("1", "a"), quoteEndpoint: "https://a.example" },
      ],
    }),
  );
  assert.throws(() =>
    quoteTrustFileSchema.parse({
      schema: QUOTE_TRUST_SCHEMA,
      candidates: [{ ...trustEntry("1", "a"), maxQuoteTtlSeconds: 901 }],
    }),
  );
  assert.throws(() =>
    quoteTrustFileSchema.parse({
      schema: QUOTE_TRUST_SCHEMA,
      candidates: [
        {
          ...trustEntry("1", "a"),
          allowedCurrencies: [`0x${"a".repeat(40)}`, `0x${"A".repeat(40)}`],
        },
      ],
    }),
  );
  assert.throws(() =>
    quoteTrustFileSchema.parse({
      schema: QUOTE_TRUST_SCHEMA,
      candidates: [trustEntry("1", "a"), trustEntry("1", "b")],
    }),
  );
});

test("quote trust freshness values cannot exceed code-owned ceilings", () => {
  assert.throws(() =>
    quoteTrustFileSchema.parse({
      schema: QUOTE_TRUST_SCHEMA,
      candidates: [
        {
          ...trustEntry("1", "a"),
          maxPassiveAgeSeconds: MAX_PASSIVE_AGE_SECONDS + 1,
        },
      ],
    }),
  );
  assert.throws(() =>
    quoteTrustFileSchema.parse({
      schema: QUOTE_TRUST_SCHEMA,
      candidates: [
        {
          ...trustEntry("1", "a"),
          maxClockSkewSeconds: MAX_CLOCK_SKEW_SECONDS + 1,
        },
      ],
    }),
  );
});

function baseInput() {
  return {
    observedAt: "2026-08-16T12:00:00.000Z",
    candidate: { chainId: 56 as const, tokenId: "265375" },
    passiveReportSha256: "1".repeat(64),
    passiveCandidateSha256: "2".repeat(64),
    passivePolicyFingerprint: "3".repeat(64),
    trustPolicySha256: "4".repeat(64),
    quoteEndpoint: "https://agent.example/",
    a2aRequestSha256: "5".repeat(64),
    expectedProvider: PROVIDER,
    providerKind: "eoa" as const,
  };
}

function passGates(): QuoteValidationGates {
  return {
    passivePreflight: "pass",
    endpointBinding: "pass",
    quoteSignature: "pass",
    quotePolicy: "pass",
    replay: "pass",
  };
}

function incompleteGates(): QuoteValidationGates {
  return {
    passivePreflight: "pass",
    endpointBinding: "pass",
    quoteSignature: "unknown",
    quotePolicy: "unknown",
    replay: "unknown",
  };
}

function acceptedEnvelope() {
  return quoteAcceptedEnvelopeSchema.parse({
    request: {
      task_description: RAW_TASK,
      terms: {
        deliverables: RAW_TERMS,
        quality_standards: "RAW_QUALITY_SECRET",
        evaluation_required: true,
        evaluator_type: "uma_oov3",
      },
    },
    request_hash: REQUEST_HASH,
    response: {
      accepted: true,
      terms: {
        deliverables: RAW_TERMS,
        quality_standards: "RAW_QUALITY_SECRET",
        evaluation_required: true,
        evaluator_type: "uma_oov3",
        price: "987654321",
        currency: CURRENCY,
      },
      estimated_completion_seconds: 600,
      quote_expires_at: 1_800_000_600,
      negotiated_at: 1_800_000_000,
    },
    response_hash: RESPONSE_HASH,
    negotiation_hash: NEGOTIATION_HASH,
    provider_sig: RAW_SIGNATURE,
    chain_id: 56,
    verifying_contract: COMMERCE,
  });
}

function trustEntry(tokenId: string, host: string) {
  return {
    chainId: 56,
    registryAddress: `0x${DEFAULT_CHAIN_PROFILE.registryAddress
      .slice(2)
      .toUpperCase()}`,
    tokenId,
    category: "rebalancing",
    cardUrl: `https://${host}.example/.well-known/agent-card.json`,
    quoteEndpoint: `https://${host}.example/`,
    expectedProvider: `0x${"A".repeat(40)}`,
    providerKind: "eoa",
    commerceContract: COMMERCE,
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
    allowedCurrencies: [`0x${"F".repeat(40)}`, `0x${"a".repeat(40)}`],
    maxPrice: "1000000000000000000",
  };
}
