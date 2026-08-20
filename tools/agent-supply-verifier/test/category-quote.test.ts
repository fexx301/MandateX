import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import {
  categoryQuoteCommitments,
  categoryQuoteEip191Message,
  categoryQuoteRequestKeccak256,
  createCategoryQuoteVerificationCapability,
  type CategoryQuoteEnvelope,
} from "../src/category/quote.js";
import {
  CATEGORY_CANDIDATE_IDENTITY_PROFILE,
  createCategoryCandidateIdentityCapability,
  type VerifiedCategoryCandidateIdentity,
} from "../src/category/identity.js";
import type {
  BoundedHttpResponse,
  TransportRoute,
} from "../src/transport/http.js";
import { hashMessage } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

const BLOCK_HASH = `0x${"ab".repeat(32)}`;
const REGISTRY = "0x8004a169fb4a3325136eb29fa0ceb6d2e539a432";
const VERIFYING_CONTRACT = `0x${"44".repeat(20)}`;
const OTHER_PROVIDER = `0x${"55".repeat(20)}`;
const HASH_A = "aa".repeat(32);
const HASH_B = "bb".repeat(32);
const HASH_C = "cc".repeat(32);
const EMPTY_ACTION_PERMISSIONS_SHA256 = createHash("sha256")
  .update("[]", "utf8")
  .digest("hex");

test("registered-owner EIP-191 quote is capability-backed and reusable until expiry", async () => {
  const scenario = await makeFixture("eoa");
  const verified = await scenario.capability.verifyAccepted(
    scenario.verificationInput,
  );
  const reused = await scenario.capability.verifyAccepted(
    scenario.verificationInput,
  );

  assert.equal(verified.expectedProvider, scenario.owner);
  assert.equal(verified.registeredOwner, scenario.owner);
  assert.equal(verified.validatedProvider, scenario.owner);
  assert.equal(verified.validatedSigner, scenario.owner);
  assert.equal(verified.signatureMethod, "eip191");
  assert.equal(verified.replayPolicy, "reusable_until_expiry");
  assert.equal(verified.scope, "evaluation_only");
  assert.equal(verified.activationAuthorization, "none");
  assert.equal(verified.reservation, "none");
  assert.equal(verified.mandateSha256, HASH_A);
  assert.equal(verified.categoryQuoteRequestSha256, HASH_B);
  assert.equal(verified.actionPermissionsSha256, EMPTY_ACTION_PERMISSIONS_SHA256);
  assert.equal(Object.isFrozen(verified), true);
  assert.notEqual(reused, verified);
  assert.equal(scenario.erc1271Checks.length, 0);


  assert.doesNotThrow(() =>
    scenario.capability.assertVerified(verified, {
      identity: scenario.identity,
      expectedRequest: scenario.expectedRequest,
    }),
  );
  assert.throws(
    () =>
      scenario.capability.assertVerified({ ...verified }, {
        identity: scenario.identity,
        expectedRequest: scenario.expectedRequest,
      }),
    /provenance/,
  );
});

test("registered-owner ERC-1271 check receives the EIP-191 digest at the identity block", async () => {
  const scenario = await makeFixture("erc1271");
  const verified = await scenario.capability.verifyAccepted(
    scenario.verificationInput,
  );

  assert.equal(verified.signatureMethod, "erc1271");
  assert.equal(verified.validatedSigner, scenario.identity.ownerAddress);
  assert.equal(scenario.erc1271Checks.length, 1);
  assert.deepEqual(scenario.erc1271Checks[0], {
    provider: scenario.owner,
    messageDigest: hashMessage(
      categoryQuoteEip191Message(scenario.envelope.negotiationKeccak256),
    ),
    signature: "0x1234",
    verifyingContract: VERIFYING_CONTRACT,
    identityBlock: scenario.identity.observedBlock,
    identityBlockHash: scenario.identity.observedBlockHash,
  });
});

test("owner, domain, audience, nonce, commitments, signature, and expiry mutations fail closed", async (t) => {
  const mutations: ReadonlyArray<
    readonly [string, (envelope: MutableEnvelope) => void]
  > = [
    [
      "registered owner",
      (envelope) => {
        envelope.challenge.registeredOwner = OTHER_PROVIDER;
      },
    ],
    [
      "response provider",
      (envelope) => {
        envelope.response.providerAddress = OTHER_PROVIDER;
      },
    ],
    [
      "signing domain",
      (envelope) => {
        envelope.challenge.signingDomain = "Other Category Quote";
      },
    ],
    [
      "audience",
      (envelope) => {
        envelope.challenge.audience = "other-audience";
      },
    ],
    [
      "nonce",
      (envelope) => {
        envelope.challenge.nonce = "other-nonce";
      },
    ],
    [
      "mandate digest",
      (envelope) => {
        envelope.challenge.mandateSha256 = HASH_C;
      },
    ],
    [
      "request commitment",
      (envelope) => {
        envelope.requestKeccak256 = `0x${"00".repeat(32)}`;
      },
    ],
    [
      "response commitment",
      (envelope) => {
        envelope.responseKeccak256 = `0x${"00".repeat(32)}`;
      },
    ],
    [
      "negotiation commitment",
      (envelope) => {
        envelope.negotiationKeccak256 = `0x${"00".repeat(32)}`;
      },
    ],
    [
      "signature",
      (envelope) => {
        envelope.providerSignature = `0x${"00".repeat(65)}`;
      },
    ],
    [
      "quote expiry",
      (envelope) => {
        envelope.response.quoteExpiresAt = 1_120;
      },
    ],
    [
      "quote endpoint digest",
      (envelope) => {
        envelope.challenge.quoteEndpointSha256 = HASH_A;
      },
    ],
    [
      "clock skew policy",
      (envelope) => {
        envelope.challenge.maxClockSkewSeconds = 31;
      },
    ],
  ];

  for (const [name, mutate] of mutations) {
    await t.test(name, async () => {
      const scenario = await makeFixture("eoa");
      const envelope = structuredClone(
        scenario.envelope,
      ) as MutableEnvelope;
      mutate(envelope);
      await assert.rejects(
        scenario.capability.verifyAccepted({
          ...scenario.verificationInput,
          envelope,
        }),
      );
    });
  }

  const wrongProvider = await makeFixture("eoa");
  await assert.rejects(
    wrongProvider.capability.verifyAccepted({
      ...wrongProvider.verificationInput,
      expectedProvider: OTHER_PROVIDER,
    }),
    /untrusted quote domain/,
  );

  const wrongRequest = await makeFixture("eoa");
  await assert.rejects(
    wrongRequest.capability.verifyAccepted({
      ...wrongRequest.verificationInput,
      expectedRequest: {
        ...wrongRequest.expectedRequest,
        categoryQuoteRequestSha256: HASH_C,
      },
    }),
    /another marketplace request/,
  );

  const wrongKind = await makeFixture("eoa");
  const wrongKindEnvelope = structuredClone(
    wrongKind.envelope,
  ) as MutableEnvelope;
  wrongKindEnvelope.challenge.providerKind = "erc1271";
  wrongKindEnvelope.response.providerKind = "erc1271";
  await assert.rejects(
    wrongKind.capability.verifyAccepted({
      ...wrongKind.verificationInput,
      envelope: wrongKindEnvelope,
    }),
    /identity|commitment|provider/,
  );
});

test("fabricated quotes and identities from another runtime capability fail provenance", async () => {
  const scenario = await makeFixture("eoa");
  const verified = await scenario.capability.verifyAccepted(
    scenario.verificationInput,
  );
  assert.throws(
    () =>
      scenario.capability.assertVerified(structuredClone(verified), {
        identity: scenario.identity,
        expectedRequest: scenario.expectedRequest,
      }),
    /provenance/,
  );
  assert.throws(
    () =>
      scenario.capability.assertVerified(verified, {
        identity: scenario.identity,
        expectedRequest: {
          ...scenario.expectedRequest,
          requestId: "request-2",
        },
      }),
    /provenance/,
  );

  const otherIdentityCapability = createCategoryCandidateIdentityCapability({
    transport: identityTransport(scenario.owner),
    registryAddress: REGISTRY,
  });
  const otherIdentityResult = await otherIdentityCapability.capture({
    chainId: 56,
    tokenId: "7",
  });
  assert.equal(otherIdentityResult.outcome, "verified");
  if (otherIdentityResult.outcome !== "verified") return;
  await assert.rejects(
    scenario.capability.verifyAccepted({
      ...scenario.verificationInput,
      identity: otherIdentityResult.identity,
    }),
    /provenance/,
  );
});

test("wire values must be canonical strict data", async () => {
  const mixedCase = await makeFixture("eoa");
  const mixedCaseEnvelope = structuredClone(
    mixedCase.envelope,
  ) as MutableEnvelope;
  mixedCaseEnvelope.challenge.verifyingContract = `0x${"AA".repeat(20)}`;
  await assert.rejects(
    mixedCase.capability.verifyAccepted({
      ...mixedCase.verificationInput,
      envelope: mixedCaseEnvelope,
    }),
  );

  const extraField = await makeFixture("eoa");
  const extraEnvelope = structuredClone(extraField.envelope) as MutableEnvelope;
  (extraEnvelope.challenge as Record<string, unknown>).extra = true;
  await assert.rejects(
    extraField.capability.verifyAccepted({
      ...extraField.verificationInput,
      envelope: extraEnvelope,
    }),
  );

  const accessor = await makeFixture("eoa");
  const accessorEnvelope = structuredClone(accessor.envelope) as MutableEnvelope;
  Object.defineProperty(accessorEnvelope, "providerSignature", {
    enumerable: true,
    get: () => accessor.envelope.providerSignature,
  });
  await assert.rejects(
    accessor.capability.verifyAccepted({
      ...accessor.verificationInput,
      envelope: accessorEnvelope,
    }),
    /data properties/,
  );
});

test("expiry is rechecked after an asynchronous ERC-1271 decision", async () => {
  let now = 1_120;
  const scenario = await makeFixture("erc1271", {
    clock: () => now,
    onErc1271Check: () => {
      now = 1_260;
    },
  });
  await assert.rejects(
    scenario.capability.verifyAccepted(scenario.verificationInput),
    /validity window/,
  );
});

test("provider quote lifetime cannot exceed the category TTL", async () => {
  const scenario = await makeFixture("eoa");
  const envelope = structuredClone(scenario.envelope) as MutableEnvelope;
  envelope.challenge.issuedAt = 1_100;
  envelope.challenge.expiresAt = 1_400;
  envelope.challenge.permissionsExpiresAt = 1_400;
  envelope.response.negotiatedAt = 1_099;
  envelope.response.quoteExpiresAt = 1_400;
  envelope.response.requestKeccak256 = categoryQuoteRequestKeccak256(
    envelope.challenge,
  );
  const commitments = categoryQuoteCommitments({
    challenge: envelope.challenge,
    response: envelope.response,
  });
  envelope.requestKeccak256 = commitments.requestKeccak256;
  envelope.responseKeccak256 = commitments.responseKeccak256;
  envelope.negotiationKeccak256 = commitments.negotiationKeccak256;
  await assert.rejects(
    scenario.capability.verifyAccepted({
      ...scenario.verificationInput,
      envelope,
      expectedRequest: {
        ...scenario.expectedRequest,
        issuedAt: 1_100,
        expiresAt: 1_400,
        permissionsExpiresAt: 1_400,
      },
    }),
    /chronology/,
  );
});

type MutableEnvelope = {
  -readonly [Key in keyof CategoryQuoteEnvelope]: CategoryQuoteEnvelope[Key] extends object
    ? { -readonly [Nested in keyof CategoryQuoteEnvelope[Key]]: any }
    : any;
};

async function makeFixture(
  providerKind: "eoa" | "erc1271",
  options: {
    readonly clock?: () => number;
    readonly onErc1271Check?: () => void;
    readonly erc1271Result?: boolean;
  } = {},
) {
  const account = privateKeyToAccount(generatePrivateKey());
  const owner = account.address.toLowerCase();
  const identityCapability = createCategoryCandidateIdentityCapability({
    transport: identityTransport(owner, providerKind),
    registryAddress: REGISTRY,
  });
  const identityResult = await identityCapability.capture({
    chainId: 56,
    tokenId: "7",
  });
  assert.equal(identityResult.outcome, "verified");
  if (identityResult.outcome !== "verified") {
    throw new Error("identity fixture failed");
  }
  const identity = identityResult.identity;
  const challenge = {
    schema: "mandatex.agent-supply.category-quote-challenge.v1",
    verificationProfile: "mandatex.agent-supply.category-quote-verification.v1",
    audience: "mandatex-category-quote-verifier",
    signingDomain: "MandateX Category Quote v1",
    chainId: 56,
    verifyingContract: VERIFYING_CONTRACT,
    scope: "evaluation_only",
    activationAuthorization: "none",
    reservation: "none",
    replayPolicy: "reusable_until_expiry",
    relation: "candidate_accepts_service_for_subject",
    providerAuthority: "erc8004_registered_owner",
    requestId: "request-1",
    mandateSha256: HASH_A,
    categoryQuoteRequestSha256: HASH_B,
    candidate: { chainId: 56, tokenId: "7" },
    identityVerificationProfile: CATEGORY_CANDIDATE_IDENTITY_PROFILE,
    candidateIdentitySha256: identity.identitySha256,
    registryAddress: identity.registryAddress,
    registryCodeSha256: identity.registryCodeSha256,
    registeredOwner: owner,
    providerKind: identityCapability
      .providerFor(identity, { chainId: 56, tokenId: "7" })
      .providerKind,
    providerCodeSha256: identityCapability
      .providerFor(identity, { chainId: 56, tokenId: "7" })
      .providerCodeSha256,
    category: "grid",
    adapterId: "pancakeswap-v3-grid-v1",
    protocol: "pancakeswap-v3",
    serviceMode: "observe_only",
    subjectSha256: HASH_A,
    conditionPolicySha256: HASH_B,
    actionPermissionsSha256: EMPTY_ACTION_PERMISSIONS_SHA256,
    maxSpendUsdMicros: "0",
    permissionsExpiresAt: 1_280,
    quoteEndpointSha256: HASH_C,
    nonce: "nonce-1",
    issuedAt: 1_100,
    expiresAt: 1_290,
    maxClockSkewSeconds: 30,
  } as const;
  const requestKeccak256 = categoryQuoteRequestKeccak256(challenge);
  const response = {
    schema: "mandatex.agent-supply.category-quote-response.v1",
    accepted: true,
    relation: "candidate_accepts_service_for_subject",
    providerAuthority: "erc8004_registered_owner",
    providerAddress: owner,
    providerKind: identityCapability
      .providerFor(identity, { chainId: 56, tokenId: "7" })
      .providerKind,
    requestKeccak256,
    negotiatedAt: 1_110,
    quoteExpiresAt: 1_260,
  } as const;
  const commitments = categoryQuoteCommitments({ challenge, response });
  const providerSignature =
    providerKind === "eoa"
      ? await account.signMessage({
          message: categoryQuoteEip191Message(
            commitments.negotiationKeccak256,
          ),
        })
      : "0x1234";
  const envelope = {
    schema: "mandatex.agent-supply.category-quote-envelope.v1",
    challenge,
    response,
    requestKeccak256: commitments.requestKeccak256,
    responseKeccak256: commitments.responseKeccak256,
    negotiationKeccak256: commitments.negotiationKeccak256,
    providerSignature,
  } as const;
  const expectedRequest = {
    requestId: challenge.requestId,
    mandateSha256: challenge.mandateSha256,
    categoryQuoteRequestSha256: challenge.categoryQuoteRequestSha256,
    candidate: challenge.candidate,
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
    expiresAt: challenge.expiresAt,
    maxClockSkewSeconds: challenge.maxClockSkewSeconds,
  } as const;
  const erc1271Checks: Record<string, unknown>[] = [];
  const capability = createCategoryQuoteVerificationCapability({
    identityCapability,
    verifyingContract: VERIFYING_CONTRACT,
    clock: options.clock ?? (() => 1_120),
    erc1271Check: async (input) => {
      erc1271Checks.push(input);
      options.onErc1271Check?.();
      return options.erc1271Result ?? true;
    },
  });
  const verificationInput = {
    envelope,
    identity,
    expectedProvider: owner,
    expectedRequest,
  } as const;
  return {
    capability,
    envelope,
    erc1271Checks,
    expectedRequest,
    identity,
    owner,
    verificationInput,
  };
}

function identityTransport(owner: string, providerKind: "eoa" | "erc1271" = "eoa") {
  let count = 0;
  return {
    async request(route: TransportRoute): Promise<BoundedHttpResponse> {
      assert.ok(route.kind === "bsc-rpc" || route.kind === "bsc-quote-rpc");
      if (route.kind !== "bsc-rpc" && route.kind !== "bsc-quote-rpc") {
        throw new Error("unexpected route");
      }
      const request = JSON.parse(route.body) as {
        method: string;
        id: string;
        params?: readonly unknown[];
      };
      const result = (() => {
        switch (request.method) {
          case "eth_chainId":
            return "0x38";
          case "eth_blockNumber":
            return "0x64";
          case "eth_getBlockByNumber":
            return { number: "0x62", hash: BLOCK_HASH };
          case "eth_getCode":
            return request.params?.[0] === owner
              ? providerKind === "eoa"
                ? "0x"
                : "0x60006000"
              : "0x60006000";
          case "eth_call":
            return `0x${"0".repeat(24)}${owner.slice(2)}`;
          default:
            throw new Error("unexpected method");
        }
      })();
      const body = Buffer.from(
        JSON.stringify({ jsonrpc: "2.0", id: request.id, result }),
      );
      count += 1;
      return {
        status: 200,
        contentType: "application/json",
        retryAfter: null,
        rateLimitRemaining: null,
        body,
        responseSha256: createHash("sha256").update(body).digest("hex"),
        resolvedAddress: "1.1.1.1",
        startedAt: `1970-01-01T00:18:${String(count).padStart(2, "0")}.000Z`,
        finishedAt: `1970-01-01T00:18:${String(count).padStart(2, "0")}.010Z`,
        latencyMs: 10,
      };
    },
  };
}

void (null as VerifiedCategoryCandidateIdentity | null);
