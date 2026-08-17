import assert from "node:assert/strict";
import { deflateRawSync } from "node:zlib";
import test from "node:test";

import { hashMessage, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import {
  buildQuoteA2aRequest,
  buildQuoteSignedContent,
  canonicalQuoteJson,
  computeQuoteNegotiationHash,
  computeQuoteReplayKey,
  computeQuoteRequestHash,
  computeQuoteResponseHash,
  decodeQuoteSignedTask,
  parseQuoteA2aResponse,
  QuoteProtocolError,
  sanitizeQuoteClaim,
  serializeQuoteA2aRequest,
  verifyQuoteEnvelope,
  verifyQuoteMandateBinding,
} from "../src/quotes/protocol.js";
import {
  quoteAcceptedEnvelopeSchema,
  quoteMandatexRebalanceMandateSchema,
  quoteMandatexSignedRebalanceTaskSchema,
  type QuoteAcceptedEnvelope,
  type QuoteEnvelope,
  type QuoteMandate,
  type QuoteMandatexSignedRebalanceTask,
  type QuoteProtocolErrorCode,
} from "../src/quotes/schema.js";
import { deriveNearestCenteredExactRange } from "../src/quotes/range.js";

const NOW = 1_800_000_000;
const PRIVATE_KEY = `0x${"11".repeat(32)}` as Hex;
const OTHER_PRIVATE_KEY = `0x${"22".repeat(32)}` as Hex;
const ACCOUNT = privateKeyToAccount(PRIVATE_KEY);
const OTHER_ACCOUNT = privateKeyToAccount(OTHER_PRIVATE_KEY);
const COMMERCE = `0x${"3".repeat(40)}`;
const CURRENCY = `0x${"4".repeat(40)}`;
const CONTRACT_PROVIDER = `0x${"5".repeat(40)}`;
const POOL = `0x${"a".repeat(40)}`;
const MANAGER = "0x46a15b0b27311cedf172ab29e4f4766fbe7f4364";
const OWNER = `0x${"c".repeat(40)}`;
const TOKEN0 = `0x${"d".repeat(40)}`;
const TOKEN1 = `0x${"e".repeat(40)}`;
const BLOCK_HASH = `0x${"ab".repeat(32)}`;
const REQUIRED_REBALANCE_CALLS = [
  "decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
  "collect((uint256,address,uint128,uint128))",
  "mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))",
] as const;

test("A2A request construction and response parsing enforce the exact negotiate contract", async () => {
  const request = buildQuoteA2aRequest({
    rpcId: "rpc-1",
    messageId: "message-1",
    mandate: rawMandate(),
  });
  assert.equal(request.method, "message/send");
  assert.equal(
    request.params.message.parts[0]?.data.skill,
    "negotiate",
  );
  assert.deepEqual(
    JSON.parse(serializeQuoteA2aRequest(request)),
    request,
  );

  const envelope = await acceptedEnvelope();
  const response = a2aResponse(envelope, "rpc-1");
  assert.deepEqual(
    parseQuoteA2aResponse(response, { expectedRpcId: "rpc-1" }),
    envelope,
  );

  assertProtocolError(
    () => parseQuoteA2aResponse("not-json"),
    "RESPONSE_JSON_INVALID",
  );
  assertProtocolError(
    () =>
      parseQuoteA2aResponse(response, {
        expectedRpcId: "different-rpc-id",
      }),
    "RPC_ID_MISMATCH",
  );
  assertProtocolError(
    () =>
      parseQuoteA2aResponse({
        jsonrpc: "2.0",
        id: "rpc-1",
        error: { code: -32_000, message: "provider unavailable" },
      }),
    "JSON_RPC_ERROR",
  );
  assertProtocolError(
    () => parseQuoteA2aResponse({ ...response, extra: true }),
    "RESPONSE_SCHEMA_INVALID",
  );
});

test("canonical hashes match pinned @bnbagent/sdk 0.5.0 vectors", () => {
  const request = {
    task_description: "Task [e]",
    terms: {
      deliverables: "D",
      quality_standards: "Q",
      evaluation_required: true,
      evaluator_type: "uma_oov3",
      success_criteria: ["alpha"],
    },
  };
  const response = {
    accepted: true as const,
    terms: {
      ...request.terms,
      price: "123",
      currency: CURRENCY,
    },
    estimated_completion_seconds: 45,
    quote_expires_at: NOW + 600,
    negotiated_at: NOW,
  };
  const envelope = quoteAcceptedEnvelopeSchema.parse({
    request,
    request_hash: `0x${"00".repeat(32)}`,
    response,
    response_hash: `0x${"00".repeat(32)}`,
    negotiation_hash: `0x${"00".repeat(32)}`,
    provider_sig: "0x00",
    chain_id: 56,
    verifying_contract: COMMERCE,
  });

  assert.equal(
    computeQuoteRequestHash(request),
    "0xaf415115810764cac5a1fcb56c494f042490cb3e2ace2522baf2d629177c34ab",
  );
  assert.equal(
    computeQuoteResponseHash(response),
    "0xf0aeb2ff62f1a77e782f5903df02599bd8354a53469daff2170f05fc51651f3a",
  );
  assert.deepEqual(buildQuoteSignedContent(envelope), {
    version: 1,
    negotiated_at: NOW,
    task: "Task (e)",
    terms: {
      deliverables: "D",
      quality_standards: "Q",
      success_criteria: ["alpha"],
    },
    price: "123",
    currency: CURRENCY,
    quote_expires_at: NOW + 600,
    chain_id: 56,
    verifying_contract: COMMERCE,
  });
  assert.equal(
    computeQuoteNegotiationHash(envelope),
    "0x241c92c36815457d6c88d4701c1ae5d8c893ff3742be0750f1cf614e044e9c41",
  );
  assert.equal(
    canonicalQuoteJson({ z: "é", a: [2, { y: 1, x: "\u007f" }] }),
    '{"a":[2,{"x":"\\u007f","y":1}],"z":"\\u00e9"}',
  );
  assert.equal(sanitizeQuoteClaim("a[b]\u0000\tb\nc\r"), "a(b)\tb\nc");
});

test("signed task decoding binds the quote to the normalized outbound mandate", async () => {
  const outbound = rawMandate();
  const envelope = await acceptedEnvelope(outbound);
  const binding = verifyQuoteMandateBinding({
    envelope,
    mandate: outbound,
    codec: "mandatex-rebalance:v1",
    now: NOW + 1,
  });
  assert.equal(binding.codec, "mandatex-rebalance:v1");
  assert.equal(binding.mandateSha256.length, 64);

  const decoded = decodeQuoteSignedTask(
    envelope.request.task_description,
    "mandatex-rebalance:v1",
  );
  assert.equal(decoded.mandate.position.token_id, "42");
  assert.deepEqual(decoded.mandate.permissions.allowed_calls, [
    "collect((uint256,address,uint128,uint128))",
    "decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
    "mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))",
  ]);

  const changed = structuredClone(outbound);
  const changedLimits = changed.limits as Record<string, QuoteMandate[string]>;
  changedLimits.max_gas_usd = 99;
  assertProtocolError(
    () =>
      verifyQuoteMandateBinding({
        envelope,
        mandate: changed,
        codec: "mandatex-rebalance:v1",
        now: NOW + 1,
      }),
    "MANDATE_BINDING_MISMATCH",
  );

  const displayTamper = structuredClone(envelope);
  if (displayTamper.mandatex !== undefined) {
    displayTamper.mandatex.observed_block += 1;
  }
  assertProtocolError(
    () =>
      verifyQuoteMandateBinding({
        envelope: displayTamper,
        mandate: outbound,
        codec: "mandatex-rebalance:v1",
        now: NOW + 1,
      }),
    "MANDATE_BINDING_MISMATCH",
  );

  assertProtocolError(
    () =>
      decodeQuoteSignedTask(
        "mandatex-rebalance:v1:not-base64!",
        "mandatex-rebalance:v1",
      ),
    "SIGNED_TASK_INVALID",
  );
});

test("signed task binding rejects evidence identity and freshness drift", async (t) => {
  const outbound = rawMandate();
  const envelope = await acceptedEnvelope(outbound);
  const mutations: ReadonlyArray<
    readonly [string, (task: QuoteMandatexSignedRebalanceTask) => void]
  > = [
    ["network", (task) => void (task.evidence.network = "bsc-testnet")],
    ["chain", (task) => void (task.evidence.chain_id = 97)],
    ["pool", (task) => void (task.evidence.pool_address = TOKEN0)],
    [
      "position manager",
      (task) => void (task.evidence.position_manager_address = TOKEN0),
    ],
    ["position token", (task) => void (task.evidence.position_token_id = "43")],
    [
      "source block",
      (task) => void (task.evidence.sources[0]!.observed_block += 1),
    ],
    ["stale evidence", (task) => void (task.evidence.observed_at = NOW - 121)],
    ["future evidence", (task) => void (task.evidence.observed_at = NOW + 16)],
    [
      "future eligibility",
      (task) => void (task.eligibility.checked_at = NOW + 17),
    ],
  ];

  for (const [name, mutate] of mutations) {
    await t.test(name, () => {
      assertBindingRejected(
        mutateSignedTaskEnvelope(envelope, mutate),
        outbound,
        NOW + 1,
      );
    });
  }

  await t.test("eligibility cannot postdate negotiation", () => {
    const postNegotiation = mutateSignedTaskEnvelope(envelope, (task) => {
      task.eligibility.checked_at = NOW + 16;
    });
    assertBindingRejected(postNegotiation, outbound, NOW + 20);
  });

  await t.test("evidence is fresh when signed but stale when verified", async () => {
    const evidenceOutbound = quoteMandatexRebalanceMandateSchema.parse(
      rawMandate(),
    );
    evidenceOutbound.execution_estimate.observed_at = NOW - 4;
    const evidenceEnvelope = await acceptedEnvelope(evidenceOutbound);
    assertBindingRejected(evidenceEnvelope, evidenceOutbound, NOW + 116);
  });

  await t.test("estimate is fresh when signed but stale when verified", () => {
    const estimateEnvelope = mutateSignedTaskEnvelope(envelope, (task) => {
      task.evidence.observed_at = NOW - 4;
    });
    assertBindingRejected(estimateEnvelope, outbound, NOW + 116);
  });
});

test("signed task binding enforces deterministic ranges and mandate limits", async (t) => {
  const outbound = rawMandate();
  const envelope = await acceptedEnvelope(outbound);
  const mutations: ReadonlyArray<
    readonly [
      string,
      (task: QuoteMandatexSignedRebalanceTask) => void,
      QuoteProtocolErrorCode?,
    ]
  > = [
    [
      "ordered range",
      (task) => void (task.proposal.proposed_lower_tick = 300),
      "SIGNED_TASK_INVALID",
    ],
    [
      "approved bounds",
      (task) => void (task.proposal.proposed_lower_tick = -660),
      "SIGNED_TASK_INVALID",
    ],
    [
      "current tick inclusion",
      (task) => void (task.proposal.proposed_upper_tick = 60),
      "SIGNED_TASK_INVALID",
    ],
    [
      "deterministic construction",
      (task) => void (task.proposal.proposed_upper_tick = 300),
      "SIGNED_TASK_INVALID",
    ],
    [
      "trigger distance",
      (task) => void (task.proposal.trigger.distance_to_boundary_ticks = 2),
    ],
    [
      "trigger reason",
      (task) => void (task.proposal.trigger.reason = "outside_current_range"),
    ],
    [
      "gas estimate binding",
      (task) => void (task.proposal.estimated_gas_usd = 1.5),
    ],
    [
      "slippage estimate binding",
      (task) => void (task.proposal.estimated_slippage_bps = 31),
    ],
    [
      "exposure estimate binding",
      (task) => void (task.proposal.estimated_exposure_usd = 501),
    ],
    [
      "estimate source binding",
      (task) =>
        void (task.proposal.estimate_source_url =
          "https://example.com/estimates/other"),
    ],
  ];

  for (const [name, mutate, expectedCode] of mutations) {
    await t.test(name, () => {
      assertBindingRejected(
        mutateSignedTaskEnvelope(envelope, mutate),
        outbound,
        NOW + 1,
        expectedCode,
      );
    });
  }

  const unsafeMandates: ReadonlyArray<
    readonly [
      string,
      (mandate: ReturnType<typeof normalizedMandate>) => void,
    ]
  > = [
    ["gas cap", (mandate) => void (mandate.limits.max_gas_usd = 1)],
    [
      "slippage cap",
      (mandate) => void (mandate.limits.max_slippage_bps = 20),
    ],
    [
      "exposure cap",
      (mandate) => void (mandate.limits.max_exposure_usd = 400),
    ],
    [
      "permission spend cap",
      (mandate) => void (mandate.permissions.spend_cap_usd = 400),
    ],
    [
      "rebalance trigger",
      (mandate) => void (mandate.range_policy.trigger_mode = "out_of_range"),
    ],
  ];
  for (const [name, mutate] of unsafeMandates) {
    await t.test(name, async () => {
      const mandate = normalizedMandate();
      mutate(mandate);
      assertBindingRejected(await acceptedEnvelope(mandate), mandate, NOW + 1);
    });
  }
});

test("rebalance ranges reject inexact execution, preserve policy envelopes, and resolve negative half-ties", async () => {
  const validEnvelope = await acceptedEnvelope();
  const validTask = decodeQuoteSignedTask(
    validEnvelope.request.task_description,
    "mandatex-rebalance:v1",
  );

  const invalidTasks: ReadonlyArray<
    readonly [string, (task: QuoteMandatexSignedRebalanceTask) => void]
  > = [
    [
      "nondivisible target width",
      (task) => void (task.mandate.range_policy.target_width_ticks = 250),
    ],
    [
      "oversized tick spacing",
      (task) => void (task.evidence.tick_spacing = 1_774_545),
    ],
    [
      "unaligned current position endpoint",
      (task) => void (task.evidence.position_tick_lower = -119),
    ],
    [
      "unaligned proposed endpoint",
      (task) => {
        task.proposal.proposed_lower_tick = 1;
        task.proposal.proposed_upper_tick = 241;
      },
    ],
    [
      "legacy outward-rounded width",
      (task) => {
        task.proposal.proposed_lower_tick = -60;
        task.proposal.proposed_upper_tick = 240;
      },
    ],
    [
      "upper-exclusive current tick",
      (task) =>
        void (task.evidence.current_tick = task.proposal.proposed_upper_tick),
    ],
  ];

  for (const [name, mutate] of invalidTasks) {
    const task = structuredClone(validTask);
    mutate(task);
    assert.equal(
      quoteMandatexSignedRebalanceTaskSchema.safeParse(task).success,
      false,
      name,
    );
  }

  const tooNarrow = normalizedMandate();
  tooNarrow.range_policy.target_width_ticks = 1_201;
  assert.equal(
    quoteMandatexRebalanceMandateSchema.safeParse(tooNarrow).success,
    false,
    "target width must fit inside the approved envelope",
  );

  const unalignedPolicyEnvelope = normalizedMandate();
  unalignedPolicyEnvelope.range_policy.approved_lower_tick = -1;
  unalignedPolicyEnvelope.range_policy.approved_upper_tick = 241;
  const policyEnvelope = await acceptedEnvelope(unalignedPolicyEnvelope);
  const policyBinding = verifyQuoteMandateBinding({
    envelope: policyEnvelope,
    mandate: unalignedPolicyEnvelope,
    codec: "mandatex-rebalance:v1",
    now: NOW + 1,
  });
  assert.deepEqual(
    {
      lower: policyBinding.signedTask.proposal.proposed_lower_tick,
      upper: policyBinding.signedTask.proposal.proposed_upper_tick,
    },
    { lower: 0, upper: 240 },
  );

  const negativeHalfTie = await acceptedEnvelope(rawMandate(), {
    currentTick: -90,
    positionLowerTick: -120,
    positionUpperTick: 0,
  });
  const negativeBinding = verifyQuoteMandateBinding({
    envelope: negativeHalfTie,
    mandate: rawMandate(),
    codec: "mandatex-rebalance:v1",
    now: NOW + 1,
  });
  assert.deepEqual(
    {
      lower: negativeBinding.signedTask.proposal.proposed_lower_tick,
      upper: negativeBinding.signedTask.proposal.proposed_upper_tick,
    },
    { lower: -180, upper: 60 },
  );
  assert.equal(
    negativeBinding.signedTask.proposal.proposed_upper_tick -
      negativeBinding.signedTask.proposal.proposed_lower_tick,
    negativeBinding.signedTask.mandate.range_policy.target_width_ticks,
  );
});

test("signed task binding restricts proposal permissions to the mandate", async (t) => {
  const outbound = rawMandate();
  const envelope = await acceptedEnvelope(outbound);
  const mutations: ReadonlyArray<
    readonly [string, (task: QuoteMandatexSignedRebalanceTask) => void]
  > = [
    [
      "contract subset",
      (task) => void task.proposal.permissions.contracts.push(POOL),
    ],
    [
      "position manager required",
      (task) => void (task.proposal.permissions.contracts = [POOL]),
    ],
    [
      "call subset",
      (task) => void task.proposal.permissions.calls.push("burn(uint256)"),
    ],
    [
      "required rebalance calls",
      (task) => void (task.proposal.permissions.calls = [
        REQUIRED_REBALANCE_CALLS[0],
        REQUIRED_REBALANCE_CALLS[1],
      ]),
    ],
    [
      "mandate spend cap",
      (task) => void (task.proposal.permissions.spend_cap_usd = 751),
    ],
    [
      "proposal exposure cap",
      (task) => void (task.proposal.permissions.spend_cap_usd = 499),
    ],
    [
      "permission expiry ceiling",
      (task) => void (task.proposal.permissions.expires_at = NOW + 1_801),
    ],
    [
      "quote lifetime coverage",
      (task) => void (task.proposal.permissions.expires_at = NOW + 300),
    ],
  ];

  for (const [name, mutate] of mutations) {
    await t.test(name, () => {
      assertBindingRejected(
        mutateSignedTaskEnvelope(envelope, mutate),
        outbound,
        NOW + 1,
      );
    });
  }
});

test("EOA verification is offline and rejects hash, domain, expiry, and signer tampering", async () => {
  const envelope = await acceptedEnvelope();
  const verified = await verifyQuoteEnvelope({
    envelope,
    expectedProvider: ACCOUNT.address,
    expectedProviderKind: "eoa",
    expectedChainId: 56,
    expectedVerifyingContract: COMMERCE,
    now: NOW + 1,
    erc1271Call: async () => {
      throw new Error("EOA verification must not call ERC-1271");
    },
  });
  assert.equal(verified.signatureMethod, "eip191");
  assert.equal(verified.signer, ACCOUNT.address.toLowerCase());
  assert.equal(verified.price, "123");
  assert.equal(verified.currency, CURRENCY);

  const requestTamper = structuredClone(envelope);
  requestTamper.request.request_id = "changed";
  await assertProtocolRejection(
    verifyQuote(requestTamper),
    "REQUEST_HASH_MISMATCH",
  );

  const responseTamper = structuredClone(envelope);
  responseTamper.response.terms.price = "124";
  await assertProtocolRejection(
    verifyQuote(responseTamper),
    "RESPONSE_HASH_MISMATCH",
  );

  const negotiationTamper = structuredClone(envelope);
  negotiationTamper.negotiation_hash = `0x${"ff".repeat(32)}`;
  await assertProtocolRejection(
    verifyQuote(negotiationTamper),
    "NEGOTIATION_HASH_MISMATCH",
  );

  await assertProtocolRejection(
    verifyQuote(envelope, { expectedChainId: 97 }),
    "CHAIN_ID_MISMATCH",
  );
  await assertProtocolRejection(
    verifyQuote(envelope, {
      expectedVerifyingContract: `0x${"6".repeat(40)}`,
    }),
    "VERIFYING_CONTRACT_MISMATCH",
  );
  await assertProtocolRejection(
    verifyQuote(envelope, { now: envelope.response.quote_expires_at }),
    "QUOTE_EXPIRED",
  );

  const signerTamper = structuredClone(envelope);
  signerTamper.provider_sig = await OTHER_ACCOUNT.signMessage({
    message: signerTamper.negotiation_hash,
  });
  await assertProtocolRejection(
    verifyQuote(signerTamper),
    "PROVIDER_SIGNATURE_INVALID",
  );
});

test("ERC-1271 verification receives the EIP-191 digest and treats RPC failure as inconclusive", async () => {
  const envelope = await acceptedEnvelope();
  let calls = 0;
  const verified = await verifyQuoteEnvelope({
    envelope,
    expectedProvider: CONTRACT_PROVIDER,
    expectedProviderKind: "erc1271",
    expectedChainId: 56,
    expectedVerifyingContract: COMMERCE,
    now: NOW + 1,
    erc1271Call: async (call) => {
      calls += 1;
      assert.equal(call.provider, CONTRACT_PROVIDER);
      assert.equal(call.hash, hashMessage(envelope.negotiation_hash));
      assert.equal(call.signature, envelope.provider_sig);
      assert.equal(call.checker, COMMERCE);
      return true;
    },
  });
  assert.equal(calls, 1);
  assert.equal(verified.signatureMethod, "erc1271");
  assert.equal(verified.signer, CONTRACT_PROVIDER);

  await assertProtocolRejection(
    verifyQuoteEnvelope({
      envelope,
      expectedProvider: CONTRACT_PROVIDER,
      expectedProviderKind: "erc1271",
      expectedChainId: 56,
      expectedVerifyingContract: COMMERCE,
      now: NOW + 1,
      erc1271Call: async () => false,
    }),
    "PROVIDER_SIGNATURE_INVALID",
  );
  await assertProtocolRejection(
    verifyQuoteEnvelope({
      envelope,
      expectedProvider: CONTRACT_PROVIDER,
      expectedProviderKind: "erc1271",
      expectedChainId: 56,
      expectedVerifyingContract: COMMERCE,
      now: NOW + 1,
      erc1271Call: async () => {
        throw new Error("RPC unavailable");
      },
    }),
    "ERC1271_UNAVAILABLE",
  );
});

test("replay keys are deterministic and domain-separated", async () => {
  const envelope = await acceptedEnvelope();
  const base = {
    chainId: 56,
    tokenId: "265375",
    endpointHash: "ab".repeat(32),
    provider: ACCOUNT.address,
    commerceContract: COMMERCE,
    negotiationHash: envelope.negotiation_hash,
  };
  const key = computeQuoteReplayKey(base);
  assert.match(key, /^[a-f0-9]{64}$/);
  assert.equal(computeQuoteReplayKey(base), key);
  assert.notEqual(
    computeQuoteReplayKey({ ...base, tokenId: "265376" }),
    key,
  );
  assert.notEqual(
    computeQuoteReplayKey({
      ...base,
      commerceContract: `0x${"7".repeat(40)}`,
    }),
    key,
  );
});

function a2aResponse(envelope: QuoteEnvelope, id: string) {
  return {
    jsonrpc: "2.0",
    id,
    result: {
      kind: "message",
      role: "agent",
      messageId: "agent-message-1",
      parts: [{ kind: "data", data: envelope }],
    },
  };
}

type SignedRangeFixture = Readonly<{
  currentTick?: number;
  tickSpacing?: number;
  positionLowerTick?: number;
  positionUpperTick?: number;
  proposedLowerTick?: number;
  proposedUpperTick?: number;
}>;

async function acceptedEnvelope(
  outboundMandate: QuoteMandate = rawMandate(),
  range: SignedRangeFixture = {},
): Promise<QuoteAcceptedEnvelope> {
  const mandate = quoteMandatexRebalanceMandateSchema.parse(outboundMandate);
  const tickSpacing = range.tickSpacing ?? 60;
  const currentTick = range.currentTick ?? 119;
  const positionLowerTick = range.positionLowerTick ?? -120;
  const positionUpperTick = range.positionUpperTick ?? 120;
  const boundaryDistance =
    currentTick < positionLowerTick || currentTick >= positionUpperTick
      ? 0
      : Math.min(
          currentTick - positionLowerTick,
          positionUpperTick - currentTick,
        );
  const expectedRange = deriveNearestCenteredExactRange(
    currentTick,
    mandate.range_policy.target_width_ticks,
    tickSpacing,
  );
  const signedTask = quoteMandatexSignedRebalanceTaskSchema.parse({
    schema: "mandatex.rebalance.quote.v1",
    mandate,
    evidence: {
      network: "bsc-mainnet",
      chain_id: 56,
      snapshot_head_block: 1_002,
      confirmation_depth_blocks: 2,
      observed_block: 1_000,
      observed_block_hash: BLOCK_HASH,
      observed_at: NOW - 5,
      pool_address: mandate.position.pool_address,
      position_manager_address: mandate.position.position_manager_address,
      position_token_id: mandate.position.token_id,
      position_owner: OWNER,
      token0: TOKEN0,
      token1: TOKEN1,
      token0_decimals: 18,
      token1_decimals: 18,
      fee: 2_500,
      tick_spacing: tickSpacing,
      current_tick: currentTick,
      sqrt_price_x96: "79704936542881920863903188246",
      approximate_token1_per_token0: "1.01197061622",
      position_tick_lower: positionLowerTick,
      position_tick_upper: positionUpperTick,
      pool_liquidity: "1000000000",
      position_liquidity: "1000000",
      sources: [
        {
          type: "onchain",
          url: "https://bscscan.com/block/1000",
          observed_block: 1_000,
        },
      ],
    },
    proposal: {
      execution_mode: "simulation",
      proposed_lower_tick: range.proposedLowerTick ?? expectedRange.lower,
      proposed_upper_tick: range.proposedUpperTick ?? expectedRange.upper,
      trigger: {
        fired: true,
        reason: "near_range_boundary",
        distance_to_boundary_ticks: boundaryDistance,
      },
      estimated_gas_usd: mandate.execution_estimate.gas_usd,
      estimated_slippage_bps: mandate.execution_estimate.slippage_bps,
      estimated_exposure_usd: mandate.execution_estimate.exposure_usd,
      estimate_source_url: mandate.execution_estimate.source_url,
      permissions: {
        contracts: [mandate.position.position_manager_address],
        calls: [...REQUIRED_REBALANCE_CALLS],
        spend_cap_usd: mandate.permissions.spend_cap_usd,
        expires_at: mandate.permissions.expires_at,
      },
      break_even: {
        status: "not_calculated",
        reason: "not required for the simulation quote",
      },
    },
    eligibility: {
      eligible: true,
      checked_at: NOW,
      checks: ["mandate and evidence passed deterministic policy"],
    },
  });
  const encodedTask = `mandatex-rebalance:v1:${deflateRawSync(
    Buffer.from(canonicalQuoteJson(signedTask), "utf8"),
    { level: 9 },
  ).toString("base64url")}`;
  const request = {
    task_description: encodedTask,
    terms: {
      deliverables: "A deterministic MandateX simulation receipt.",
      quality_standards: "Refuse on stale state or mandate drift.",
      evaluation_required: true,
      evaluator_type: "uma_oov3",
      success_criteria: ["The receipt preserves the approved limits."],
    },
  };
  const response = {
    accepted: true as const,
    terms: {
      ...request.terms,
      price: "123",
      currency: CURRENCY,
    },
    estimated_completion_seconds: 120,
    quote_expires_at: NOW + 600,
    negotiated_at: NOW,
  };
  const draft = quoteAcceptedEnvelopeSchema.parse({
    request,
    request_hash: computeQuoteRequestHash(request),
    response,
    response_hash: computeQuoteResponseHash(response),
    negotiation_hash: `0x${"00".repeat(32)}`,
    provider_sig: "0x00",
    chain_id: 56,
    verifying_contract: COMMERCE,
    mandatex: {
      schema: "mandatex.rebalance.quote.v1",
      mandate_id: mandate.mandate_id,
      observed_block: signedTask.evidence.observed_block,
      proposed_lower_tick: signedTask.proposal.proposed_lower_tick,
      proposed_upper_tick: signedTask.proposal.proposed_upper_tick,
      display_only: true,
    },
  });
  const negotiationHash = computeQuoteNegotiationHash(draft);
  return quoteAcceptedEnvelopeSchema.parse({
    ...draft,
    negotiation_hash: negotiationHash,
    provider_sig: await ACCOUNT.signMessage({ message: negotiationHash }),
  });
}

function rawMandate(): QuoteMandate {
  return {
    version: "1",
    mandate_id: "rebalance-demo-1",
    category: "rebalancing",
    chain_id: 56,
    protocol: "pancakeswap-v3",
    expires_at: NOW + 3_600,
    position: {
      pool_address: POOL.toUpperCase().replace("0X", "0x"),
      position_manager_address: MANAGER,
      token_id: "0042",
    },
    range_policy: {
      approved_lower_tick: -600,
      approved_upper_tick: 600,
      target_width_ticks: 240,
      trigger_distance_ticks: 30,
      max_delivery_tick_drift: 30,
    },
    limits: {
      max_gas_usd: 3,
      max_slippage_bps: 50,
      max_exposure_usd: 1_000,
    },
    execution_estimate: {
      gas_usd: 1.25,
      slippage_bps: 30,
      exposure_usd: 500,
      observed_at: NOW - 5,
      source_url: "https://example.com/estimates/rebalance-demo-1",
    },
    permissions: {
      allowed_contracts: [MANAGER, MANAGER],
      allowed_calls: [
        "decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))",
        "collect((uint256,address,uint128,uint128))",
        "collect((uint256,address,uint128,uint128))",
        "mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))",
      ],
      spend_cap_usd: 750,
      expires_at: NOW + 1_800,
    },
  };
}

function normalizedMandate() {
  return quoteMandatexRebalanceMandateSchema.parse(rawMandate());
}

function encodeSignedTask(task: QuoteMandatexSignedRebalanceTask): string {
  return `mandatex-rebalance:v1:${deflateRawSync(
    Buffer.from(canonicalQuoteJson(task), "utf8"),
    { level: 9 },
  ).toString("base64url")}`;
}

function mutateSignedTaskEnvelope(
  envelope: QuoteAcceptedEnvelope,
  mutate: (task: QuoteMandatexSignedRebalanceTask) => void,
): QuoteAcceptedEnvelope {
  const changed = structuredClone(envelope);
  const task = structuredClone(
    decodeQuoteSignedTask(
      changed.request.task_description,
      "mandatex-rebalance:v1",
    ),
  );
  mutate(task);
  changed.request.task_description = encodeSignedTask(task);
  if (changed.mandatex !== undefined) {
    changed.mandatex.mandate_id = task.mandate.mandate_id;
    changed.mandatex.observed_block = task.evidence.observed_block;
    changed.mandatex.proposed_lower_tick = task.proposal.proposed_lower_tick;
    changed.mandatex.proposed_upper_tick = task.proposal.proposed_upper_tick;
  }
  return quoteAcceptedEnvelopeSchema.parse(changed);
}

function assertBindingRejected(
  envelope: QuoteAcceptedEnvelope,
  mandate: QuoteMandate,
  now: number,
  expectedCode: QuoteProtocolErrorCode = "MANDATE_BINDING_MISMATCH",
): void {
  assertProtocolError(
    () =>
      verifyQuoteMandateBinding({
        envelope,
        mandate,
        codec: "mandatex-rebalance:v1",
        now,
      }),
    expectedCode,
  );
}

function verifyQuote(
  envelope: QuoteAcceptedEnvelope,
  overrides: Partial<{
    expectedChainId: number;
    expectedVerifyingContract: string;
    now: number;
  }> = {},
) {
  return verifyQuoteEnvelope({
    envelope,
    expectedProvider: ACCOUNT.address,
    expectedProviderKind: "eoa",
    expectedChainId: overrides.expectedChainId ?? 56,
    expectedVerifyingContract:
      overrides.expectedVerifyingContract ?? COMMERCE,
    now: overrides.now ?? NOW + 1,
  });
}

function assertProtocolError(
  operation: () => unknown,
  code: QuoteProtocolErrorCode,
): void {
  assert.throws(
    operation,
    (error: unknown) =>
      error instanceof QuoteProtocolError && error.code === code,
  );
}

async function assertProtocolRejection(
  operation: Promise<unknown>,
  code: QuoteProtocolErrorCode,
): Promise<void> {
  await assert.rejects(
    operation,
    (error: unknown) =>
      error instanceof QuoteProtocolError && error.code === code,
  );
}
