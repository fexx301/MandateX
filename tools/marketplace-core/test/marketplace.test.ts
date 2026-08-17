import assert from "node:assert/strict";
import test from "node:test";

import * as publicApi from "../src/index.js";
import { createProjectionCapability } from "../src/capture.js";
import { CATEGORY_POLICIES } from "../src/category-policy.js";
import { normalizeCapturedQuote } from "../src/normalize.js";
import {
  CandidateSetError,
  MarketplaceCoreError,
  STRATEGY_WEIGHTS,
  marketplaceEligibilityDecisionSchema,
  marketplaceQuoteSchema,
  marketplaceReceiptSchema,
  verifyMarketplaceEvaluationConsistency,
  type CapturedDisplaySafeQuoteProjection,
  type DisplaySafeQuoteProjectionPayload,
  type EvaluateMarketplaceInput,
  type MarketplaceCoreOptions,
  type MarketplaceErrorCode,
  type TrustedProjectionIngress,
} from "../src/index.js";
import {
  capturedQuote,
  createTestMarketplaceCore,
  rawMandate,
  rawProjection,
  testMarketplace,
} from "./fixtures.js";

type TimedEvaluationInput = EvaluateMarketplaceInput & {
  readonly evaluatedAt: number;
};

function evaluateMarketplace(input: TimedEvaluationInput) {
  const { evaluatedAt, ...evaluationInput } = input;
  testMarketplace.setClock(evaluatedAt);
  return testMarketplace.core.evaluateMarketplace(evaluationInput);
}

function hasErrorCode(code: MarketplaceErrorCode) {
  return (error: unknown): boolean =>
    error instanceof MarketplaceCoreError && error.code === code;
}

test("happy path produces four validated artifacts and a deterministic ranking", () => {
  const result = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [
      capturedQuote({ quoteId: "quote-b", tokenId: "9", gasUsdMicros: "20" }),
      capturedQuote({ quoteId: "quote-a", tokenId: "7", gasUsdMicros: "10" }),
    ],
    evaluatedAt: 1_100,
  });
  assert.equal(result.quotes.length, 2);
  assert.equal(result.decisions.length, 2);
  assert.equal(result.decisions[0]?.outcome, "eligible");
  assert.equal(result.decisions[1]?.outcome, "eligible");
  assert.equal(result.receipt.effect, "evaluation_only");
  assert.deepEqual(result.receipt.adapter, {
    status: "supported",
    name: "pancakeswap-v3-rebalancing-v1",
  });
  assert.deepEqual(result.quotes[0]?.normalization, {
    status: "normalized",
    adapter: "pancakeswap-v3-rebalancing-v1",
  });
  assert.equal(result.receipt.summary.eligible, 2);
  assert.equal(result.receipt.ranking[0]?.candidate.tokenId, "7");
  assert.equal(result.receipt.ranking[0]?.rank, 1);
  assert.deepEqual(STRATEGY_WEIGHTS, {
    mandateFit: 30,
    executionReadiness: 20,
    evidenceFreshness: 20,
    riskCompatibility: 15,
    totalCost: 10,
    reputationConfidence: 5,
  });
  const score = result.receipt.ranking[0]?.score;
  assert.ok(score);
  assert.equal(
    score.weightedTotal,
    Object.values(score.factors).reduce(
      (sum, factor) => sum + factor.weight * factor.scoreBps,
      0,
    ),
  );
  assert.equal(score.scoreBps, Math.floor(score.weightedTotal / 100));
  assert.doesNotThrow(() => marketplaceQuoteSchema.parse(result.quotes[0]));
  assert.doesNotThrow(() =>
    marketplaceEligibilityDecisionSchema.parse(result.decisions[0]),
  );
  assert.doesNotThrow(() => marketplaceReceiptSchema.parse(result.receipt));
  const consistency = verifyMarketplaceEvaluationConsistency(result);
  assert.equal(consistency.scope, "integrity_only");
  assert.deepEqual(consistency.result, result);
});

test("candidate and quote ordering do not affect receipt hashes", () => {
  const first = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [
      capturedQuote({ quoteId: "quote-b", tokenId: "9" }),
      capturedQuote({ quoteId: "quote-a", tokenId: "7" }),
    ],
    evaluatedAt: 1_100,
  });
  const second = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [
      capturedQuote({ quoteId: "quote-a", tokenId: "7" }),
      capturedQuote({ quoteId: "quote-b", tokenId: "9" }),
    ],
    evaluatedAt: 1_100,
  });
  assert.equal(first.receipt.receiptId, second.receipt.receiptId);
  assert.deepEqual(first.quotes, second.quotes);
  assert.deepEqual(first.decisions, second.decisions);
});

test("the supported category preserves its pre-refactor receipt identity", () => {
  const result = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [capturedQuote()],
    evaluatedAt: 1_100,
  });
  assert.equal(
    result.receipt.receiptId,
    "2434e36b122a8bdbc7e88466fba2c0f4cd60354bed4e33b4ecadc255683a4471",
  );
});

test("nonzero token atomic prices are explicit inconclusive and never ranked", () => {
  const result = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [capturedQuote({ amountAtomic: "1" })],
    evaluatedAt: 1_100,
  });
  assert.equal(result.quotes[0]?.pricing.status, "usd_unavailable");
  assert.equal(result.quotes[0]?.normalization.status, "inconclusive");
  assert.equal(result.decisions[0]?.outcome, "inconclusive");
  assert.equal(result.decisions[0]?.findings[0]?.code, "PRICING_USD_UNAVAILABLE");
  assert.equal(result.receipt.ranking.length, 0);
});

test("grid, yield, and health are explicit unsupported results", () => {
  const cases = [
    [
      "grid",
      "CATEGORY_GRID_UNSUPPORTED",
      "eed503ec0b13220b0815003d6065a9a625b7927a66b69dbce48d13b86357bd69",
    ],
    [
      "yield",
      "CATEGORY_YIELD_UNSUPPORTED",
      "1a583e53d6bcd1e9aa989a538bf2f6b38b4100b58012ca667646072fcd8caa03",
    ],
    [
      "health",
      "CATEGORY_HEALTH_UNSUPPORTED",
      "ca2e3eb421a0c69f6fa2fde282fb1da84209acc32a3ff09664baba41178a2883",
    ],
  ] as const;
  for (const [category, expectedCode, expectedReceiptId] of cases) {
    const { rebalancing: _rebalancing, ...commonMandate } = rawMandate();
    const result = evaluateMarketplace({
      mandate: { ...commonMandate, category },
      candidates: [capturedQuote({ category })],
      evaluatedAt: 1_100,
    });
    assert.deepEqual(result.receipt.adapter, {
      status: "unsupported",
      code: expectedCode,
    });
    assert.equal(result.decisions[0]?.outcome, "unsupported");
    assert.equal(result.decisions[0]?.findings[0]?.code, expectedCode);
    assert.deepEqual(result.quotes[0]?.normalization, {
      status: "unsupported",
      code: expectedCode,
    });
    assert.equal(result.receipt.receiptId, expectedReceiptId);
    assert.equal(result.receipt.ranking.length, 0);
  }
});

test("unsupported category policy takes precedence over nonzero pricing", () => {
  const { rebalancing: _rebalancing, ...commonMandate } = rawMandate();
  const result = evaluateMarketplace({
    mandate: { ...commonMandate, category: "grid" },
    candidates: [capturedQuote({ category: "grid", amountAtomic: "1" })],
    evaluatedAt: 1_100,
  });
  assert.equal(result.quotes[0]?.pricing.status, "usd_unavailable");
  assert.deepEqual(result.quotes[0]?.normalization, {
    status: "unsupported",
    code: "CATEGORY_GRID_UNSUPPORTED",
  });
  assert.equal(result.decisions[0]?.outcome, "unsupported");
});

test("the closed category policy table is exhaustive and recursively frozen", () => {
  assert.deepEqual(Object.keys(CATEGORY_POLICIES).sort(), [
    "grid",
    "health",
    "rebalancing",
    "yield",
  ]);
  assert.equal(Object.isFrozen(CATEGORY_POLICIES), true);
  for (const policy of Object.values(CATEGORY_POLICIES)) {
    assert.equal(Object.isFrozen(policy), true);
    assert.equal(Object.isFrozen(policy.receiptAdapter), true);
  }
  const mutable = CATEGORY_POLICIES as unknown as {
    grid: { receiptAdapter: { code: string } };
  };
  assert.throws(() => {
    mutable.grid.receiptAdapter.code = "CATEGORY_YIELD_UNSUPPORTED";
  }, TypeError);
});

test("hard eligibility gates fail closed with stable exclusion codes", () => {
  const cases = [
    [{ endpoint: "fail" as const }, "AGENT_UNREACHABLE"],
    [{ preview: "failed" as const }, "EXECUTION_PREVIEW_FAILED"],
    [{ triggerFired: false }, "REBALANCE_TRIGGER_NOT_FIRED"],
    [{ proposedLowerTick: -110 }, "RANGE_OUTSIDE_POLICY"],
    [{ gasUsdMicros: "51" }, "GAS_BUDGET_EXCEEDED"],
    [
      { permissionsContracts: ["0x6666666666666666666666666666666666666666"] },
      "PERMISSION_CONTRACT_NOT_ALLOWED",
    ],
  ] as const;
  for (const [options, expectedCode] of cases) {
    const result = evaluateMarketplace({
      mandate: rawMandate(),
      candidates: [capturedQuote(options)],
      evaluatedAt: 1_100,
    });
    assert.equal(result.decisions[0]?.outcome, "excluded");
    assert.ok(
      result.decisions[0]?.findings.some(
        (finding) => finding.code === expectedCode,
      ),
    );
  }
});

test("unknown upstream gates and unavailable preview remain inconclusive", () => {
  const unknown = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [capturedQuote({ endpoint: "unknown" })],
    evaluatedAt: 1_100,
  });
  assert.equal(unknown.decisions[0]?.outcome, "inconclusive");
  assert.ok(
    unknown.decisions[0]?.findings.some(
      (finding) => finding.code === "ENDPOINT_CHECK_INCONCLUSIVE",
    ),
  );
  const unavailablePreview = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [capturedQuote({ preview: "unavailable" })],
    evaluatedAt: 1_100,
  });
  assert.equal(unavailablePreview.decisions[0]?.outcome, "inconclusive");
  assert.ok(
    unavailablePreview.decisions[0]?.findings.some(
      (finding) => finding.code === "EXECUTION_PREVIEW_INCONCLUSIVE",
    ),
  );
});

test("definitive exclusion dominates an additional inconclusive finding", () => {
  const result = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [capturedQuote({ amountAtomic: "1", endpoint: "fail" })],
    evaluatedAt: 1_100,
  });
  assert.equal(result.decisions[0]?.outcome, "excluded");
  assert.deepEqual(
    result.decisions[0]?.findings.map((finding) => finding.kind),
    ["exclusion", "inconclusive"],
  );
  const contradictory = structuredClone(result.decisions[0]) as unknown as {
    outcome: string;
  };
  contradictory.outcome = "inconclusive";
  assert.throws(() => marketplaceEligibilityDecisionSchema.parse(contradictory));
});

test("only eligible candidates receive scores and ranking entries", () => {
  const result = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [
      capturedQuote({ quoteId: "excluded", tokenId: "8", triggerFired: false }),
      capturedQuote({ quoteId: "eligible", tokenId: "9" }),
    ],
    evaluatedAt: 1_100,
  });
  assert.equal(
    result.decisions.find((decision) => decision.quoteId === "excluded")?.score,
    null,
  );
  assert.notEqual(
    result.decisions.find((decision) => decision.quoteId === "eligible")?.score,
    null,
  );
  assert.deepEqual(
    result.receipt.ranking.map((entry) => entry.quoteId),
    ["eligible"],
  );
});

test("the candidate set has a strict eight-item and uniqueness boundary", () => {
  const eight = Array.from({ length: 8 }, (_, index) =>
    capturedQuote({ quoteId: `quote-${index}`, tokenId: String(index + 1) }),
  );
  assert.doesNotThrow(() =>
    evaluateMarketplace({ mandate: rawMandate(), candidates: eight, evaluatedAt: 1_100 }),
  );
  assert.throws(
    () =>
      evaluateMarketplace({
        mandate: rawMandate(),
        candidates: [
          ...eight,
          capturedQuote({ quoteId: "quote-8", tokenId: "9" }),
        ],
        evaluatedAt: 1_100,
      }),
    (error: unknown) =>
      error instanceof CandidateSetError &&
      error.code === "CANDIDATE_LIMIT_EXCEEDED",
  );
  assert.throws(
    () =>
      evaluateMarketplace({
        mandate: rawMandate(),
        candidates: [
          capturedQuote({ quoteId: "quote-a", tokenId: "7" }),
          capturedQuote({ quoteId: "quote-b", tokenId: "7" }),
        ],
        evaluatedAt: 1_100,
      }),
    hasErrorCode("DUPLICATE_CANDIDATE"),
  );
  assert.throws(
    () =>
      evaluateMarketplace({
        mandate: rawMandate(),
        candidates: [
          capturedQuote({ quoteId: "same", tokenId: "7" }),
          capturedQuote({ quoteId: "same", tokenId: "8" }),
        ],
        evaluatedAt: 1_100,
      }),
    hasErrorCode("DUPLICATE_QUOTE_ID"),
  );
});

test("capture authority is per core and cannot be reconstructed or recaptured", () => {
  const captured = capturedQuote();
  const other = createTestMarketplaceCore();
  assert.throws(
    () =>
      other.core.evaluateMarketplace({
        mandate: rawMandate(),
        candidates: [captured],
      }),
    hasErrorCode("DISPLAY_SAFE_PROJECTION_NOT_CAPTURED_BY_CORE"),
  );
  const roundTripped = JSON.parse(JSON.stringify(captured)) as unknown;
  assert.throws(
    () =>
      evaluateMarketplace({
        mandate: rawMandate(),
        candidates: [roundTripped as CapturedDisplaySafeQuoteProjection],
        evaluatedAt: 1_100,
      }),
    hasErrorCode("DISPLAY_SAFE_PROJECTION_NOT_CAPTURED_BY_CORE"),
  );
  assert.throws(
    () =>
      testMarketplace.ingress.capture(
        captured as unknown as DisplaySafeQuoteProjectionPayload,
      ),
    hasErrorCode("TRUSTED_PROJECTION_INVALID"),
  );
});

test("normalization runtime-checks the private brand and raw helpers are not public", () => {
  let ingress: TrustedProjectionIngress | undefined;
  const capability = createProjectionCapability(
    (installed) => {
      ingress = installed;
    },
    () => 1_120,
  );
  assert.ok(ingress);
  const captured = ingress.capture(
    rawProjection() as unknown as DisplaySafeQuoteProjectionPayload,
  );
  const unbranded = structuredClone(captured);
  assert.throws(
    () => normalizeCapturedQuote(unbranded, capability),
    hasErrorCode("DISPLAY_SAFE_PROJECTION_NOT_CAPTURED_BY_CORE"),
  );
  assert.equal("normalizeCapturedQuote" in publicApi, false);
  assert.equal("scoreEligibleQuote" in publicApi, false);
  assert.equal("captureValidatedDisplaySafeQuoteProjection" in publicApi, false);
});

test("core clocks and ingress installers fail with stable errors", async () => {
  assert.throws(
    () =>
      publicApi.createMarketplaceCore({
        installTrustedProjectionIngress() {
          throw new Error("installer failed");
        },
        clock: () => 1_120,
      }),
    hasErrorCode("TRUSTED_INGRESS_INSTALLER_INVALID"),
  );
  assert.throws(
    () =>
      publicApi.createMarketplaceCore({
        installTrustedProjectionIngress: (() =>
          Promise.resolve()) as unknown as MarketplaceCoreOptions["installTrustedProjectionIngress"],
        clock: () => 1_120,
      }),
    hasErrorCode("TRUSTED_INGRESS_INSTALLER_INVALID"),
  );

  const unhandledRejections: unknown[] = [];
  const captureUnhandledRejection = (reason: unknown) => {
    unhandledRejections.push(reason);
  };
  process.on("unhandledRejection", captureUnhandledRejection);
  try {
    assert.throws(
      () =>
        publicApi.createMarketplaceCore({
          installTrustedProjectionIngress: (async () => {
            throw new Error("late installer failure");
          }) as unknown as MarketplaceCoreOptions["installTrustedProjectionIngress"],
          clock: () => 1_120,
        }),
      hasErrorCode("TRUSTED_INGRESS_INSTALLER_INVALID"),
    );

    const asyncClockCore = publicApi.createMarketplaceCore({
      installTrustedProjectionIngress() {},
      clock: (async () => {
        throw new Error("late clock failure");
      }) as unknown as () => number,
    });
    assert.throws(
      () =>
        asyncClockCore.evaluateMarketplace({
          mandate: rawMandate(),
          candidates: [],
        }),
      hasErrorCode("CORE_CLOCK_INVALID"),
    );
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.deepEqual(unhandledRejections, []);
  } finally {
    process.off("unhandledRejection", captureUnhandledRejection);
  }

  let ingress: TrustedProjectionIngress | undefined;
  const core = publicApi.createMarketplaceCore({
    installTrustedProjectionIngress(installed) {
      ingress = installed;
    },
    clock() {
      throw new Error("clock failed");
    },
  });
  const installedIngress = ingress;
  if (installedIngress === undefined) {
    throw new Error("expected ingress installation");
  }
  assert.throws(
    () =>
      installedIngress.capture(
        rawProjection() as DisplaySafeQuoteProjectionPayload,
      ),
    hasErrorCode("CORE_CLOCK_INVALID"),
  );
  assert.throws(
    () => core.evaluateMarketplace({ mandate: rawMandate(), candidates: [] }),
    hasErrorCode("CORE_CLOCK_INVALID"),
  );
});

test("live evaluation takes time from its core-owned clock", () => {
  const delayed = createTestMarketplaceCore(1_120);
  const captured = delayed.ingress.capture(
    rawProjection() as DisplaySafeQuoteProjectionPayload,
  );
  assert.throws(
    () =>
      delayed.core.evaluateMarketplace({
        mandate: rawMandate(),
        candidates: [captured],
        evaluatedAt: 1_100,
      } as unknown as EvaluateMarketplaceInput),
    hasErrorCode("EVALUATION_INPUT_INVALID"),
  );
  delayed.setClock(1_000_000);
  const result = delayed.core.evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [captured],
  });
  assert.equal(result.receipt.evaluatedAt, 1_000_000);
  assert.equal(result.decisions[0]?.outcome, "excluded");
  assert.ok(
    result.decisions[0]?.findings.some(
      (finding) => finding.code === "MANDATE_EXPIRED",
    ),
  );
});

test("normalized quotes retain no signed task or verifier sidecar fields", () => {
  const projection = rawProjection();
  projection.signedTask = "must-not-be-accepted";
  assert.throws(
    () =>
      testMarketplace.ingress.capture(
        projection as unknown as DisplaySafeQuoteProjectionPayload,
      ),
    hasErrorCode("TRUSTED_PROJECTION_INVALID"),
  );
  const result = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [capturedQuote()],
    evaluatedAt: 1_100,
  });
  const quote = result.quotes[0];
  assert.ok(quote);
  assert.equal("signedTask" in quote, false);
  assert.equal("taskDescription" in quote, false);
  assert.equal("sidecar" in quote, false);
});

test("evaluation and integrity-only results are recursively frozen", () => {
  const result = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [capturedQuote()],
    evaluatedAt: 1_100,
  });
  const consistency = verifyMarketplaceEvaluationConsistency(result);
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.quotes), true);
  assert.equal(Object.isFrozen(result.quotes[0]?.candidate), true);
  assert.equal(Object.isFrozen(result.receipt.commitments), true);
  assert.equal(Object.isFrozen(consistency), true);
  assert.equal(Object.isFrozen(consistency.result.decisions[0]?.findings), true);
  const mutable = result as unknown as {
    quotes: Array<{ candidate: { owner: string } }>;
  };
  assert.throws(() => {
    mutable.quotes[0]!.candidate.owner =
      "0x9999999999999999999999999999999999999999";
  }, TypeError);
});

test("receipt and decision schemas reject tampered arithmetic or classifications", () => {
  const result = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [capturedQuote()],
    evaluatedAt: 1_100,
  });
  const decision = structuredClone(result.decisions[0]) as any;
  assert.ok(decision.score);
  decision.score.factors.mandateFit.weightedPoints -= 1;
  assert.throws(() => marketplaceEligibilityDecisionSchema.parse(decision));

  const receipt = structuredClone(result.receipt) as any;
  receipt.summary.excluded = 1;
  assert.throws(() => marketplaceReceiptSchema.parse(receipt));

  const wrongSupportedCategory = structuredClone(result.receipt) as any;
  wrongSupportedCategory.category = "grid";
  assert.throws(() => marketplaceReceiptSchema.parse(wrongSupportedCategory));

  const { rebalancing: _rebalancing, ...commonMandate } = rawMandate();
  const unsupported = evaluateMarketplace({
    mandate: { ...commonMandate, category: "grid" },
    candidates: [capturedQuote({ category: "grid" })],
    evaluatedAt: 1_100,
  });
  const wrongUnsupportedCode = structuredClone(unsupported.receipt) as any;
  wrongUnsupportedCode.adapter.code = "CATEGORY_YIELD_UNSUPPORTED";
  assert.throws(() => marketplaceReceiptSchema.parse(wrongUnsupportedCode));
  const wrongQuoteCode = structuredClone(unsupported.quotes[0]) as any;
  wrongQuoteCode.normalization.code = "CATEGORY_HEALTH_UNSUPPORTED";
  assert.throws(() => marketplaceQuoteSchema.parse(wrongQuoteCode));

  const tamperedResult = structuredClone(result) as any;
  tamperedResult.receipt.receiptId = "00".repeat(32);
  assert.throws(
    () => verifyMarketplaceEvaluationConsistency(tamperedResult),
    hasErrorCode("INTEGRITY_RECEIPT_INVALID"),
  );
});

test("integrity verification rejects unknown shape, duplicates, and noncanonical order", () => {
  const result = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [
      capturedQuote({ quoteId: "quote-a", tokenId: "7" }),
      capturedQuote({ quoteId: "quote-b", tokenId: "8" }),
    ],
    evaluatedAt: 1_100,
  });
  assert.throws(
    () => verifyMarketplaceEvaluationConsistency({ ...result, extra: true }),
    hasErrorCode("INTEGRITY_RESULT_SHAPE_INVALID"),
  );

  const duplicated = structuredClone(result) as any;
  duplicated.quotes[1] = structuredClone(duplicated.quotes[0]);
  assert.throws(
    () => verifyMarketplaceEvaluationConsistency(duplicated),
    hasErrorCode("INTEGRITY_UNIQUENESS_INVALID"),
  );

  const unordered = structuredClone(result) as any;
  unordered.quotes.reverse();
  assert.throws(
    () => verifyMarketplaceEvaluationConsistency(unordered),
    hasErrorCode("INTEGRITY_RESULT_UNORDERED"),
  );

  const sparse = structuredClone(result) as any;
  sparse.quotes = new Array(2);
  sparse.decisions = new Array(2);
  assert.throws(
    () => verifyMarketplaceEvaluationConsistency(sparse),
    hasErrorCode("INTEGRITY_QUOTES_INVALID"),
  );

  const sparseDecisions = structuredClone(result) as any;
  sparseDecisions.decisions = new Array(2);
  assert.throws(
    () => verifyMarketplaceEvaluationConsistency(sparseDecisions),
    hasErrorCode("INTEGRITY_DECISIONS_INVALID"),
  );
});

test("integrity verification rejects normalized-only and pre-mandate artifacts", () => {
  const result = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [capturedQuote()],
    evaluatedAt: 1_100,
  });
  const noncanonical = structuredClone(result) as any;
  noncanonical.quotes[0].candidate.owner =
    "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  assert.throws(
    () => verifyMarketplaceEvaluationConsistency(noncanonical),
    hasErrorCode("INTEGRITY_NONCANONICAL_INPUT"),
  );

  const preMandate = structuredClone(result) as any;
  preMandate.receipt.evaluatedAt = 999;
  assert.throws(
    () => verifyMarketplaceEvaluationConsistency(preMandate),
    hasErrorCode("EVALUATED_AT_BEFORE_MANDATE"),
  );
});

test("caller-provided source digests remain integrity-only, not provenance proof", () => {
  const payload = rawProjection();
  payload.sourceCommitments = {
    quoteValidationSha256: "ff".repeat(32),
    previewValidationSha256: "ee".repeat(32),
  };
  const captured = testMarketplace.ingress.capture(
    payload as unknown as DisplaySafeQuoteProjectionPayload,
  );
  const result = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [captured],
    evaluatedAt: 1_100,
  });
  const consistency = verifyMarketplaceEvaluationConsistency(result);
  assert.equal(consistency.scope, "integrity_only");
  assert.equal(
    consistency.result.quotes[0]?.sourceCommitments.quoteValidationSha256,
    "ff".repeat(32),
  );
});

test("capture rejects contradictory evidence chronology", () => {
  const timestampPaths = [
    ["estimates", "observedAt"],
    ["preview", "observedAt"],
    ["reputation", "observedAt"],
    ["categoryEvidence", "observedAt"],
  ] as const;
  for (const [section, field] of timestampPaths) {
    const projection = rawProjection() as any;
    projection[section][field] = 1_121;
    assert.throws(
      () =>
        testMarketplace.ingress.capture(
          projection as DisplaySafeQuoteProjectionPayload,
        ),
      hasErrorCode("TRUSTED_PROJECTION_INVALID"),
    );
  }
});

test("mandate-relative chronology uses stable evidence-specific codes", () => {
  const cases = [
    [{ estimatesObservedAt: 999 }, "ESTIMATE_PRECEDES_MANDATE"],
    [{ previewObservedAt: 999 }, "PREVIEW_PRECEDES_MANDATE"],
    [{ reputationObservedAt: 999 }, "REPUTATION_PRECEDES_MANDATE"],
    [
      { categoryEvidenceObservedAt: 999 },
      "CATEGORY_EVIDENCE_PRECEDES_MANDATE",
    ],
  ] as const;
  for (const [options, code] of cases) {
    const result = evaluateMarketplace({
      mandate: rawMandate(),
      candidates: [capturedQuote(options)],
      evaluatedAt: 1_100,
    });
    assert.equal(result.decisions[0]?.outcome, "excluded");
    assert.ok(
      result.decisions[0]?.findings.some((finding) => finding.code === code),
    );
  }
});

test("every scored evidence timestamp contributes to freshness", () => {
  const fresh = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [capturedQuote()],
    evaluatedAt: 1_100,
  });
  const freshScore = fresh.decisions[0]?.score?.factors.evidenceFreshness.scoreBps;
  assert.equal(freshScore, 10_000);

  const olderTimestampCases = [
    {
      observedAt: 1_001,
      estimatesObservedAt: 1_100,
      previewObservedAt: 1_100,
      reputationObservedAt: 1_100,
      categoryEvidenceObservedAt: 1_100,
    },
    { estimatesObservedAt: 1_001 },
    { previewObservedAt: 1_001 },
    { reputationObservedAt: 1_001 },
    { categoryEvidenceObservedAt: 1_001 },
  ] as const;
  for (const options of olderTimestampCases) {
    const older = evaluateMarketplace({
      mandate: rawMandate(),
      candidates: [capturedQuote(options)],
      evaluatedAt: 1_100,
    });
    const olderScore =
      older.decisions[0]?.score?.factors.evidenceFreshness.scoreBps;
    assert.ok(olderScore !== undefined && olderScore < freshScore);
  }

  const stale = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [capturedQuote({ reputationObservedAt: 1_099 })],
    evaluatedAt: 1_400,
  });
  assert.ok(
    stale.decisions[0]?.findings.some(
      (finding) => finding.code === "REPUTATION_STALE",
    ),
  );
});

test("range derivation has exact width, aligned endpoints, and negative floor semantics", () => {
  const exact = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [capturedQuote()],
    evaluatedAt: 1_100,
  });
  assert.equal(exact.decisions[0]?.outcome, "eligible");
  const evidence = exact.quotes[0]?.categoryEvidence;
  assert.equal(evidence?.category, "rebalancing");
  if (evidence?.category === "rebalancing") {
    assert.equal(evidence.proposedUpperTick - evidence.proposedLowerTick, 100);
    assert.equal(Math.abs(evidence.proposedLowerTick % evidence.tickSpacing), 0);
    assert.equal(Math.abs(evidence.proposedUpperTick % evidence.tickSpacing), 0);
  }

  const negative = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [
      capturedQuote({
        currentTick: -19,
        proposedLowerTick: -70,
        proposedUpperTick: 30,
      }),
    ],
    evaluatedAt: 1_100,
  });
  assert.equal(negative.decisions[0]?.outcome, "eligible");

  const negativeTieMandate = rawMandate();
  const negativeTiePolicy = negativeTieMandate.rebalancing as Record<
    string,
    unknown
  >;
  negativeTiePolicy.approvedLowerTick = -200;
  negativeTiePolicy.targetWidthTicks = 200;
  const negativeTie = evaluateMarketplace({
    mandate: negativeTieMandate,
    candidates: [
      capturedQuote({
        currentTick: -95,
        currentLowerTick: -100,
        currentUpperTick: -90,
        triggerDistanceToBoundaryTicks: 5,
        proposedLowerTick: -190,
        proposedUpperTick: 10,
      }),
    ],
    evaluatedAt: 1_100,
  });
  assert.equal(negativeTie.decisions[0]?.outcome, "eligible");

  const widened = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [capturedQuote({ proposedLowerTick: -40, proposedUpperTick: 70 })],
    evaluatedAt: 1_100,
  });
  assert.ok(
    widened.decisions[0]?.findings.some(
      (finding) => finding.code === "TARGET_WIDTH_MISMATCH",
    ),
  );

  const unaligned = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [
      capturedQuote({ proposedLowerTick: -39, proposedUpperTick: 61 }),
    ],
    evaluatedAt: 1_100,
  });
  assert.ok(
    unaligned.decisions[0]?.findings.some(
      (finding) => finding.code === "TICK_ALIGNMENT_INVALID",
    ),
  );

  const unalignedEnvelopeMandate = rawMandate();
  const unalignedEnvelope = unalignedEnvelopeMandate.rebalancing as Record<
    string,
    unknown
  >;
  unalignedEnvelope.approvedLowerTick = -31;
  unalignedEnvelope.approvedUpperTick = 71;
  const acceptedUnalignedEnvelope = evaluateMarketplace({
    mandate: unalignedEnvelopeMandate,
    candidates: [capturedQuote()],
    evaluatedAt: 1_100,
  });
  assert.equal(acceptedUnalignedEnvelope.decisions[0]?.outcome, "eligible");

  const nondivisibleMandate = rawMandate();
  (nondivisibleMandate.rebalancing as Record<string, unknown>).targetWidthTicks = 95;
  const nondivisible = evaluateMarketplace({
    mandate: nondivisibleMandate,
    candidates: [capturedQuote()],
    evaluatedAt: 1_100,
  });
  assert.ok(
    nondivisible.decisions[0]?.findings.some(
      (finding) => finding.code === "TARGET_WIDTH_NOT_TICK_ALIGNED",
    ),
  );
});

test("mandate lifetime and trigger-mode policy are enforced", () => {
  const expired = evaluateMarketplace({
    mandate: rawMandate(),
    candidates: [capturedQuote()],
    evaluatedAt: 2_000,
  });
  assert.equal(expired.decisions[0]?.outcome, "excluded");
  assert.ok(
    expired.decisions[0]?.findings.some(
      (finding) => finding.code === "MANDATE_EXPIRED",
    ),
  );

  const mandate = rawMandate();
  (mandate.rebalancing as Record<string, unknown>).triggerMode = "out_of_range";
  const mismatchedTrigger = evaluateMarketplace({
    mandate,
    candidates: [capturedQuote()],
    evaluatedAt: 1_100,
  });
  assert.ok(
    mismatchedTrigger.decisions[0]?.findings.some(
      (finding) => finding.code === "TRIGGER_POLICY_MISMATCH",
    ),
  );
});
