import assert from "node:assert/strict";
import test from "node:test";
import {
  FIXED_REBALANCE_TERMS,
  type RebalanceDeliveryApi,
  type RebalanceReceipt,
} from "../src/rebalance.js";
import {
  parseJobId,
  SellerCore,
  type SigningApi,
} from "../src/sellerCore.js";

function signingFake(): SigningApi & {
  signCalls: Record<string, unknown>[];
  submitted: string[];
  spec: { task: string; terms: Record<string, unknown> } | null;
} {
  const fake = {
    signCalls: [] as Record<string, unknown>[],
    submitted: [] as string[],
    spec: null as { task: string; terms: Record<string, unknown> } | null,
    listPrice: () => 0n,
    clampPrice: (price: bigint) => price,
    signQuote: async (request: Record<string, unknown>) => {
      fake.signCalls.push(request);
      return {
        request,
        response: { accepted: true },
        negotiation_hash: "0x01",
        provider_sig: "0x02",
      };
    },
    verifySignedJob: async () => ({ ok: true, reason: "ok", permanent: false }),
    jobSpec: async () => fake.spec,
    submitResult: async (_jobId: number, content: string) => {
      fake.submitted.push(content);
      return { submitTx: "0xsubmit", deliverableUrl: "file:///receipt.json" };
    },
  };
  return fake;
}

function receipt(status: "simulation_ready" | "refused"): RebalanceReceipt {
  return {
    schema: "mandatex.rebalance.receipt.v1",
    job_id: 1,
    mandate_id: "m1",
    status,
    execution_mode: "simulation",
    simulation_only: true,
    policy_result: status === "simulation_ready" ? "within_mandate" : "refused_by_rule",
    quoted_evidence: null,
    delivery_evidence: null,
    proposal: null,
    refusal:
      status === "refused"
        ? { code: "STATE_DRIFT", message: "tick moved" }
        : null,
    generated_at: 1_800_000_000,
    note: "test",
  };
}

test("valid MandateX quote signs exactly the normalized request", async () => {
  const signing = signingFake();
  let prepareCalls = 0;
  const rebalance: RebalanceDeliveryApi = {
    prepareQuote: async () => {
      prepareCalls += 1;
      return {
        ok: true,
        request: {
          task_description: "mandatex-rebalance:v1:encoded",
          terms: FIXED_REBALANCE_TERMS,
        },
        signedTask: {
          schema: "mandatex.rebalance.quote.v1",
          mandate: { mandate_id: "m1" } as never,
          evidence: { observed_block: 123 } as never,
          proposal: {
            proposed_lower_tick: -60,
            proposed_upper_tick: 60,
          } as never,
          eligibility: { eligible: true, checked_at: 1, checks: [] },
        },
      };
    },
    deliver: async () => null,
  };
  let llmCalls = 0;
  const core = new SellerCore({
    signing,
    rebalance,
    generator: "test",
    runWork: async () => {
      llmCalls += 1;
      return "unused";
    },
    pendingJobs: async () => ({ jobs: [] }),
  });

  const result = await core.negotiate({ request: { mandate: { version: "1" } } });
  assert.equal(prepareCalls, 1);
  assert.equal(signing.signCalls.length, 1);
  assert.equal(signing.signCalls[0].task_description, "mandatex-rebalance:v1:encoded");
  assert.equal((result.mandatex as Record<string, unknown>).display_only, true);
  assert.equal(llmCalls, 0);
});

test("policy rejection never signs or calls the LLM", async () => {
  const signing = signingFake();
  let llmCalls = 0;
  const core = new SellerCore({
    signing,
    rebalance: {
      prepareQuote: async () => ({
        ok: false,
        refusal: {
          code: "UNSUPPORTED_CHAIN",
          message: "wrong chain",
        },
      }),
      deliver: async () => null,
    },
    generator: "test",
    runWork: async () => {
      llmCalls += 1;
      return "unused";
    },
    pendingJobs: async () => ({ jobs: [] }),
  });

  const result = await core.negotiate({ mandate: {} });
  assert.equal((result.response as Record<string, unknown>).accepted, false);
  assert.equal(signing.signCalls.length, 0);
  assert.equal(llmCalls, 0);
});

test("recognized funded jobs submit deterministic receipts without the LLM", async () => {
  const signing = signingFake();
  signing.spec = {
    task: "mandatex-rebalance:v1:encoded",
    terms: structuredClone(FIXED_REBALANCE_TERMS),
  };
  let llmCalls = 0;
  let deliveryCalls = 0;
  const core = new SellerCore({
    signing,
    rebalance: {
      prepareQuote: async () => {
        throw new Error("unused");
      },
      deliver: async () => {
        deliveryCalls += 1;
        return receipt("simulation_ready");
      },
    },
    generator: "test",
    runWork: async () => {
      llmCalls += 1;
      return "LLM output";
    },
    pendingJobs: async () => ({ jobs: [] }),
  });

  const ack = await core.notifyFunded({ job_id: 1 });
  assert.equal(ack.status, "accepted");
  await core.drain();
  assert.equal(deliveryCalls, 1);
  assert.equal(llmCalls, 0);
  assert.equal(signing.submitted.length, 1);
  assert.equal(JSON.parse(signing.submitted[0]).status, "simulation_ready");
});

test("invalid job ids are rejected without verification", async () => {
  for (const raw of [-1, 1.5, "-1", "9007199254740992", "not-an-id"]) {
    const signing = signingFake();
    let verifies = 0;
    signing.verifySignedJob = async () => {
      verifies += 1;
      return { ok: true, reason: "ok", permanent: false };
    };
    const core = new SellerCore({
      signing,
      rebalance: {
        prepareQuote: async () => {
          throw new Error("unused");
        },
        deliver: async () => null,
      },
      generator: "test",
      runWork: async () => "unused",
      pendingJobs: async () => ({ jobs: [] }),
    });
    const result = await core.notifyFunded({ job_id: raw });
    assert.equal(result.status, "rejected");
    assert.equal(verifies, 0);
  }
});

test("parseJobId accepts decimal and hex safe integers only", () => {
  assert.equal(parseJobId(0), 0);
  assert.equal(parseJobId("42"), 42);
  assert.equal(parseJobId("0x2a"), 42);
  assert.throws(() => parseJobId(-1));
  assert.throws(() => parseJobId(BigInt(Number.MAX_SAFE_INTEGER) + 1n));
});
