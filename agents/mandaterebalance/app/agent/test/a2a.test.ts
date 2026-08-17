import assert from "node:assert/strict";
import { once } from "node:events";
import type { Server } from "node:http";
import test from "node:test";
import type {
  AgentCard,
  DataPart,
  Message,
  SendMessageRequest,
  SendMessageResponse,
} from "@a2a-js/sdk";
import express from "express";
import {
  createA2ARequestHandler,
  mountA2ARoutes,
} from "../src/a2aApp.js";
import { SellerAgentExecutor } from "../src/executor.js";
import {
  type RebalanceEvidence,
  type RebalanceMandate,
  type RebalanceStateReader,
  RebalanceService,
  REQUIRED_REBALANCE_CALLS,
} from "../src/rebalance.js";
import type { SigningApi } from "../src/sellerCore.js";

const NOW = 1_800_000_000;
const JOB_ID = 42;
const POOL = "0x1111111111111111111111111111111111111111";
const MANAGER = "0x427bf5b37357632377ecbec9de3626c71a5396c1";
const TOKEN0 = "0x3333333333333333333333333333333333333333";
const TOKEN1 = "0x4444444444444444444444444444444444444444";
const OWNER = "0x5555555555555555555555555555555555555555";
const CURRENCY = "0x6666666666666666666666666666666666666666";
const QUOTE_BLOCK = 50_000_000;
const DELIVERY_BLOCK = QUOTE_BLOCK + 1;
const QUOTE_BLOCK_HASH = `0x${"aa".repeat(32)}`;
const DELIVERY_BLOCK_HASH = `0x${"bb".repeat(32)}`;

const TEST_AGENT_CARD: AgentCard = {
  name: "MandateX A2A smoke seller",
  description: "Deterministic loopback smoke seller.",
  url: "http://127.0.0.1/",
  version: "1.0.0",
  protocolVersion: "0.3.0",
  preferredTransport: "JSONRPC",
  capabilities: { streaming: false },
  defaultInputModes: ["application/json"],
  defaultOutputModes: ["application/json"],
  skills: [
    {
      id: "negotiate",
      name: "Negotiate",
      description: "Prepare a deterministic MandateX quote.",
      tags: ["mandatex"],
      inputModes: ["application/json"],
      outputModes: ["application/json"],
    },
    {
      id: "notify_funded",
      name: "Notify funded",
      description: "Start deterministic receipt delivery.",
      tags: ["mandatex"],
      inputModes: ["application/json"],
      outputModes: ["application/json"],
    },
  ],
};

function validMandate(): RebalanceMandate {
  return {
    version: "1",
    mandate_id: "a2a-smoke-rebalance",
    category: "rebalancing",
    chain_id: 97,
    protocol: "pancakeswap-v3",
    expires_at: NOW + 900,
    max_evidence_age_seconds: 120,
    position: {
      pool_address: POOL,
      position_manager_address: MANAGER,
      token_id: "42",
    },
    range_policy: {
      approved_lower_tick: -600,
      approved_upper_tick: 600,
      target_width_ticks: 120,
      trigger_mode: "boundary_proximity",
      trigger_distance_ticks: 30,
      max_delivery_tick_drift: 30,
    },
    limits: {
      max_gas_usd: 3,
      max_slippage_bps: 50,
      max_exposure_usd: 1000,
    },
    execution_estimate: {
      gas_usd: 1.25,
      slippage_bps: 30,
      exposure_usd: 500,
      observed_at: NOW - 5,
      source_url: "https://example.com/estimates/a2a-smoke-rebalance",
    },
    permissions: {
      allowed_contracts: [MANAGER],
      allowed_calls: [...REQUIRED_REBALANCE_CALLS],
      spend_cap_usd: 750,
      expires_at: NOW + 600,
    },
  };
}

function evidence(
  observedBlock: number,
  observedBlockHash: string,
  observedAt: number,
  currentTick: number,
): RebalanceEvidence {
  return {
    network: "bsc-testnet",
    chain_id: 97,
    snapshot_head_block: observedBlock + 2,
    confirmation_depth_blocks: 2,
    observed_block: observedBlock,
    observed_block_hash: observedBlockHash,
    observed_at: observedAt,
    pool_address: POOL,
    position_manager_address: MANAGER,
    position_token_id: "42",
    position_owner: OWNER,
    token0: TOKEN0,
    token1: TOKEN1,
    token0_decimals: 18,
    token1_decimals: 18,
    fee: 2500,
    tick_spacing: 60,
    current_tick: currentTick,
    sqrt_price_x96: "79704936542881920863903188246",
    approximate_token1_per_token0: "1.01197061622",
    position_tick_lower: -120,
    position_tick_upper: 120,
    pool_liquidity: "2000000",
    position_liquidity: "1000000",
    sources: [
      {
        type: "onchain",
        url: `https://testnet.bscscan.com/block/${observedBlock}`,
        observed_block: observedBlock,
      },
    ],
  };
}

class DeterministicStateReader implements RebalanceStateReader {
  calls = 0;

  async read(): Promise<RebalanceEvidence> {
    const value =
      this.calls === 0
        ? evidence(QUOTE_BLOCK, QUOTE_BLOCK_HASH, NOW - 2, 119)
        : evidence(DELIVERY_BLOCK, DELIVERY_BLOCK_HASH, NOW - 1, 120);
    this.calls += 1;
    return structuredClone(value);
  }
}

interface Submission {
  jobId: number;
  content: string;
  metadata: Record<string, unknown> | null | undefined;
}

interface FakeSigning extends SigningApi {
  fundedSpec: { task: string; terms: Record<string, unknown> } | null;
  signCalls: number;
  verifyCalls: number[];
  jobSpecCalls: number[];
  submitCalls: number;
  submissions: Submission[];
}

function signingFake(submitGate: Promise<void>): FakeSigning {
  const fake: FakeSigning = {
    fundedSpec: null,
    signCalls: 0,
    verifyCalls: [],
    jobSpecCalls: [],
    submitCalls: 0,
    submissions: [],
    listPrice: () => 25n,
    clampPrice: (price) => price,
    signQuote: async (request, price) => {
      fake.signCalls += 1;
      const task = request.task_description;
      const terms = request.terms;
      assert.equal(typeof task, "string");
      assert.ok(isRecord(terms));
      fake.fundedSpec = { task, terms };
      return {
        request,
        request_hash: `0x${"11".repeat(32)}`,
        response: {
          accepted: true,
          terms: {
            ...terms,
            price: String(price),
            currency: CURRENCY,
          },
          quote_expires_at: NOW + 300,
        },
        response_hash: `0x${"22".repeat(32)}`,
        negotiation_hash: `0x${"33".repeat(32)}`,
        provider_sig: `0x${"44".repeat(65)}`,
        negotiated_at: NOW,
        quote_expires_at: NOW + 300,
        chain_id: 97,
        verifying_contract: MANAGER,
      };
    },
    verifySignedJob: async (jobId) => {
      fake.verifyCalls.push(jobId);
      return { ok: true, reason: "funded", permanent: false };
    },
    jobSpec: async (jobId) => {
      fake.jobSpecCalls.push(jobId);
      return fake.fundedSpec;
    },
    submitResult: async (jobId, content, metadata) => {
      fake.submitCalls += 1;
      await submitGate;
      fake.submissions.push({ jobId, content, metadata });
      return {
        submitTx: `0x${"55".repeat(32)}`,
        deliverableUrl: "https://example.com/receipts/42.json",
      };
    },
  };
  return fake;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function messageData(message: Message): Record<string, unknown> {
  const part = message.parts.find((candidate): candidate is DataPart => {
    return candidate.kind === "data";
  });
  assert.ok(part, "expected an A2A data part");
  return part.data;
}

async function sendData(
  baseUrl: string,
  id: string,
  data: Record<string, unknown>,
): Promise<Message> {
  const request: SendMessageRequest = {
    jsonrpc: "2.0",
    id,
    method: "message/send",
    params: {
      message: {
        kind: "message",
        messageId: `${id}-message`,
        role: "user",
        parts: [{ kind: "data", data }],
      },
    },
  };
  const response = await fetch(baseUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request),
    signal: AbortSignal.timeout(2_000),
  });
  assert.equal(response.status, 200);
  const payload = (await response.json()) as SendMessageResponse;
  assert.equal(payload.jsonrpc, "2.0");
  assert.equal(payload.id, id);
  assert.ok("result" in payload, JSON.stringify(payload));
  assert.equal(payload.result.kind, "message");
  return payload.result as Message;
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

async function closeServer(server: Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

test(
  "A2A loopback negotiates and submits one deterministic funded receipt",
  { timeout: 10_000 },
  async () => {
    const submitGate = deferred();
    const signing = signingFake(submitGate.promise);
    const reader = new DeterministicStateReader();
    const rebalance = new RebalanceService({ reader, now: () => NOW });
    let llmCalls = 0;
    let pendingJobCalls = 0;
    const executor = new SellerAgentExecutor({
      generator: "a2a-smoke",
      network: "bsc-testnet",
      signing,
      rebalance,
      runWork: async () => {
        llmCalls += 1;
        throw new Error("the deterministic MandateX path must not call the LLM");
      },
      pendingJobs: async () => {
        pendingJobCalls += 1;
        return { jobs: [] };
      },
    });
    const handler = createA2ARequestHandler(TEST_AGENT_CARD, executor);
    const app = express();
    mountA2ARoutes(app, handler);

    const server = app.listen(0, "127.0.0.1");
    await once(server, "listening");
    const address = server.address();
    assert.ok(address !== null && typeof address === "object");
    const baseUrl = `http://127.0.0.1:${address.port}`;

    try {
      const cardResponse = await fetch(
        `${baseUrl}/.well-known/agent-card.json`,
        { signal: AbortSignal.timeout(2_000) },
      );
      assert.equal(cardResponse.status, 200);
      const servedCard = (await cardResponse.json()) as AgentCard;
      assert.equal(servedCard.name, TEST_AGENT_CARD.name);
      assert.deepEqual(servedCard.skills, TEST_AGENT_CARD.skills);

      const quoteMessage = await sendData(baseUrl, "negotiate-1", {
        skill: "negotiate",
        request: { mandate: validMandate() },
      });
      const quote = messageData(quoteMessage);
      assert.equal(
        (quote.response as Record<string, unknown>).accepted,
        true,
      );
      assert.equal(signing.signCalls, 1);
      assert.ok(signing.fundedSpec);
      const signedRequest = quote.request as Record<string, unknown>;
      assert.equal(
        signedRequest.task_description,
        signing.fundedSpec.task,
      );
      assert.deepEqual(signedRequest.terms, signing.fundedSpec.terms);

      const acceptedMessage = await sendData(baseUrl, "notify-1", {
        skill: "notify_funded",
        job_id: JOB_ID,
      });
      const accepted = messageData(acceptedMessage);
      assert.equal(accepted.status, "accepted");
      assert.equal(accepted.job_id, JOB_ID);
      assert.equal(executor.isBusy(), true);
      assert.equal(signing.submissions.length, 0);

      submitGate.resolve();
      await executor.drain();

      assert.equal(executor.isBusy(), false);
      assert.deepEqual(signing.verifyCalls, [JOB_ID]);
      assert.deepEqual(signing.jobSpecCalls, [JOB_ID]);
      assert.equal(signing.submitCalls, 1);
      assert.equal(signing.submissions.length, 1);
      assert.equal(signing.submissions[0].jobId, JOB_ID);
      assert.equal(
        signing.submissions[0].metadata?.mandatex_receipt_status,
        "simulation_ready",
      );
      const receipt = JSON.parse(signing.submissions[0].content) as Record<
        string,
        unknown
      >;
      assert.equal(receipt.status, "simulation_ready");
      assert.equal(receipt.simulation_only, true);
      assert.equal(receipt.job_id, JOB_ID);
      assert.equal(
        (receipt.quoted_evidence as Record<string, unknown>).observed_block,
        QUOTE_BLOCK,
      );
      assert.equal(
        (receipt.delivery_evidence as Record<string, unknown>).observed_block,
        DELIVERY_BLOCK,
      );
      assert.equal(reader.calls, 2);
      assert.equal(pendingJobCalls, 1);
      assert.equal(llmCalls, 0);
    } finally {
      submitGate.resolve();
      await executor.drain();
      await closeServer(server);
    }
  },
);
