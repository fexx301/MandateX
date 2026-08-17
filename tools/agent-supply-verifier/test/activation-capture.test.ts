import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";

import { encodeFunctionData, parseAbi } from "viem";

import { captureActivationIntent } from "../src/activation/capture.js";
import { BSC_ACTIVATION_DEPLOYMENT } from "../src/activation/deployment.js";
import {
  ACTIVATION_CLIENT,
  ACTIVATION_JOB_EXPIRES_AT,
  ACTIVATION_JOB_ID,
  ACTIVATION_PROVIDER,
} from "./activation-fixture.js";

const commerceWriteAbi = parseAbi([
  "function createJob(address provider,address evaluator,uint256 expiredAt,string description,address hook)",
  "function setBudget(uint256 jobId,uint256 amount,bytes optParams)",
  "function fund(uint256 jobId,uint256 expectedBudget,bytes optParams)",
]);
const routerWriteAbi = parseAbi([
  "function registerJob(uint256 jobId,address policy)",
]);

test("SDK capture produces one exact unsigned zero-value intent per activation operation", async () => {
  const description = "mandatex activation capture fixture";
  const jobId = BigInt(ACTIVATION_JOB_ID);
  const cases = [
    {
      operation: "create_job" as const,
      intent: await captureActivationIntent({
        operation: "create_job",
        client: ACTIVATION_CLIENT,
        provider: ACTIVATION_PROVIDER,
        expiredAt: BigInt(ACTIVATION_JOB_EXPIRES_AT),
        description,
      }),
      target: BSC_ACTIVATION_DEPLOYMENT.commerceProxy,
      data: encodeFunctionData({
        abi: commerceWriteAbi,
        functionName: "createJob",
        args: [
          ACTIVATION_PROVIDER,
          BSC_ACTIVATION_DEPLOYMENT.routerProxy,
          BigInt(ACTIVATION_JOB_EXPIRES_AT),
          description,
          BSC_ACTIVATION_DEPLOYMENT.routerProxy,
        ],
      }).toLowerCase(),
    },
    {
      operation: "register_job" as const,
      intent: await captureActivationIntent({
        operation: "register_job",
        client: ACTIVATION_CLIENT,
        jobId,
      }),
      target: BSC_ACTIVATION_DEPLOYMENT.routerProxy,
      data: encodeFunctionData({
        abi: routerWriteAbi,
        functionName: "registerJob",
        args: [jobId, BSC_ACTIVATION_DEPLOYMENT.policy],
      }).toLowerCase(),
    },
    {
      operation: "set_budget" as const,
      intent: await captureActivationIntent({
        operation: "set_budget",
        client: ACTIVATION_CLIENT,
        jobId,
      }),
      target: BSC_ACTIVATION_DEPLOYMENT.commerceProxy,
      data: encodeFunctionData({
        abi: commerceWriteAbi,
        functionName: "setBudget",
        args: [jobId, 0n, "0x"],
      }).toLowerCase(),
    },
    {
      operation: "fund" as const,
      intent: await captureActivationIntent({
        operation: "fund",
        client: ACTIVATION_CLIENT,
        jobId,
      }),
      target: BSC_ACTIVATION_DEPLOYMENT.commerceProxy,
      data: encodeFunctionData({
        abi: commerceWriteAbi,
        functionName: "fund",
        args: [jobId, 0n, "0x"],
      }).toLowerCase(),
    },
  ];

  for (const entry of cases) {
    assert.equal(entry.intent.operation, entry.operation);
    assert.equal(entry.intent.from, ACTIVATION_CLIENT);
    assert.equal(entry.intent.to, entry.target);
    assert.equal(entry.intent.valueWei, "0");
    assert.equal(entry.intent.data, entry.data);
    assert.equal(
      entry.intent.calldataSha256,
      createHash("sha256")
        .update(Buffer.from(entry.data.slice(2), "hex"))
        .digest("hex"),
    );
  }
});
