import assert from "node:assert/strict";
import test from "node:test";

import {
  GRID_ADAPTER_ID,
  GRID_EVIDENCE_SCHEMA,
  SELECTOR_SLOT0,
  SELECTOR_TOTAL_ASSETS,
} from "@mandatex/category-adapters";

import {
  CATEGORY_EXECUTION_ARTIFACT_SCHEMA,
  CATEGORY_VERIFIER_POLICY_PROFILE,
  categoryExecutionArtifactSchema,
} from "../src/category/schema.js";
import { CATEGORY_ADAPTER_VALIDATION_PROFILES } from "../src/category/policy.js";
import { canonicalQuoteJson, computeQuoteSha256 } from "../src/quotes/protocol.js";

const BLOCK_HASH = `0x${"b".repeat(64)}`;
const POOL = "0x1111111111111111111111111111111111111111";
const OTHER = "0x2222222222222222222222222222222222222222";
const REQUEST_SHA256 = "1".repeat(64);
const RESPONSE_SHA256 = "2".repeat(64);

test("category artifact schema recomputes evidence hashes", () => {
  const artifact = gridPassArtifact();
  assert.equal(categoryExecutionArtifactSchema.safeParse(artifact).success, true);

  artifact.result.evidenceSha256 = "0".repeat(64);
  assert.equal(categoryExecutionArtifactSchema.safeParse(artifact).success, false);
});

test("category artifact schema binds pass evidence to exact reads and pass semantics", () => {
  const wrongTarget = gridPassArtifact();
  wrongTarget.reads[0]!.to = OTHER;
  wrongTarget.result.evidence.reads[0]!.to = OTHER;
  rehash(wrongTarget);
  assert.equal(categoryExecutionArtifactSchema.safeParse(wrongTarget).success, false);

  const wrongCalldata = gridPassArtifact();
  (wrongCalldata.reads[0]! as { data: string }).data = SELECTOR_TOTAL_ASSETS;
  assert.equal(categoryExecutionArtifactSchema.safeParse(wrongCalldata).success, false);

  const outsideBand = gridPassArtifact();
  outsideBand.result.evidence.metric.spotTick = 11;
  rehash(outsideBand);
  assert.equal(categoryExecutionArtifactSchema.safeParse(outsideBand).success, false);
});

test("category artifact schema binds unknown codes to read outcomes", () => {
  const unavailableWithSuccess = unknownArtifact("READ_UNAVAILABLE");
  assert.equal(
    categoryExecutionArtifactSchema.safeParse(unavailableWithSuccess).success,
    false,
  );

  const unavailable = unknownArtifact("READ_UNAVAILABLE");
  unavailable.reads[0]!.outcome = "unavailable";
  delete unavailable.reads[0]!.responseSha256;
  assert.equal(categoryExecutionArtifactSchema.safeParse(unavailable).success, true);

  const successfulWithoutDigest = unknownArtifact(
    "READ_RETURNDATA_MALFORMED",
  );
  delete successfulWithoutDigest.reads[0]!.responseSha256;
  assert.equal(
    categoryExecutionArtifactSchema.safeParse(successfulWithoutDigest).success,
    false,
  );

  const measuredWithUnavailableRead = unknownArtifact(
    "GRID_TICK_UNINTERPRETABLE",
  );
  measuredWithUnavailableRead.reads[0]!.outcome = "invalid_response";
  assert.equal(
    categoryExecutionArtifactSchema.safeParse(measuredWithUnavailableRead)
      .success,
    false,
  );
});

function gridPassArtifact() {
  const observation = {
    label: "slot0",
    to: POOL,
    requestSha256: REQUEST_SHA256,
    responseSha256: RESPONSE_SHA256,
  };
  const evidence = {
    schema: GRID_EVIDENCE_SCHEMA,
    category: "grid" as const,
    protocol: "pancakeswap-v3" as const,
    adapterId: GRID_ADAPTER_ID,
    observedAt: 100,
    observedBlock: 98,
    observedBlockHash: BLOCK_HASH,
    subject: { poolAddress: POOL },
    policy: { lowerTick: -10, upperTick: 10 },
    metric: {
      spotTick: 0,
      sqrtPriceX96: (2n ** 96n).toString(10),
    },
    reads: [{ ...observation }],
  };
  return {
    schema: CATEGORY_EXECUTION_ARTIFACT_SCHEMA,
    chainId: 56 as const,
    confirmationDepth: 2 as const,
    deploymentSha256: "a".repeat(64),
    verifierPolicyProfile: CATEGORY_VERIFIER_POLICY_PROFILE,
    verifierPolicySha256: "c".repeat(64),
    evaluatedAt: 110,
    adapter: {
      adapterId: GRID_ADAPTER_ID,
      category: "grid" as const,
      evidenceSchema: GRID_EVIDENCE_SCHEMA,
      protocol: "pancakeswap-v3" as const,
      validationProfile: CATEGORY_ADAPTER_VALIDATION_PROFILES.grid,
    },
    anchor: { number: 98, hash: BLOCK_HASH, timestamp: 100 },
    reads: [
      {
        ...observation,
        data: SELECTOR_SLOT0,
        outcome: "success" as const,
      },
    ],
    result: {
      status: "pass" as const,
      evidenceSha256: computeQuoteSha256(canonicalQuoteJson(evidence)),
      evidence,
    },
  };
}

function rehash(artifact: ReturnType<typeof gridPassArtifact>): void {
  artifact.result.evidenceSha256 = computeQuoteSha256(
    canonicalQuoteJson(artifact.result.evidence),
  );
}

function unknownArtifact(
  code:
    | "READ_UNAVAILABLE"
    | "READ_RETURNDATA_MALFORMED"
    | "GRID_TICK_UNINTERPRETABLE",
) {
  const artifact = gridPassArtifact() as unknown as {
    [key: string]: unknown;
    reads: Array<{
      [key: string]: unknown;
      outcome: "success" | "unavailable" | "invalid_response";
      responseSha256?: string;
    }>;
    result: unknown;
  };
  artifact.result = {
    status: "unknown",
    code,
    message: "the category metric could not be established",
  };
  return artifact;
}
