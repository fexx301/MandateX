import {
  GRID_ADAPTER_ID,
  HEALTH_ADAPTER_ID,
  VENUS_HEALTH_ADAPTER_ID,
  YIELD_ADAPTER_ID,
  addressCalldata,
  evaluateGrid,
  evaluateHealth,
  evaluateVenusHealth,
  evaluateYield,
  failResult,
  gridAdapterConfigSchema,
  gridEvidenceSchema,
  healthAdapterConfigSchema,
  healthEvidenceSchema,
  unknownResult,
  venusHealthAdapterConfigSchema,
  venusHealthEvidenceSchema,
  yieldAdapterConfigSchema,
  yieldEvidenceSchema,
  type AdapterResult,
  type CategoryEvidenceDocument,
} from "@mandatex/category-adapters";

import { canonicalQuoteJson, computeQuoteSha256 } from "../quotes/protocol.js";
import type { PinnedHttpsTransport } from "../transport/http.js";
import {
  categoryAdapterDeploymentSha256,
  parseCategoryAdapterDeploymentManifest,
  type CategoryAdapterDeploymentEntry,
  type CategoryAdapterDeploymentManifest,
} from "./policy.js";
import {
  CATEGORY_CONFIRMATION_DEPTH,
  CategoryBlockCanonicalityError,
  CategoryBlockPinError,
  CategoryReadContractError,
  TransportPinnedCategoryReader,
  type ExpectedCategoryRead,
} from "./rpc.js";
import {
  CATEGORY_EXECUTION_ARTIFACT_SCHEMA,
  CATEGORY_EXECUTION_RESULT_SCHEMA,
  CATEGORY_VERIFIER_POLICY_PROFILE,
  categoryExecutionArtifactSchema,
  type CategoryExecutionArtifact,
  type CategoryExecutionInconclusive,
  type CategoryReadAttempt,
  type TrustedCategoryExecution,
  type TrustedCategoryExecutionResult,
  type TrustedCategoryExecutionSuccess,
} from "./schema.js";

export type CategoryAdapterExecutionInput = Readonly<{
  category: "grid" | "yield" | "health";
}>;

export interface CategoryAdapterExecutorOptions {
  readonly deployment: unknown;
  readonly verifierPolicySha256: string;
  readonly transport: Pick<PinnedHttpsTransport, "request">;
  readonly clock: () => number;
  readonly randomUUID: () => string;
}

export interface CategoryAdapterExecutor {
  readonly deployment: CategoryAdapterDeploymentManifest;
  readonly deploymentSha256: string;
  readonly verifierPolicySha256: string;
  readonly evaluate: (
    input: CategoryAdapterExecutionInput,
  ) => Promise<TrustedCategoryExecutionResult>;
}

type TrustedCategoryExecutionProvenance = Readonly<{
  executor: CategoryAdapterExecutor;
  artifact: CategoryExecutionArtifact;
  artifactSha256: string;
  deploymentSha256: string;
  verifierPolicySha256: string;
}>;

const trustedCategoryExecutionResults = new WeakMap<
  object,
  TrustedCategoryExecutionProvenance
>();

export function createCategoryAdapterExecutor(
  options: CategoryAdapterExecutorOptions,
): CategoryAdapterExecutor {
  const deployment = parseCategoryAdapterDeploymentManifest(options.deployment);
  const deploymentSha256 = categoryAdapterDeploymentSha256(deployment);
  const verifierPolicySha256 = parseSha256(options.verifierPolicySha256);
  if (typeof options.transport?.request !== "function") {
    throw new TypeError("category executor transport must expose request()");
  }
  if (typeof options.clock !== "function" || typeof options.randomUUID !== "function") {
    throw new TypeError("category executor clock and UUID source must be functions");
  }
  const receiver = options.transport;
  const request = options.transport.request;
  const transport = Object.freeze({
    request: (route: Parameters<typeof request>[0]) => request.call(receiver, route),
  });
  const clock = options.clock;
  const randomUUID = options.randomUUID;

  const executor: CategoryAdapterExecutor = Object.freeze({
    deployment,
    deploymentSha256,
    verifierPolicySha256,
    async evaluate(
      input: CategoryAdapterExecutionInput,
    ): Promise<TrustedCategoryExecutionResult> {
      const category = parseExecutionCategory(input);
      const entry = deployment.adapters.find(
        (candidate) => candidate.enabled && candidate.category === category,
      );
      if (entry === undefined || entry.configuration === undefined) {
        return inconclusive(
          category,
          "CATEGORY_ADAPTER_NOT_CONFIGURED",
          "no adapter is enabled for this category in the pinned deployment",
        );
      }

      const runtime = runtimeContract(entry);
      let reader: TransportPinnedCategoryReader;
      try {
        reader = await TransportPinnedCategoryReader.create({
          transport,
          randomUUID,
          expectedReads: runtime.expectedReads,
        });
      } catch (cause) {
        if (cause instanceof CategoryBlockPinError) {
          return inconclusive(
            category,
            "CATEGORY_BLOCK_PIN_UNAVAILABLE",
            "a canonical confirmed BSC block could not be pinned",
          );
        }
        if (cause instanceof CategoryReadContractError) {
          return inconclusive(
            category,
            "CATEGORY_ADAPTER_EXECUTION_INVALID",
            "the category transport rejected the manifest-derived block-pinning route",
          );
        }
        throw cause;
      }

      let adapterResult: AdapterResult<unknown>;
      try {
        adapterResult = await runtime.evaluate(reader);
      } catch {
        return inconclusive(
          category,
          "CATEGORY_ADAPTER_EXECUTION_INVALID",
          "the configured adapter did not return a valid fail-closed result",
        );
      }

      let reads;
      try {
        reads = reader.attempts();
      } catch (cause) {
        if (cause instanceof CategoryReadContractError) {
          return inconclusive(
            category,
            "CATEGORY_ADAPTER_EXECUTION_INVALID",
            "the adapter did not execute the exact manifest-derived read set",
          );
        }
        throw cause;
      }
      try {
        await reader.assertCanonical();
      } catch (cause) {
        if (cause instanceof CategoryBlockCanonicalityError) {
          return inconclusive(
            category,
            "CATEGORY_BLOCK_NONCANONICAL",
            "the pinned BSC block changed before category evidence was finalized",
          );
        }
        if (cause instanceof CategoryReadContractError) {
          return inconclusive(
            category,
            "CATEGORY_ADAPTER_EXECUTION_INVALID",
            "the category transport rejected the manifest-derived canonicality route",
          );
        }
        throw cause;
      }

      let artifact: CategoryExecutionArtifact;
      try {
        artifact = buildArtifact({
          entry,
          adapterResult,
          reads,
          anchor: reader.anchor,
          deploymentSha256,
          verifierPolicySha256,
          evaluatedAt: readClock(clock),
        });
      } catch {
        return inconclusive(
          category,
          "CATEGORY_ADAPTER_EXECUTION_INVALID",
          "the adapter result did not match its pinned identity, policy, or evidence schema",
        );
      }

      const artifactSha256 = canonicalSha256(artifact);
      const result = deepFreeze({
        schema: CATEGORY_EXECUTION_RESULT_SCHEMA,
        outcome: "executed" as const,
        artifactSha256,
        artifact,
      });
      trustedCategoryExecutionResults.set(
        result,
        Object.freeze({
          executor,
          artifact: result.artifact,
          artifactSha256,
          deploymentSha256,
          verifierPolicySha256,
        }),
      );
      return result;
    },
  });
  return executor;
}

export function assertTrustedCategoryExecutionSuccess(
  value: unknown,
  executor: CategoryAdapterExecutor,
): asserts value is TrustedCategoryExecutionSuccess {
  assertTrustedCategoryExecution(value, executor);
  const result = value as TrustedCategoryExecution;
  if (result.artifact.result.status !== "pass") {
    throw new Error("trusted category execution did not produce a pass result");
  }
}

export function assertTrustedCategoryExecution(
  value: unknown,
  executor: CategoryAdapterExecutor,
): asserts value is TrustedCategoryExecution {
  if (value === null || typeof value !== "object") {
    throw new Error("category execution result lacks trusted in-process provenance");
  }
  const provenance = trustedCategoryExecutionResults.get(value);
  if (provenance === undefined) {
    throw new Error("category execution result lacks trusted in-process provenance");
  }
  if (provenance.executor !== executor) {
    throw new Error("category execution result belongs to a different executor");
  }
  if (!hasExactDataKeys(value, ["artifact", "artifactSha256", "outcome", "schema"])) {
    throw new Error("trusted category execution result changed after validation");
  }
  const result = value as TrustedCategoryExecution;
  if (
    result.artifact !== provenance.artifact ||
    result.schema !== CATEGORY_EXECUTION_RESULT_SCHEMA ||
    result.outcome !== "executed" ||
    result.artifactSha256 !== provenance.artifactSha256
  ) {
    throw new Error("trusted category execution result changed after validation");
  }
  const artifact = categoryExecutionArtifactSchema.parse(result.artifact);
  if (
    artifact.deploymentSha256 !== provenance.deploymentSha256 ||
    artifact.verifierPolicySha256 !== provenance.verifierPolicySha256 ||
    artifact.deploymentSha256 !== executor.deploymentSha256 ||
    artifact.verifierPolicySha256 !== executor.verifierPolicySha256
  ) {
    throw new Error("trusted category execution provenance changed after validation");
  }
  if (artifact.result.status === "pass") {
    const evidenceSha256 = canonicalSha256(artifact.result.evidence);
    if (artifact.result.evidenceSha256 !== evidenceSha256) {
      throw new Error("trusted category evidence hash changed after validation");
    }
  }
  const actual = canonicalSha256(artifact);
  if (
    result.artifactSha256 !== actual ||
    provenance.artifactSha256 !== actual
  ) {
    throw new Error("trusted category execution result changed after validation");
  }
}

function parseExecutionCategory(
  value: unknown,
): CategoryAdapterExecutionInput["category"] {
  let category: unknown;
  try {
    if (!isRecord(value) || Reflect.ownKeys(value).length !== 1) {
      throw new TypeError();
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, "category");
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    ) {
      throw new TypeError();
    }
    category = descriptor.value;
  } catch {
    throw new TypeError(
      "category execution input must contain one supported category",
    );
  }
  if (
    typeof category !== "string" ||
    !["grid", "yield", "health"].includes(category)
  ) {
    throw new TypeError(
      "category execution input must contain one supported category",
    );
  }
  return category as CategoryAdapterExecutionInput["category"];
}

function assertAdapterResultContract(
  entry: CategoryAdapterDeploymentEntry,
  result: AdapterResult<unknown>,
): void {
  if (!isRecord(result)) {
    throw new TypeError("category adapter result must be a plain object");
  }
  if (result.status === "pass") {
    if (
      !hasExactDataKeys(result, ["adapterId", "category", "evidence", "status"])
    ) {
      throw new TypeError("category adapter pass result has unexpected fields");
    }
    return;
  }
  if (
    !hasExactDataKeys(result, [
      "adapterId",
      "category",
      "code",
      "message",
      "status",
    ])
  ) {
    throw new TypeError("category adapter result has unexpected fields");
  }
  const expected =
    result.status === "fail"
      ? failResult(entry.adapterId, entry.category, result.code)
      : unknownResult(entry.adapterId, entry.category, result.code);
  if (canonicalQuoteJson(result) !== canonicalQuoteJson(expected)) {
    throw new TypeError("category adapter result code or message mismatch");
  }
}

function parseEvidenceForEntry(
  entry: CategoryAdapterDeploymentEntry,
  value: unknown,
): CategoryEvidenceDocument {
  switch (entry.adapterId) {
    case GRID_ADAPTER_ID:
      return gridEvidenceSchema.parse(value);
    case YIELD_ADAPTER_ID:
      return yieldEvidenceSchema.parse(value);
    case HEALTH_ADAPTER_ID:
      return healthEvidenceSchema.parse(value);
    case VENUS_HEALTH_ADAPTER_ID:
      return venusHealthEvidenceSchema.parse(value);
  }
}

function runtimeContract(entry: CategoryAdapterDeploymentEntry): Readonly<{
  expectedReads: readonly ExpectedCategoryRead[];
  evaluate: (
    reader: TransportPinnedCategoryReader,
  ) => Promise<AdapterResult<unknown>>;
}> {
  if (!entry.enabled || entry.configuration === undefined) {
    throw new TypeError("category adapter is not enabled");
  }
  switch (entry.adapterId) {
    case GRID_ADAPTER_ID: {
      const [slot0Read] = entry.reads;
      if (slot0Read === undefined) {
        throw new TypeError("grid adapter manifest read is missing");
      }
      const config = gridAdapterConfigSchema.parse({
        adapterId: entry.adapterId,
        protocol: entry.protocol,
        ...entry.configuration,
      });
      return Object.freeze({
        expectedReads: [
          Object.freeze({
            label: "slot0",
            to: config.poolAddress,
            data: slot0Read.selector,
          }),
        ],
        evaluate: (reader) => evaluateGrid(config, reader),
      });
    }
    case YIELD_ADAPTER_ID: {
      const config = yieldAdapterConfigSchema.parse({
        adapterId: entry.adapterId,
        protocol: entry.protocol,
        ...entry.configuration,
      });
      return Object.freeze({
        expectedReads: entry.reads.map((read) =>
          Object.freeze({
            label: read.label,
            to: config.vaultAddress,
            data: read.selector,
          }),
        ),
        evaluate: (reader) => evaluateYield(config, reader),
      });
    }
    case HEALTH_ADAPTER_ID: {
      const [accountDataRead] = entry.reads;
      if (accountDataRead === undefined) {
        throw new TypeError("Aave health adapter manifest read is missing");
      }
      const config = healthAdapterConfigSchema.parse({
        adapterId: entry.adapterId,
        protocol: entry.protocol,
        ...entry.configuration,
      });
      return Object.freeze({
        expectedReads: [
          Object.freeze({
            label: "getUserAccountData",
            to: config.poolAddress,
            data: addressCalldata(
              accountDataRead.selector,
              config.accountAddress,
            ),
          }),
        ],
        evaluate: (reader) => evaluateHealth(config, reader),
      });
    }
    case VENUS_HEALTH_ADAPTER_ID: {
      const [liquidityRead, assetsRead, borrowRead] = entry.reads;
      if (
        liquidityRead === undefined ||
        assetsRead === undefined ||
        borrowRead === undefined
      ) {
        throw new TypeError("Venus health adapter manifest reads are missing");
      }
      const config = venusHealthAdapterConfigSchema.parse({
        adapterId: entry.adapterId,
        protocol: entry.protocol,
        ...entry.configuration,
      });
      return Object.freeze({
        expectedReads: [
          Object.freeze({
            label: "getAccountLiquidity",
            to: config.comptrollerAddress,
            data: addressCalldata(
              liquidityRead.selector,
              config.accountAddress,
            ),
          }),
          Object.freeze({
            label: "getAssetsIn",
            to: config.comptrollerAddress,
            data: addressCalldata(
              assetsRead.selector,
              config.accountAddress,
            ),
          }),
          Object.freeze({
            label: "borrowBalanceStored",
            to: config.borrowMarketAddress,
            data: addressCalldata(
              borrowRead.selector,
              config.accountAddress,
            ),
          }),
        ],
        evaluate: (reader) => evaluateVenusHealth(config, reader),
      });
    }
  }
}

function buildArtifact(input: {
  entry: CategoryAdapterDeploymentEntry;
  adapterResult: AdapterResult<unknown>;
  reads: readonly CategoryReadAttempt[];
  anchor: Readonly<{ number: number; hash: string; timestamp: number }>;
  deploymentSha256: string;
  verifierPolicySha256: string;
  evaluatedAt: number;
}): CategoryExecutionArtifact {
  if (
    input.adapterResult.adapterId !== input.entry.adapterId ||
    input.adapterResult.category !== input.entry.category
  ) {
    throw new TypeError("adapter result identity mismatch");
  }
  assertAdapterResultContract(input.entry, input.adapterResult);
  if (
    input.adapterResult.status !== "unknown" &&
    input.reads.some(
      (read) => read.outcome !== "success" || read.responseSha256 === undefined,
    )
  ) {
    throw new TypeError("measured category result requires successful reads");
  }
  const common = {
    schema: CATEGORY_EXECUTION_ARTIFACT_SCHEMA,
    chainId: 56 as const,
    confirmationDepth: CATEGORY_CONFIRMATION_DEPTH,
    deploymentSha256: input.deploymentSha256,
    verifierPolicyProfile: CATEGORY_VERIFIER_POLICY_PROFILE,
    verifierPolicySha256: input.verifierPolicySha256,
    evaluatedAt: input.evaluatedAt,
    adapter: {
      adapterId: input.entry.adapterId,
      category: input.entry.category,
      evidenceSchema: input.entry.evidenceSchema,
      protocol: input.entry.protocol,
      validationProfile: input.entry.validationProfile,
    },
    anchor: input.anchor,
    reads: input.reads,
  };

  if (input.adapterResult.status === "pass") {
    const evidence = parseEvidenceForEntry(
      input.entry,
      input.adapterResult.evidence,
    );
    assertEvidenceBinding(input.entry, evidence, input.anchor, input.reads);
    return deepFreeze(
      categoryExecutionArtifactSchema.parse({
        ...common,
        result: {
          status: "pass",
          evidenceSha256: canonicalSha256(evidence),
          evidence,
        },
      }),
    );
  }

  return deepFreeze(
    categoryExecutionArtifactSchema.parse({
      ...common,
      result: {
        status: input.adapterResult.status,
        code: input.adapterResult.code,
        message: input.adapterResult.message,
      },
    }),
  );
}

function assertEvidenceBinding(
  entry: CategoryAdapterDeploymentEntry,
  evidence: CategoryEvidenceDocument,
  anchor: Readonly<{ number: number; hash: string; timestamp: number }>,
  reads: readonly CategoryReadAttempt[],
): void {
  if (
    evidence.adapterId !== entry.adapterId ||
    evidence.category !== entry.category ||
    evidence.protocol !== entry.protocol ||
    evidence.schema !== entry.evidenceSchema ||
    evidence.observedAt !== anchor.timestamp ||
    evidence.observedBlock !== anchor.number ||
    evidence.observedBlockHash !== anchor.hash
  ) {
    throw new TypeError("category evidence identity or anchor mismatch");
  }
  const observedReads = reads.map((read) => ({
    label: read.label,
    to: read.to,
    requestSha256: read.requestSha256,
    responseSha256: requireResponseSha256(read),
  }));
  if (canonicalQuoteJson(evidence.reads) !== canonicalQuoteJson(observedReads)) {
    throw new TypeError("category evidence read observations mismatch");
  }
  if (!entry.enabled || entry.configuration === undefined) {
    throw new TypeError("category evidence has no enabled deployment");
  }

  switch (entry.adapterId) {
    case GRID_ADAPTER_ID:
      if (
        evidence.schema !== entry.evidenceSchema ||
        evidence.subject.poolAddress !== entry.configuration.poolAddress ||
        evidence.policy.lowerTick !== entry.configuration.lowerTick ||
        evidence.policy.upperTick !== entry.configuration.upperTick
      ) {
        throw new TypeError("grid evidence deployment mismatch");
      }
      return;
    case YIELD_ADAPTER_ID:
      if (
        evidence.schema !== entry.evidenceSchema ||
        evidence.subject.vaultAddress !== entry.configuration.vaultAddress ||
        evidence.policy.minSharePriceScaled !==
          entry.configuration.minSharePriceScaled
      ) {
        throw new TypeError("yield evidence deployment mismatch");
      }
      return;
    case HEALTH_ADAPTER_ID:
      if (
        evidence.schema !== entry.evidenceSchema ||
        evidence.subject.poolAddress !== entry.configuration.poolAddress ||
        evidence.subject.accountAddress !== entry.configuration.accountAddress ||
        evidence.policy.minHealthFactorScaled !==
          entry.configuration.minHealthFactorScaled
      ) {
        throw new TypeError("Aave health evidence deployment mismatch");
      }
      return;
    case VENUS_HEALTH_ADAPTER_ID:
      if (
        evidence.schema !== entry.evidenceSchema ||
        evidence.subject.comptrollerAddress !==
          entry.configuration.comptrollerAddress ||
        evidence.subject.accountAddress !== entry.configuration.accountAddress ||
        evidence.subject.borrowMarketAddress !==
          entry.configuration.borrowMarketAddress ||
        evidence.policy.minLiquidityUsdScaled !==
          entry.configuration.minLiquidityUsdScaled
      ) {
        throw new TypeError("Venus health evidence deployment mismatch");
      }
      return;
  }
}

function inconclusive(
  category: "grid" | "yield" | "health",
  code: CategoryExecutionInconclusive["code"],
  message: string,
): CategoryExecutionInconclusive {
  return Object.freeze({
    schema: CATEGORY_EXECUTION_RESULT_SCHEMA,
    outcome: "inconclusive",
    category,
    code,
    message,
  });
}

function canonicalSha256(value: unknown): string {
  return computeQuoteSha256(canonicalQuoteJson(value));
}

function requireResponseSha256(read: CategoryReadAttempt): string {
  if (read.responseSha256 === undefined) {
    throw new TypeError("successful category read lacks a response digest");
  }
  return read.responseSha256;
}

function parseSha256(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) {
    throw new TypeError("expected a lowercase SHA-256 digest");
  }
  return value;
}

function readClock(clock: () => number): number {
  const value = clock();
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError("category executor clock must return positive Unix seconds");
  }
  return value;
}

function deepFreeze<T>(value: T, seen = new WeakSet<object>()): T {
  if (value === null || typeof value !== "object") return value;
  const object = value as object;
  if (seen.has(object)) return value;
  seen.add(object);
  for (const key of Reflect.ownKeys(object)) {
    deepFreeze((object as Record<PropertyKey, unknown>)[key], seen);
  }
  return Object.freeze(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactDataKeys(
  value: object,
  expected: readonly string[],
): boolean {
  try {
    const actual = Reflect.ownKeys(value);
    if (
      actual.length !== expected.length ||
      actual.some((key) => typeof key !== "string" || !expected.includes(key))
    ) {
      return false;
    }
    return expected.every((key) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor !== undefined && "value" in descriptor;
    });
  } catch {
    return false;
  }
}
