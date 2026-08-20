import {
  GRID_ADAPTER_ID,
  HEALTH_ADAPTER_ID,
  VENUS_HEALTH_ADAPTER_ID,
  YIELD_ADAPTER_ID,
  failResult,
  gridEvidenceSchema,
  healthEvidenceSchema,
  unknownResult,
  venusHealthEvidenceSchema,
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
  type CategorySnapshot,
  type CategorySnapshotCapability,
  type CategorySnapshotHandle,
  createCategorySnapshotCapability,
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
import {
  parseCategoryExecutionScope,
  categoryScopeRuntime,
  type CategoryExecutionScope,
} from "./scope.js";

export type CategoryAdapterId =
  | typeof GRID_ADAPTER_ID
  | typeof YIELD_ADAPTER_ID
  | typeof HEALTH_ADAPTER_ID
  | typeof VENUS_HEALTH_ADAPTER_ID;

export type ResolvedCategoryAdapterSelection =
  | Readonly<{
      category: "grid";
      adapterId: typeof GRID_ADAPTER_ID;
    }>
  | Readonly<{
      category: "yield";
      adapterId: typeof YIELD_ADAPTER_ID;
    }>
  | Readonly<{
      category: "health";
      adapterId:
        | typeof HEALTH_ADAPTER_ID
        | typeof VENUS_HEALTH_ADAPTER_ID;
    }>;

export type CategoryExecutionBindingContext = Readonly<{
  mandate: unknown;
  candidate: unknown;
}>;

declare const boundCategoryExecutionBrand: unique symbol;

export type BoundCategoryExecutionSuccess =
  TrustedCategoryExecutionSuccess & {
    readonly [boundCategoryExecutionBrand]: true;
  };

export type CategoryExecutionBindingRequest = Readonly<{
  selection: ResolvedCategoryAdapterSelection;
  mandate: unknown;
  candidate: unknown;
}>;

export type CategoryExecutionContextualSelection =
  ResolvedCategoryAdapterSelection &
    Readonly<{
      mandate: unknown;
      candidate: unknown;
    }>;

/**
 * Optional IDs preserve category-only calls for single-adapter deployments.
 * The discriminated shape prevents a caller from pairing an adapter with a
 * different category at compile time; the runtime parser enforces the same
 * relationship for untyped callers and hostile objects.
 */
export type CategoryAdapterExecutionInput =
  | Readonly<{
      category: "grid";
      adapterId?: typeof GRID_ADAPTER_ID;
    }>
  | Readonly<{
      category: "yield";
      adapterId?: typeof YIELD_ADAPTER_ID;
    }>
  | Readonly<{
      category: "health";
      adapterId?:
        | typeof HEALTH_ADAPTER_ID
        | typeof VENUS_HEALTH_ADAPTER_ID;
    }>;

export interface CategoryAdapterExecutorOptions {
  readonly deployment: unknown;
  readonly verifierPolicySha256: string;
  readonly transport: Pick<PinnedHttpsTransport, "request">;
  readonly clock: () => number;
  readonly randomUUID: () => string;
  readonly snapshotCapability?: CategorySnapshotCapability;
}

export interface CategoryAdapterExecutor {
  readonly deployment: CategoryAdapterDeploymentManifest;
  readonly deploymentSha256: string;
  readonly verifierPolicySha256: string;
  readonly evaluate: (
    input: CategoryAdapterExecutionInput,
  ) => Promise<TrustedCategoryExecutionResult>;
  /** Evaluate against a verifier-pinned anchor shared with identity/provenance reads. */
  readonly evaluateAtAnchor: (
    input: CategoryAdapterExecutionInput,
    anchor: CategorySnapshot["anchor"],
  ) => Promise<TrustedCategoryExecutionResult>;
  readonly evaluateAtSnapshot: (
    input: CategoryAdapterExecutionInput,
    snapshot: CategorySnapshotHandle,
  ) => Promise<TrustedCategoryExecutionResult>;
  /**
   * Evaluate a mandate-owned scope against static deployment policy. Dynamic
   * targets and thresholds are supplied by the signed scope, never by the
   * deployment manifest.
   */
  readonly evaluateScope: (
    scope: unknown,
  ) => Promise<TrustedCategoryExecutionResult>;
  readonly evaluateScopeAtAnchor: (
    scope: unknown,
    anchor: CategorySnapshot["anchor"],
  ) => Promise<TrustedCategoryExecutionResult>;
  readonly evaluateScopeAtSnapshot: (
    scope: unknown,
    snapshot: CategorySnapshotHandle,
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

type BoundCategoryExecutionProvenance = Readonly<{
  executor: CategoryAdapterExecutor;
  result: TrustedCategoryExecutionSuccess;
  selection: ResolvedCategoryAdapterSelection;
  mandateCanonical?: string;
  candidateCanonical?: string;
}>;

const boundCategoryExecutionResults = new WeakMap<
  object,
  BoundCategoryExecutionProvenance
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
  const snapshotCapability =
    options.snapshotCapability ??
    createCategorySnapshotCapability({
      transport,
      randomUUID,
    });
  if (
    snapshotCapability === null ||
    typeof snapshotCapability !== "object" ||
    typeof snapshotCapability.withSnapshot !== "function" ||
    typeof snapshotCapability.withActiveSnapshot !== "function" ||
    typeof snapshotCapability.anchorForOpaque !== "function" ||
    typeof snapshotCapability.finalizeOpaqueSnapshot !== "function" ||
    typeof snapshotCapability.createReader !== "function"
  ) {
    throw new TypeError("category executor snapshot capability is invalid");
  }

  let executor: CategoryAdapterExecutor;

  const evaluateResolved = async (
    entry: CategoryAdapterDeploymentEntry,
    runtime: ReturnType<typeof runtimeContractForScope>,
    suppliedAnchor?: CategorySnapshot["anchor"],
    suppliedSnapshot?: CategorySnapshotHandle,
  ): Promise<TrustedCategoryExecutionResult> => {
      const category = runtime.scope.category;
      try {
        const evaluateSnapshot = async (
          snapshot: CategorySnapshot | CategorySnapshotHandle,
        ): Promise<TrustedCategoryExecutionResult> => {
          const reader = await snapshotCapability.createReader(
            snapshot,
            runtime.expectedReads,
          );
          const anchor =
            "anchor" in snapshot
              ? snapshot.anchor
              : snapshotCapability.anchorForOpaque(snapshot);
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

          let artifact: CategoryExecutionArtifact;
          try {
            artifact = buildArtifact({
              entry,
              scope: runtime.scope,
              adapterResult,
              reads,
              anchor,
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
        };
        if (suppliedSnapshot !== undefined) {
          return await snapshotCapability.withActiveSnapshot(
            suppliedSnapshot,
            evaluateSnapshot,
          );
        }
        return await snapshotCapability.withSnapshot(
          evaluateSnapshot as (snapshot: CategorySnapshot) => Promise<TrustedCategoryExecutionResult>,
          suppliedAnchor,
        );
      } catch (cause) {
        if (cause instanceof CategoryBlockPinError) {
          return inconclusive(
            category,
            "CATEGORY_BLOCK_PIN_UNAVAILABLE",
            "a canonical confirmed BSC block could not be pinned",
          );
        }
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
            "the category transport rejected the shared snapshot contract",
          );
        }
        throw cause;
      }
    };

  const evaluate = async (
    input: CategoryAdapterExecutionInput,
    suppliedAnchor?: CategorySnapshot["anchor"],
    suppliedSnapshot?: CategorySnapshotHandle,
  ): Promise<TrustedCategoryExecutionResult> => {
      const selection = parseExecutionInput(input);
      const category = selection.category;
      const candidates = deployment.adapters.filter(
        (candidate) => candidate.enabled && candidate.category === category,
      );
      let entry: CategoryAdapterDeploymentEntry | undefined;
      if (selection.adapterId !== undefined) {
        entry = candidates.find(
          (candidate) => candidate.adapterId === selection.adapterId,
        );
        if (entry === undefined) {
          return inconclusive(
            category,
            "CATEGORY_ADAPTER_NOT_CONFIGURED",
            "the requested adapter is not enabled for this category in the pinned deployment",
          );
        }
      } else if (candidates.length === 1) {
        entry = candidates[0];
      } else if (candidates.length > 1) {
        return inconclusive(
          category,
          "CATEGORY_ADAPTER_SELECTION_REQUIRED",
          "multiple adapters are enabled for this category; adapterId is required",
        );
      }
      if (entry === undefined || entry.configuration === undefined) {
        return inconclusive(
          category,
          "CATEGORY_ADAPTER_NOT_CONFIGURED",
          "no adapter is enabled for this category in the pinned deployment",
        );
      }
      return evaluateResolved(
        entry,
        runtimeContract(entry),
        suppliedAnchor,
        suppliedSnapshot,
      );
    };

  const evaluateScope = async (
    scopeInput: unknown,
    suppliedAnchor?: CategorySnapshot["anchor"],
    suppliedSnapshot?: CategorySnapshotHandle,
  ): Promise<TrustedCategoryExecutionResult> => {
    const runtime = runtimeContractForScope(scopeInput);
    const entry = deployment.adapters.find(
      (candidate) => candidate.adapterId === runtime.scope.adapterId,
    );
    if (entry === undefined || !entry.enabled) {
      return inconclusive(
        runtime.scope.category,
        "CATEGORY_ADAPTER_NOT_CONFIGURED",
        "the requested adapter is not enabled in the pinned static deployment",
      );
    }
    if (
      entry.category !== runtime.scope.category ||
      entry.evidenceSchema !== runtime.scope.evidenceSchema ||
      entry.protocol !== runtime.scope.protocol
    ) {
      return inconclusive(
        runtime.scope.category,
        "CATEGORY_ADAPTER_EXECUTION_INVALID",
        "the mandate scope identity does not match the static adapter policy",
      );
    }
    return evaluateResolved(entry, runtime, suppliedAnchor, suppliedSnapshot);
  };

  executor = Object.freeze({
    deployment,
    deploymentSha256,
    verifierPolicySha256,
    evaluate: (input: CategoryAdapterExecutionInput) => evaluate(input),
    evaluateAtAnchor: (
      input: CategoryAdapterExecutionInput,
      anchor: CategorySnapshot["anchor"],
    ) => evaluate(input, anchor),
    evaluateAtSnapshot: (
      input: CategoryAdapterExecutionInput,
      snapshot: CategorySnapshotHandle,
    ) => evaluate(input, undefined, snapshot),
    evaluateScope: (scope: unknown) => evaluateScope(scope),
    evaluateScopeAtAnchor: (
      scope: unknown,
      anchor: CategorySnapshot["anchor"],
    ) => evaluateScope(scope, anchor),
    evaluateScopeAtSnapshot: (
      scope: unknown,
      snapshot: CategorySnapshotHandle,
    ) => evaluateScope(scope, undefined, snapshot),
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

/**
 * Brands the exact executor-owned pass result for one resolved adapter and,
 * when supplied, one canonical mandate/candidate context. The context stays
 * in the private capability map; no caller-provided digest becomes trusted.
 */
export function bindTrustedCategoryExecutionSuccess(
  value: unknown,
  executor: CategoryAdapterExecutor,
  expected: ResolvedCategoryAdapterSelection,
  context?: CategoryExecutionBindingContext,
): BoundCategoryExecutionSuccess;
export function bindTrustedCategoryExecutionSuccess(
  value: unknown,
  executor: CategoryAdapterExecutor,
  request: CategoryExecutionBindingRequest,
): BoundCategoryExecutionSuccess;
export function bindTrustedCategoryExecutionSuccess(
  value: unknown,
  executor: CategoryAdapterExecutor,
  expectedOrRequest:
    | ResolvedCategoryAdapterSelection
    | CategoryExecutionBindingRequest
    | CategoryExecutionContextualSelection,
  context?: CategoryExecutionBindingContext,
): BoundCategoryExecutionSuccess;
export function bindTrustedCategoryExecutionSuccess(
  value: unknown,
  executor: CategoryAdapterExecutor,
  request: CategoryExecutionContextualSelection,
): BoundCategoryExecutionSuccess;
export function bindTrustedCategoryExecutionSuccess(
  value: unknown,
  executor: CategoryAdapterExecutor,
  expectedOrRequest:
    | ResolvedCategoryAdapterSelection
    | CategoryExecutionBindingRequest
    | CategoryExecutionContextualSelection,
  context?: CategoryExecutionBindingContext,
): BoundCategoryExecutionSuccess {
  const parsed = parseBindingRequest(expectedOrRequest, context);
  return bindTrustedCategoryExecutionSuccessParsed(value, executor, parsed);
}

function bindTrustedCategoryExecutionSuccessParsed(
  value: unknown,
  executor: CategoryAdapterExecutor,
  parsed: ParsedBindingRequest,
): BoundCategoryExecutionSuccess {
  assertTrustedCategoryExecutionSuccess(value, executor);

  const result = value as TrustedCategoryExecutionSuccess;
  const artifactSelection = {
    category: result.artifact.adapter.category,
    adapterId: result.artifact.adapter.adapterId,
  } as ResolvedCategoryAdapterSelection;
  if (
    parsed.selection.category !== artifactSelection.category ||
    parsed.selection.adapterId !== artifactSelection.adapterId
  ) {
    throw new Error(
      "trusted category execution result does not match the resolved adapter selection",
    );
  }

  const existing = boundCategoryExecutionResults.get(result);
  if (existing !== undefined) {
    if (
      existing.executor !== executor ||
      !sameSelection(existing.selection, parsed.selection) ||
      existing.mandateCanonical !== parsed.mandateCanonical ||
      existing.candidateCanonical !== parsed.candidateCanonical
    ) {
      throw new Error("trusted category execution result is already bound");
    }
    return result as BoundCategoryExecutionSuccess;
  }

  boundCategoryExecutionResults.set(
    result,
    Object.freeze({
      executor,
      result,
      selection: parsed.selection,
      ...(parsed.mandateCanonical === undefined
        ? {}
        : { mandateCanonical: parsed.mandateCanonical }),
      ...(parsed.candidateCanonical === undefined
        ? {}
        : { candidateCanonical: parsed.candidateCanonical }),
    }),
  );
  return result as BoundCategoryExecutionSuccess;
}

export function assertBoundCategoryExecutionSuccess(
  value: unknown,
  executor: CategoryAdapterExecutor,
  expected: ResolvedCategoryAdapterSelection,
  context?: CategoryExecutionBindingContext,
): asserts value is BoundCategoryExecutionSuccess;
export function assertBoundCategoryExecutionSuccess(
  value: unknown,
  executor: CategoryAdapterExecutor,
  request: CategoryExecutionBindingRequest,
): asserts value is BoundCategoryExecutionSuccess;
export function assertBoundCategoryExecutionSuccess(
  value: unknown,
  executor: CategoryAdapterExecutor,
  expectedOrRequest:
    | ResolvedCategoryAdapterSelection
    | CategoryExecutionBindingRequest
    | CategoryExecutionContextualSelection,
  context?: CategoryExecutionBindingContext,
): asserts value is BoundCategoryExecutionSuccess;
export function assertBoundCategoryExecutionSuccess(
  value: unknown,
  executor: CategoryAdapterExecutor,
  request: CategoryExecutionContextualSelection,
): asserts value is BoundCategoryExecutionSuccess;
export function assertBoundCategoryExecutionSuccess(
  value: unknown,
  executor: CategoryAdapterExecutor,
  expectedOrRequest:
    | ResolvedCategoryAdapterSelection
    | CategoryExecutionBindingRequest
    | CategoryExecutionContextualSelection,
  context?: CategoryExecutionBindingContext,
): asserts value is BoundCategoryExecutionSuccess {
  const parsed = parseBindingRequest(expectedOrRequest, context);
  assertBoundCategoryExecutionSuccessParsed(value, executor, parsed);
}

function assertBoundCategoryExecutionSuccessParsed(
  value: unknown,
  executor: CategoryAdapterExecutor,
  parsed: ParsedBindingRequest,
): asserts value is BoundCategoryExecutionSuccess {
  assertTrustedCategoryExecutionSuccess(value, executor);
  const provenance = boundCategoryExecutionResults.get(value);
  if (provenance === undefined) {
    throw new Error("category execution result lacks a bound in-process capability");
  }
  if (
    provenance.executor !== executor ||
    !sameSelection(provenance.selection, parsed.selection) ||
    provenance.mandateCanonical !== parsed.mandateCanonical ||
    provenance.candidateCanonical !== parsed.candidateCanonical
  ) {
    throw new Error("trusted category execution binding does not match its context");
  }
}

/**
 * Executor-scoped capability for services that must pass a bound result across
 * an internal signer boundary without exposing the executor itself. The
 * capability closes over the exact executor and delegates to the private
 * WeakMap-backed binding checks above.
 */
export interface CategoryExecutionBindingCapability {
  /**
   * Snapshots the complete request before invoking the adapter and binds a
   * trusted pass result to that same snapshot. Non-pass results are returned
   * unchanged and are intentionally not added to the binding map.
   */
  readonly evaluateBound: (
    request: CategoryExecutionBindingRequest,
  ) => Promise<TrustedCategoryExecutionResult>;
  readonly bind: (
    value: unknown,
    expectedOrRequest:
      | ResolvedCategoryAdapterSelection
      | CategoryExecutionBindingRequest
      | CategoryExecutionContextualSelection,
    context?: CategoryExecutionBindingContext,
  ) => BoundCategoryExecutionSuccess;
  readonly assertBound: (
    value: unknown,
    expectedOrRequest:
      | ResolvedCategoryAdapterSelection
      | CategoryExecutionBindingRequest
      | CategoryExecutionContextualSelection,
    context?: CategoryExecutionBindingContext,
  ) => asserts value is BoundCategoryExecutionSuccess;
}

export function createCategoryExecutionBindingCapability(
  executor: CategoryAdapterExecutor,
): CategoryExecutionBindingCapability {
  if (executor === null || typeof executor !== "object") {
    throw new TypeError("category binding capability requires an executor");
  }
  const capability: CategoryExecutionBindingCapability = {
    evaluateBound: async (
      request: CategoryExecutionBindingRequest,
    ): Promise<TrustedCategoryExecutionResult> => {
      // Parse and canonicalize before the first adapter/RPC await. The
      // resulting selection and context digests are immutable snapshots, so a
      // caller cannot change what is bound while execution is in flight.
      const parsed = parseCategoryExecutionBindingRequest(request);
      const result = await executor.evaluate(parsed.selection);
      if (result.outcome !== "executed" || result.artifact.result.status !== "pass") {
        return result;
      }
      bindTrustedCategoryExecutionSuccessParsed(result, executor, parsed);
      return result;
    },
    bind: (
      value,
      expectedOrRequest,
      context,
    ) =>
      bindTrustedCategoryExecutionSuccess(
        value,
        executor,
        expectedOrRequest,
        context,
      ),
    assertBound: (
      value,
      expectedOrRequest,
      context,
    ): asserts value is BoundCategoryExecutionSuccess => {
      assertBoundCategoryExecutionSuccess(
        value,
        executor,
        expectedOrRequest,
        context,
      );
    },
  };
  return Object.freeze(capability);
}

export const createCategoryArtifactBindingCapability =
  createCategoryExecutionBindingCapability;

type ParsedBindingRequest = Readonly<{
  selection: ResolvedCategoryAdapterSelection;
  mandateCanonical?: string;
  candidateCanonical?: string;
}>;

function parseBindingRequest(
  expectedOrRequest:
    | ResolvedCategoryAdapterSelection
    | CategoryExecutionBindingRequest
    | CategoryExecutionContextualSelection,
  context: CategoryExecutionBindingContext | undefined,
): ParsedBindingRequest {
  if (
    isRecord(expectedOrRequest) &&
    Object.hasOwn(expectedOrRequest, "selection")
  ) {
    if (context !== undefined) {
      throw new TypeError("category binding request cannot include a second context");
    }
    return parseCategoryExecutionBindingRequest(expectedOrRequest);
  }

  if (
    isRecord(expectedOrRequest) &&
    (Object.hasOwn(expectedOrRequest, "mandate") ||
      Object.hasOwn(expectedOrRequest, "candidate"))
  ) {
    if (context !== undefined) {
      throw new TypeError("category binding request cannot include a second context");
    }
    assertExactDataKeys(expectedOrRequest, [
      "adapterId",
      "candidate",
      "category",
      "mandate",
    ]);
    const request = expectedOrRequest as object;
    const selection = parseResolvedSelection({
      category: readDataProperty(request, "category"),
      adapterId: readDataProperty(request, "adapterId"),
    });
    const parsed = Object.freeze({
      selection,
      mandateCanonical: canonicalBindingValue(
        readDataProperty(request, "mandate"),
        "mandate",
      ),
      candidateCanonical: canonicalBindingValue(
        readDataProperty(request, "candidate"),
        "candidate",
      ),
    });
    rejectProxy(request);
    return parsed;
  }

  const selection = parseResolvedSelection(expectedOrRequest);
  if (context === undefined) return Object.freeze({ selection });
  assertExactDataKeys(context, ["candidate", "mandate"]);
  const parsed = Object.freeze({
    selection,
    mandateCanonical: canonicalBindingValue(
      readDataProperty(context, "mandate"),
      "mandate",
    ),
    candidateCanonical: canonicalBindingValue(
      readDataProperty(context, "candidate"),
      "candidate",
    ),
  });
  rejectProxy(context);
  return parsed;
}

function parseCategoryExecutionBindingRequest(
  value: unknown,
): ParsedBindingRequest {
  if (!isRecord(value)) {
    throw new TypeError("category binding request must be an object");
  }
  assertExactDataKeys(value, ["candidate", "mandate", "selection"]);
  const parsed = Object.freeze({
    selection: parseResolvedSelection(readDataProperty(value, "selection")),
    mandateCanonical: canonicalBindingValue(
      readDataProperty(value, "mandate"),
      "mandate",
    ),
    candidateCanonical: canonicalBindingValue(
      readDataProperty(value, "candidate"),
      "candidate",
    ),
  });
  rejectProxy(value);
  return parsed;
}

function parseResolvedSelection(
  value: unknown,
): ResolvedCategoryAdapterSelection {
  if (value === null || typeof value !== "object") {
    throw new TypeError("category binding requires an explicit adapter selection");
  }
  assertExactDataKeys(value, ["adapterId", "category"]);
  const category = readDataProperty(value, "category");
  const adapterId = readDataProperty(value, "adapterId");
  if (
    typeof category !== "string" ||
    typeof adapterId !== "string" ||
    !REGISTERED_CATEGORY_ADAPTER_IDS.includes(adapterId as CategoryAdapterId) ||
    CATEGORY_BY_ADAPTER[adapterId as CategoryAdapterId] !== category
  ) {
    throw new TypeError("category binding requires a registered adapter/category pair");
  }
  rejectProxy(value);
  return Object.freeze({
    category: category as ResolvedCategoryAdapterSelection["category"],
    adapterId: adapterId as ResolvedCategoryAdapterSelection["adapterId"],
  }) as ResolvedCategoryAdapterSelection;
}

function sameSelection(
  left: ResolvedCategoryAdapterSelection,
  right: ResolvedCategoryAdapterSelection,
): boolean {
  return left.category === right.category && left.adapterId === right.adapterId;
}

function assertExactDataKeys(value: object, expected: readonly string[]): void {
  let keys: readonly PropertyKey[];
  let prototype: object | null;
  try {
    prototype = Object.getPrototypeOf(value);
    keys = Reflect.ownKeys(value);
  } catch (cause) {
    throw new TypeError("category binding context is unreadable", { cause });
  }
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("category binding context must be a plain object");
  }
  if (
    keys.length !== expected.length ||
    keys.some((key) => typeof key !== "string" || !expected.includes(key))
  ) {
    throw new TypeError("category binding context contains unsupported fields");
  }
  for (const key of expected) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    ) {
      throw new TypeError("category binding context requires data properties");
    }
  }
}

function readDataProperty(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor)) {
    throw new TypeError("category binding context requires data properties");
  }
  return descriptor.value;
}

function canonicalBindingValue(value: unknown, label: string): string {
  return canonicalQuoteJson(snapshotBindingValue(value, label));
}

type BindingJsonValue =
  | null
  | boolean
  | string
  | number
  | BindingJsonValue[]
  | { readonly [key: string]: BindingJsonValue };

function snapshotBindingValue(
  value: unknown,
  label: string,
  seen = new WeakSet<object>(),
): BindingJsonValue {
  if (value === null) return null;
  if (typeof value === "boolean" || typeof value === "string") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError(`${label} contains a non-finite number`);
    }
    return value;
  }
  if (typeof value !== "object") {
    throw new TypeError(`${label} must be JSON-serializable data`);
  }
  if (seen.has(value)) throw new TypeError(`${label} contains a cycle or alias`);
  seen.add(value);

  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      throw new TypeError(`${label} array has an unsupported prototype`);
    }
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
    if (
      lengthDescriptor === undefined ||
      !("value" in lengthDescriptor) ||
      !Number.isSafeInteger(lengthDescriptor.value) ||
      lengthDescriptor.value < 0
    ) {
      throw new TypeError(`${label} array length is invalid`);
    }
    const length = lengthDescriptor.value as number;
    const keys = Reflect.ownKeys(value);
    if (
      keys.length !== length + 1 ||
      keys.some(
        (key) =>
          key !== "length" &&
          (typeof key !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(key) || Number(key) >= length),
      )
    ) {
      throw new TypeError(`${label} array contains unsupported fields`);
    }
    const result: BindingJsonValue[] = [];
    for (let index = 0; index < length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        descriptor.enumerable !== true
      ) {
        throw new TypeError(`${label} array contains a non-data element`);
      }
      result.push(snapshotBindingValue(descriptor.value, `${label}[${index}]`, seen));
    }
    rejectProxy(value);
    return result;
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${label} must be a plain object`);
  }
  const result = Object.create(null) as Record<string, BindingJsonValue>;
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") {
      throw new TypeError(`${label} contains a symbol property`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    ) {
      throw new TypeError(`${label}.${key} must be a data property`);
    }
    result[key] = snapshotBindingValue(descriptor.value, `${label}.${key}`, seen);
  }
  rejectProxy(value);
  return result;
}

function rejectProxy(value: object): void {
  try {
    const clone = globalThis.structuredClone;
    if (typeof clone === "function") clone(value);
  } catch (cause) {
    throw new TypeError("category binding inputs must not be proxies", { cause });
  }
}

type ParsedCategoryAdapterExecutionInput = Readonly<{
  category: CategoryAdapterExecutionInput["category"];
  adapterId?: CategoryAdapterId;
}>;

const REGISTERED_CATEGORY_ADAPTER_IDS = Object.freeze([
  GRID_ADAPTER_ID,
  YIELD_ADAPTER_ID,
  HEALTH_ADAPTER_ID,
  VENUS_HEALTH_ADAPTER_ID,
] as const);

const CATEGORY_BY_ADAPTER = Object.freeze({
  [GRID_ADAPTER_ID]: "grid",
  [YIELD_ADAPTER_ID]: "yield",
  [HEALTH_ADAPTER_ID]: "health",
  [VENUS_HEALTH_ADAPTER_ID]: "health",
} as const satisfies Readonly<
  Record<CategoryAdapterId, "grid" | "yield" | "health">
>);

function parseExecutionInput(
  value: unknown,
): ParsedCategoryAdapterExecutionInput {
  let category: unknown;
  let adapterId: unknown;
  let hasAdapterId = false;
  try {
    if (!isRecord(value)) {
      throw new TypeError();
    }
    const keys = Reflect.ownKeys(value);
    if (
      (keys.length !== 1 && keys.length !== 2) ||
      !keys.includes("category") ||
      keys.some(
        (key) =>
          typeof key !== "string" ||
          (key !== "category" && key !== "adapterId"),
      )
    ) {
      throw new TypeError();
    }
    for (const key of keys) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (
        descriptor === undefined ||
        !("value" in descriptor) ||
        descriptor.enumerable !== true
      ) {
        throw new TypeError();
      }
      if (key === "category") {
        category = descriptor.value;
      } else {
        hasAdapterId = true;
        adapterId = descriptor.value;
      }
    }
  } catch {
    throw new TypeError(
      "category execution input must contain a supported category and optional adapterId",
    );
  }
  if (
    typeof category !== "string" ||
    !["grid", "yield", "health"].includes(category)
  ) {
    throw new TypeError(
      "category execution input must contain a supported category and optional adapterId",
    );
  }
  if (
    hasAdapterId &&
    (typeof adapterId !== "string" ||
      !REGISTERED_CATEGORY_ADAPTER_IDS.includes(
        adapterId as CategoryAdapterId,
      ))
  ) {
    throw new TypeError(
      "category execution input must contain a registered adapterId",
    );
  }
  if (
    hasAdapterId &&
    CATEGORY_BY_ADAPTER[adapterId as CategoryAdapterId] !== category
  ) {
    throw new TypeError(
      "category execution input adapterId does not belong to category",
    );
  }
  return Object.freeze({
    category: category as CategoryAdapterExecutionInput["category"],
    ...(!hasAdapterId
      ? {}
      : { adapterId: adapterId as CategoryAdapterId }),
  });
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
  scope: CategoryExecutionScope;
  expectedReads: readonly ExpectedCategoryRead[];
  evaluate: (
    reader: TransportPinnedCategoryReader,
  ) => Promise<AdapterResult<unknown>>;
}> {
  if (!entry.enabled || entry.configuration === undefined) {
    throw new TypeError("category adapter is not enabled");
  }
  const scope = legacyDeploymentScope(entry);
  const runtime = categoryScopeRuntime(scope);
  return Object.freeze({
    scope,
    expectedReads: runtime.expectedReads,
    evaluate: runtime.evaluate,
  });
}

/**
 * Build an execution contract from mandate-owned dynamic values while
 * checking its immutable adapter identity against the static deployment.
 */
function runtimeContractForScope(value: unknown): Readonly<{
  scope: CategoryExecutionScope;
  expectedReads: readonly ExpectedCategoryRead[];
  evaluate: (
    reader: TransportPinnedCategoryReader,
  ) => Promise<AdapterResult<unknown>>;
}> {
  const scope = categoryScopeRuntime(value);
  // `categoryScopeRuntime` validates the discriminated scope and creates the
  // exact adapter invocation. The caller still supplies the parsed scope to
  // retain its mandate-owned subject/policy in the signed artifact.
  return Object.freeze({
    scope: parseCategoryExecutionScope(value),
    expectedReads: scope.expectedReads,
    evaluate: scope.evaluate,
  });
}

function legacyDeploymentScope(
  entry: CategoryAdapterDeploymentEntry,
): CategoryExecutionScope {
  if (!entry.enabled || entry.configuration === undefined) {
    throw new TypeError("category adapter is not enabled");
  }
  switch (entry.adapterId) {
    case GRID_ADAPTER_ID:
      return {
        adapterId: entry.adapterId,
        category: entry.category,
        evidenceSchema: entry.evidenceSchema,
        protocol: entry.protocol,
        subject: { poolAddress: entry.configuration.poolAddress },
        conditionPolicy: {
          unit: "uniswap-v3-tick",
          lowerTick: entry.configuration.lowerTick,
          upperTick: entry.configuration.upperTick,
        },
      };
    case YIELD_ADAPTER_ID:
      return {
        adapterId: entry.adapterId,
        category: entry.category,
        evidenceSchema: entry.evidenceSchema,
        protocol: entry.protocol,
        subject: { vaultAddress: entry.configuration.vaultAddress },
        conditionPolicy: {
          unit: "1e18-share-price",
          minSharePriceScaled: entry.configuration.minSharePriceScaled,
        },
      };
    case HEALTH_ADAPTER_ID:
      return {
        adapterId: entry.adapterId,
        category: entry.category,
        evidenceSchema: entry.evidenceSchema,
        protocol: entry.protocol,
        subject: {
          poolAddress: entry.configuration.poolAddress,
          accountAddress: entry.configuration.accountAddress,
        },
        conditionPolicy: {
          unit: "1e18-health-factor",
          minHealthFactorScaled: entry.configuration.minHealthFactorScaled,
        },
      };
    case VENUS_HEALTH_ADAPTER_ID:
      return {
        adapterId: entry.adapterId,
        category: entry.category,
        evidenceSchema: entry.evidenceSchema,
        protocol: entry.protocol,
        subject: {
          comptrollerAddress: entry.configuration.comptrollerAddress,
          accountAddress: entry.configuration.accountAddress,
          borrowMarketAddress: entry.configuration.borrowMarketAddress,
        },
        conditionPolicy: {
          unit: "1e18-usd",
          minLiquidityUsdScaled: entry.configuration.minLiquidityUsdScaled,
        },
      };
  }
}

function buildArtifact(input: {
  entry: CategoryAdapterDeploymentEntry;
  scope: CategoryExecutionScope;
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
    assertEvidenceBinding(
      input.entry,
      input.scope,
      evidence,
      input.anchor,
      input.reads,
    );
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
  scope: CategoryExecutionScope,
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
  if (!entry.enabled) {
    throw new TypeError("category evidence has no enabled deployment");
  }
  categoryScopeRuntime(scope).assertEvidence(evidence);
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
