import { canonicalJson, canonicalSha256 } from "./canonical.js";
import {
  MARKETPLACE_CATEGORY_ADAPTER_IDS,
  type MarketplaceCategoryAdapterId,
} from "./category-policy.js";
import { deepFreeze } from "./immutable.js";
import {
  addressSchema,
  canonicalIdentifierSchema,
  sha256Schema,
  unixSecondsSchema,
} from "./primitives.js";
import {
  MAX_MARKETPLACE_TRUST_BUNDLE_TTL_SECONDS,
  assertMarketplaceTrustResolvedTuple,
  marketplaceTrustBundleDurableStateSchema,
  marketplaceTrustBundleRollbackFloorSchema,
  resolveMarketplaceTrustBundleAttestationTuple,
  validateMarketplaceTrustBundleRoot,
  verifyMarketplaceTrustBundle,
  type MarketplaceTrustBundleDurableState,
  type MarketplaceTrustBundleRollbackFloor,
  type MarketplaceTrustBundleRoot,
  type MarketplaceTrustBundleWire,
  type MarketplaceTrustResolvedTuple,
  type ValidatedMarketplaceTrustBundleRoot,
  type VerifiedMarketplaceTrustBundle,
} from "./trust-bundle.js";

const stateDigestSchema = sha256Schema;

export type MarketplaceCategoryTrustStateSnapshot = Readonly<{
  readonly state: MarketplaceTrustBundleDurableState | undefined;
  readonly stateSha256: string | undefined;
}>;

export type MarketplaceCategoryTrustCasInput = Readonly<{
  readonly expectedStateSha256: string | undefined;
  readonly nextState: MarketplaceTrustBundleDurableState;
  readonly nextStateSha256: string;
  readonly bundleSha256: string;
  readonly generation: number;
  readonly revocationEpoch: number;
}>;

export type MarketplaceCategoryTrustCasReceipt = Readonly<{
  readonly status: "committed" | "already_committed" | "conflict";
  readonly expectedStateSha256: string | undefined;
  readonly committedStateSha256: string | undefined;
  readonly bundleSha256: string | undefined;
  readonly generation: number | undefined;
  readonly revocationEpoch: number | undefined;
}>;

export interface MarketplaceCategoryTrustStateStore {
  readonly load: () => Promise<MarketplaceCategoryTrustStateSnapshot>;
  readonly compareAndSwap: (
    input: MarketplaceCategoryTrustCasInput,
  ) => Promise<MarketplaceCategoryTrustCasReceipt>;
  /** The backend must serialize this callback with compareAndSwap operations. */
  readonly withRevision: <Result>(
    expectedStateSha256: string,
    operation: () => Promise<Result>,
  ) => Promise<Result>;
}

const trustedStores = new WeakSet<object>();

/**
 * Captures the only state-store capability accepted by the trust controller.
 * The backend remains responsible for real atomic durability; this factory
 * enforces the wire, receipt, and callback boundary at the library edge.
 */
export function createMarketplaceCategoryTrustStateStore(options: {
  readonly load: () => Promise<unknown>;
  readonly compareAndSwap: (input: unknown) => Promise<unknown>;
  readonly withRevision: <Result>(
    expectedStateSha256: string,
    operation: () => Promise<Result>,
  ) => Promise<Result>;
}): MarketplaceCategoryTrustStateStore {
  assertExactObject(
    options,
    ["compareAndSwap", "load", "withRevision"],
    "trust state store",
  );
  const load = options.load;
  const compareAndSwap = options.compareAndSwap;
  const withRevision = options.withRevision;
  if (
    typeof load !== "function" ||
    typeof compareAndSwap !== "function" ||
    typeof withRevision !== "function"
  ) {
    throw new TypeError("trust state store callbacks must be functions");
  }
  const store: MarketplaceCategoryTrustStateStore = Object.freeze({
    async load(): Promise<MarketplaceCategoryTrustStateSnapshot> {
      return normalizeSnapshot(await load());
    },
    async compareAndSwap(
      input: MarketplaceCategoryTrustCasInput,
    ): Promise<MarketplaceCategoryTrustCasReceipt> {
      const normalized = normalizeCasInput(input);
      return normalizeCasReceipt(await compareAndSwap(normalized), normalized);
    },
    async withRevision<Result>(
      expectedStateSha256: string,
      operation: () => Promise<Result>,
    ): Promise<Result> {
      const expected = stateDigestSchema.parse(expectedStateSha256);
      if (typeof operation !== "function") {
        throw new TypeError("trust revision operation must be a function");
      }
      return withRevision(expected, operation);
    },
  });
  trustedStores.add(store);
  return store;
}

export type MarketplaceCategoryIssuancePermit = Readonly<{
  readonly bundleSha256: string;
  readonly generation: number;
  readonly revocationEpoch: number;
  readonly stateSha256: string;
  readonly keyId: string;
  readonly releaseId: string;
  readonly adapterId: MarketplaceCategoryAdapterId;
  readonly serviceMode: "observe_only" | "transactional";
  readonly issuedAt: number;
  readonly quoteVerifyingContract: string;
  readonly tuple: MarketplaceTrustResolvedTuple;
}>;

type ControllerContext = Readonly<{
  readonly root: ValidatedMarketplaceTrustBundleRoot;
  readonly quoteVerifyingContract: string;
  readonly rollbackFloor: MarketplaceTrustBundleRollbackFloor;
  readonly stateStore: MarketplaceCategoryTrustStateStore;
  readonly clock: () => number;
}>;

const permits = new WeakMap<object, Readonly<{ controller: MarketplaceCategoryTrustController }>>();
const consumedPermits = new WeakSet<object>();
const controllerRoots = new WeakMap<object, MarketplaceCategoryTrustRootIdentity>();
const commitments = new WeakMap<
  object,
  Readonly<{
    controller: MarketplaceCategoryTrustController;
    verified: VerifiedMarketplaceTrustBundle;
    quoteVerifyingContract: string;
  }>
>();

export interface MarketplaceCategoryTrustController {
  readonly prepare: (input: {
    readonly bundleWire: MarketplaceTrustBundleWire;
  }) => Promise<MarketplaceCategoryTrustCommitment>;
  readonly issuePermit: (input: {
    readonly bundleWire: MarketplaceTrustBundleWire;
    readonly keyId: string;
    readonly releaseId: string;
    readonly adapterId: string;
    readonly serviceMode: "observe_only" | "transactional";
    readonly issuedAt?: number;
  }) => Promise<MarketplaceCategoryIssuancePermit>;
  readonly assertPermit: (
    value: unknown,
  ) => asserts value is MarketplaceCategoryIssuancePermit;
  readonly withPermit: <Result>(
    value: MarketplaceCategoryIssuancePermit,
    operation: (tuple: MarketplaceTrustResolvedTuple) => Promise<Result>,
  ) => Promise<Result>;
  readonly readiness: (input: {
    readonly bundleWire: MarketplaceTrustBundleWire;
  }) => Promise<MarketplaceCategoryTrustReadiness>;
}

export type MarketplaceCategoryTrustRootIdentity = Readonly<{
  readonly keyId: string;
  readonly publicKeyFingerprintSha256: string;
}>;

export type MarketplaceCategoryTrustCommitment = Readonly<{
  readonly bundleSha256: string;
  readonly generation: number;
  readonly revocationEpoch: number;
  readonly stateSha256: string;
}>;

export type ResolvedMarketplaceCategoryTrustCommitment = Readonly<{
  readonly verified: VerifiedMarketplaceTrustBundle;
  readonly quoteVerifyingContract: string;
}>;

export type MarketplaceCategoryTrustReadiness = Readonly<{
  readonly ready: boolean;
  readonly reason:
    | "ready"
    | "bundle_invalid"
    | "state_unavailable"
    | "state_mismatch"
    | "commit_conflict"
    | "bundle_expired";
  readonly commitment?: MarketplaceCategoryTrustCommitment;
}>;

export function createMarketplaceCategoryTrustController(options: {
  readonly root: MarketplaceTrustBundleRoot;
  readonly quoteVerifyingContract: string;
  readonly rollbackFloor: MarketplaceTrustBundleRollbackFloor;
  readonly stateStore: MarketplaceCategoryTrustStateStore;
  readonly clock: () => number;
}): MarketplaceCategoryTrustController {
  assertExactObject(
    options,
    ["clock", "quoteVerifyingContract", "rollbackFloor", "root", "stateStore"],
    "trust controller options",
  );
  if (!trustedStores.has(options.stateStore as object)) {
    throw new TypeError("trust controller requires a factory-created state store");
  }
  if (typeof options.clock !== "function") {
    throw new TypeError("trust controller clock must be a function");
  }
  const context: ControllerContext = Object.freeze({
    root: validateMarketplaceTrustBundleRoot(options.root),
    quoteVerifyingContract: addressSchema.parse(options.quoteVerifyingContract),
    rollbackFloor: deepFreeze(
      marketplaceTrustBundleRollbackFloorSchema.parse(options.rollbackFloor),
    ),
    stateStore: options.stateStore,
    clock: options.clock,
  });

  let controller: MarketplaceCategoryTrustController;
  controller = Object.freeze({
    async prepare(
      input: Parameters<MarketplaceCategoryTrustController["prepare"]>[0],
    ): Promise<MarketplaceCategoryTrustCommitment> {
      assertExactObject(input, ["bundleWire"], "trust bundle preparation input");
      const verified = await verifyAndCommit(context, input.bundleWire);
      return commitmentFromVerified(controller, context, verified);
    },
    async issuePermit(
      input: Parameters<MarketplaceCategoryTrustController["issuePermit"]>[0],
    ): Promise<MarketplaceCategoryIssuancePermit> {
      assertExactObject(
        input,
        input.issuedAt === undefined
          ? ["adapterId", "bundleWire", "keyId", "releaseId", "serviceMode"]
          : [
              "adapterId",
              "bundleWire",
              "issuedAt",
              "keyId",
              "releaseId",
              "serviceMode",
            ],
        "trust issuance input",
      );
      const verified = await verifyAndCommit(context, input.bundleWire);
      const issuedAt =
        input.issuedAt === undefined
          ? readClock(context.clock)
          : unixSecondsSchema.parse(input.issuedAt);
      const adapterId = parseAdapterId(input.adapterId);
      const tuple = resolveMarketplaceTrustBundleAttestationTuple({
        verified,
        keyId: canonicalIdentifierSchema.parse(input.keyId),
        releaseId: canonicalIdentifierSchema.parse(input.releaseId),
        issuedAt,
        adapterId,
        serviceMode: input.serviceMode,
        phase: "issuance",
      });
      assertMarketplaceTrustResolvedTuple(tuple);
      const commitment = commitmentFromVerified(controller, context, verified);
      const permit = deepFreeze({
        bundleSha256: commitment.bundleSha256,
        generation: commitment.generation,
        revocationEpoch: commitment.revocationEpoch,
        stateSha256: commitment.stateSha256,
        keyId: tuple.keyId,
        releaseId: tuple.releaseId,
        adapterId: tuple.adapterMode.adapterId,
        serviceMode: tuple.adapterMode.serviceMode,
        issuedAt,
        quoteVerifyingContract: context.quoteVerifyingContract,
        tuple,
      });
      permits.set(permit, { controller });
      return permit;
    },
    assertPermit(value: unknown): asserts value is MarketplaceCategoryIssuancePermit {
      if (
        value === null ||
        typeof value !== "object" ||
        permits.get(value)?.controller !== controller ||
        consumedPermits.has(value)
      ) {
        throw new TypeError("issuance permit is not current controller provenance");
      }
    },
    async withPermit<Result>(
      value: MarketplaceCategoryIssuancePermit,
      operation: (tuple: MarketplaceTrustResolvedTuple) => Promise<Result>,
    ): Promise<Result> {
      controller.assertPermit(value);
      if (typeof operation !== "function") {
        throw new TypeError("issuance permit operation must be a function");
      }
      return context.stateStore.withRevision(value.stateSha256, async () => {
        const current = await context.stateStore.load();
        if (current.stateSha256 !== value.stateSha256 || current.state === undefined) {
          throw new Error("issuance permit is stale because trust state advanced");
        }
        if (canonicalSha256(current.state) !== value.stateSha256) {
          throw new Error("durable trust state digest is inconsistent");
        }
        consumedPermits.add(value);
        return operation(value.tuple);
      });
    },
    async readiness(
      input: Parameters<MarketplaceCategoryTrustController["readiness"]>[0],
    ): Promise<MarketplaceCategoryTrustReadiness> {
      try {
        const commitment = await controller.prepare(input);
        return Object.freeze({ ready: true, reason: "ready" as const, commitment });
      } catch (error) {
        const reason = classifyReadinessError(error);
        return Object.freeze({ ready: false, reason });
      }
    },
  });
  controllerRoots.set(
    controller,
    Object.freeze({
      keyId: context.root.keyId,
      publicKeyFingerprintSha256: context.root.publicKeyFingerprintSha256,
    }),
  );
  return controller;
}

/**
 * Resolves the root identity only for a controller created by this factory.
 * A structural clone cannot substitute a different root at the service edge.
 */
export function resolveMarketplaceCategoryTrustControllerRoot(
  value: unknown,
): MarketplaceCategoryTrustRootIdentity {
  const root =
    value !== null && typeof value === "object"
      ? controllerRoots.get(value)
      : undefined;
  if (root === undefined) {
    throw new TypeError("trust controller must come from the Core factory");
  }
  return root;
}

export function resolveMarketplaceCategoryTrustCommitment(
  value: unknown,
): ResolvedMarketplaceCategoryTrustCommitment {
  const resolved =
    value !== null && typeof value === "object"
      ? commitments.get(value)
      : undefined;
  if (resolved === undefined) {
    throw new TypeError(
      "trust commitment must come from an exact durable controller commit",
    );
  }
  return resolved;
}

async function verifyAndCommit(
  context: ControllerContext,
  bundleWire: MarketplaceTrustBundleWire,
): Promise<VerifiedMarketplaceTrustBundle> {
  const before = await context.stateStore.load();
  const verified = verifyMarketplaceTrustBundle({
    wire: bundleWire,
    root: context.root,
    evaluatedAt: readClock(context.clock),
    maxClockSkewSeconds: 30,
    maxBundleTtlSeconds: MAX_MARKETPLACE_TRUST_BUNDLE_TTL_SECONDS,
    rollbackFloor: context.rollbackFloor,
    ...(before.state === undefined ? {} : { priorState: before.state }),
  });
  const nextState = marketplaceTrustBundleDurableStateSchema.parse(verified.nextState);
  const nextStateSha256 = canonicalSha256(nextState);
  const expectedStateSha256 = before.stateSha256;
  if (before.state !== undefined && canonicalSha256(before.state) !== expectedStateSha256) {
    throw new Error("durable trust state digest does not match its content");
  }
  if (expectedStateSha256 !== nextStateSha256) {
    let receipt: MarketplaceCategoryTrustCasReceipt | undefined;
    try {
      receipt = await context.stateStore.compareAndSwap({
        expectedStateSha256,
        nextState,
        nextStateSha256,
        bundleSha256: verified.bundleSha256,
        generation: verified.envelope.generation,
        revocationEpoch: verified.envelope.revocationEpoch,
      });
    } catch {
      // The write may have committed before the backend response was lost.
    }
    if (
      receipt === undefined ||
      receipt.status === "conflict" ||
      receipt.committedStateSha256 !== nextStateSha256 ||
      receipt.bundleSha256 !== verified.bundleSha256 ||
      receipt.generation !== verified.envelope.generation ||
      receipt.revocationEpoch !== verified.envelope.revocationEpoch
    ) {
      const afterConflict = await context.stateStore.load();
      if (afterConflict.stateSha256 !== nextStateSha256) {
        throw new Error("durable trust state CAS conflict");
      }
    }
  }
  const after = await context.stateStore.load();
  if (
    after.state === undefined ||
    after.stateSha256 !== nextStateSha256 ||
    canonicalSha256(after.state) !== nextStateSha256 ||
    after.state.bundleSha256 !== verified.bundleSha256 ||
    after.state.generation !== verified.envelope.generation ||
    after.state.revocationEpoch !== verified.envelope.revocationEpoch
  ) {
    throw new Error("durable trust state was not committed exactly");
  }
  return verified;
}

function commitmentFromVerified(
  controller: MarketplaceCategoryTrustController,
  context: ControllerContext,
  verified: VerifiedMarketplaceTrustBundle,
): MarketplaceCategoryTrustCommitment {
  const nextState = deepFreeze(marketplaceTrustBundleDurableStateSchema.parse(verified.nextState));
  const commitment = Object.freeze({
    bundleSha256: verified.bundleSha256,
    generation: verified.envelope.generation,
    revocationEpoch: verified.envelope.revocationEpoch,
    stateSha256: canonicalSha256(nextState),
  });
  commitments.set(
    commitment,
    Object.freeze({
      controller,
      verified,
      quoteVerifyingContract: context.quoteVerifyingContract,
    }),
  );
  return commitment;
}

function normalizeSnapshot(value: unknown): MarketplaceCategoryTrustStateSnapshot {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("trust state snapshot must be an object");
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (canonicalJson(keys) !== canonicalJson(["state", "stateSha256"])) {
    throw new TypeError("trust state snapshot has unsupported fields");
  }
  const state =
    record.state === undefined
      ? undefined
      : deepFreeze(marketplaceTrustBundleDurableStateSchema.parse(record.state));
  const stateSha256 =
    record.stateSha256 === undefined
      ? undefined
      : stateDigestSchema.parse(record.stateSha256);
  if ((state === undefined) !== (stateSha256 === undefined)) {
    throw new TypeError("trust state snapshot must pair state and digest");
  }
  if (state !== undefined && canonicalSha256(state) !== stateSha256) {
    throw new TypeError("trust state snapshot digest does not match state");
  }
  return Object.freeze({ state, stateSha256 });
}

function normalizeCasInput(value: unknown): MarketplaceCategoryTrustCasInput {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("trust CAS input must be an object");
  }
  const input = value as Record<string, unknown>;
  const keys = Object.keys(input).sort();
  if (
    canonicalJson(keys) !==
    canonicalJson([
      "bundleSha256",
      "expectedStateSha256",
      "generation",
      "nextState",
      "nextStateSha256",
      "revocationEpoch",
    ])
  ) {
    throw new TypeError("trust CAS input has unsupported fields");
  }
  const nextState = deepFreeze(marketplaceTrustBundleDurableStateSchema.parse(input.nextState));
  const nextStateSha256 = stateDigestSchema.parse(input.nextStateSha256);
  if (canonicalSha256(nextState) !== nextStateSha256) {
    throw new TypeError("trust CAS input state digest does not match");
  }
  return Object.freeze({
    expectedStateSha256:
      input.expectedStateSha256 === undefined
        ? undefined
        : stateDigestSchema.parse(input.expectedStateSha256),
    nextState,
    nextStateSha256,
    bundleSha256: stateDigestSchema.parse(input.bundleSha256),
    generation: parseCounter(input.generation),
    revocationEpoch: parseCounter(input.revocationEpoch),
  });
}

function normalizeCasReceipt(
  value: unknown,
  input: MarketplaceCategoryTrustCasInput,
): MarketplaceCategoryTrustCasReceipt {
  assertExactObject(
    value,
    [
      "bundleSha256",
      "committedStateSha256",
      "expectedStateSha256",
      "generation",
      "revocationEpoch",
      "status",
    ],
    "trust CAS receipt",
  );
  const receipt = value as Record<string, unknown>;
  const status = receipt.status;
  if (status !== "committed" && status !== "already_committed" && status !== "conflict") {
    throw new TypeError("trust CAS receipt status is invalid");
  }
  const expectedStateSha256 =
    receipt.expectedStateSha256 === undefined
      ? undefined
      : stateDigestSchema.parse(receipt.expectedStateSha256);
  const committedStateSha256 =
    receipt.committedStateSha256 === undefined
      ? undefined
      : stateDigestSchema.parse(receipt.committedStateSha256);
  const bundleSha256 =
    receipt.bundleSha256 === undefined
      ? undefined
      : stateDigestSchema.parse(receipt.bundleSha256);
  const generation =
    receipt.generation === undefined ? undefined : parseCounter(receipt.generation);
  const revocationEpoch =
    receipt.revocationEpoch === undefined
      ? undefined
      : parseCounter(receipt.revocationEpoch);
  if (expectedStateSha256 !== input.expectedStateSha256) {
    throw new TypeError("trust CAS receipt expected digest does not match input");
  }
  return Object.freeze({
    status,
    expectedStateSha256,
    committedStateSha256,
    bundleSha256,
    generation,
    revocationEpoch,
  });
}

function parseCounter(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError("trust counter is invalid");
  }
  return value;
}

function parseAdapterId(value: unknown): MarketplaceCategoryAdapterId {
  const parsed = canonicalIdentifierSchema.parse(value);
  if (!(MARKETPLACE_CATEGORY_ADAPTER_IDS as readonly string[]).includes(parsed)) {
    throw new TypeError("trust issuance adapter ID is not registered");
  }
  return parsed as MarketplaceCategoryAdapterId;
}

function classifyReadinessError(error: unknown): MarketplaceCategoryTrustReadiness["reason"] {
  const message = error instanceof Error ? error.message : "";
  if (message.includes("expired")) return "bundle_expired";
  if (message.includes("CAS conflict")) return "commit_conflict";
  if (message.includes("durable trust state")) return "state_mismatch";
  if (message.includes("state store")) return "state_unavailable";
  return "bundle_invalid";
}

function readClock(clock: () => number): number {
  let value: number;
  try {
    value = clock();
  } catch (cause) {
    throw new Error("trust controller clock is unavailable", { cause });
  }
  return unixSecondsSchema.parse(value);
}

function assertExactObject(
  value: unknown,
  expected: readonly string[],
  label: string,
): asserts value is Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new TypeError(`${label} must be a plain object`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors).sort();
  if (canonicalJson(keys) !== canonicalJson([...expected].sort())) {
    throw new TypeError(`${label} has unsupported or missing fields`);
  }
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    ) {
      throw new TypeError(`${label} must contain enumerable data properties`);
    }
  }
}
