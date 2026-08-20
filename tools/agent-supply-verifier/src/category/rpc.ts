import {
  blockAnchorSchema,
  type BlockAnchor,
  type CallOutcome,
  type PinnedBlockReader,
  type ReadObservation,
} from "@mandatex/category-adapters";

import { computeQuoteSha256 } from "../quotes/protocol.js";
import {
  BSC_MAINNET_RPC_ORIGIN,
  TransportError,
  type BoundedHttpResponse,
  type PinnedHttpsTransport,
} from "../transport/http.js";
import type { CategoryReadAttempt } from "./schema.js";

const BSC_CHAIN_ID = 56;
export const CATEGORY_CONFIRMATION_DEPTH = 2 as const;

export type CategorySnapshot = Readonly<{
  chainId: 56;
  anchor: BlockAnchor;
  confirmationDepth: typeof CATEGORY_CONFIRMATION_DEPTH;
}>;

declare const categorySnapshotHandleBrand: unique symbol;

/**
 * An opaque, verifier-owned snapshot handle.  The block anchor is deliberately
 * not part of this public shape; consumers must present the handle back to the
 * originating capability for every read.
 */
export type CategorySnapshotHandle = Readonly<{
  readonly [categorySnapshotHandleBrand]: true;
}>;

export interface CategorySnapshotCapability {
  readonly withSnapshot: <Result>(
    operation: (snapshot: CategorySnapshot) => Promise<Result>,
    anchor?: BlockAnchor,
  ) => Promise<Result>;
  readonly assertActive: (value: unknown) => asserts value is CategorySnapshot;
  /** Capture one opaque snapshot for a multi-capability evaluation. */
  readonly withOpaqueSnapshot: <Result>(
    operation: (snapshot: CategorySnapshotHandle) => Promise<Result>,
  ) => Promise<Result>;
  /** Run a consumer against an already-active opaque snapshot. */
  readonly withActiveSnapshot: <Result>(
    snapshot: CategorySnapshotHandle,
    operation: (snapshot: CategorySnapshotHandle) => Promise<Result>,
  ) => Promise<Result>;
  readonly assertOpaqueActive: (
    value: unknown,
  ) => asserts value is CategorySnapshotHandle;
  readonly anchorForOpaque: (value: CategorySnapshotHandle) => BlockAnchor;
  readonly assertOpaqueCanonical: (
    value: CategorySnapshotHandle,
  ) => Promise<void>;
  /**
   * Perform the terminal canonicality fence and execute a durable commit while
   * the caller's surrounding authorization/revision lock is still held.
   * Successful finalization suppresses the wrapper's redundant trailing fence.
   */
  readonly finalizeOpaqueSnapshot: <Result>(
    value: CategorySnapshotHandle,
    commit: () => Promise<Result>,
  ) => Promise<Result>;
  readonly createReader: (
    value: CategorySnapshot | CategorySnapshotHandle,
    expectedReads: readonly ExpectedCategoryRead[],
  ) => Promise<TransportPinnedCategoryReader>;
}

const activeSnapshots = new WeakMap<object, CategorySnapshotCapability>();
const activeOpaqueSnapshots = new WeakMap<
  object,
  Readonly<{ capability: CategorySnapshotCapability; anchor: BlockAnchor }>
>();
const finalizedOpaqueSnapshots = new WeakSet<object>();

export type ExpectedCategoryRead = Readonly<{
  label: string;
  to: string;
  data: string;
}>;

export class CategoryBlockPinError extends Error {
  constructor() {
    super("the category reader could not establish a canonical BSC block anchor");
    this.name = "CategoryBlockPinError";
  }
}

export class CategoryBlockCanonicalityError extends Error {
  constructor() {
    super("the pinned category block is no longer canonical");
    this.name = "CategoryBlockCanonicalityError";
  }
}

export class CategoryReadContractError extends Error {
  constructor() {
    super("the category adapter violated its manifest-derived read contract");
    this.name = "CategoryReadContractError";
  }
}

/**
 * Pins one confirmed BSC block for all category evidence producers. The
 * returned object is capability-branded; consumers must use the same factory
 * instance to prove that its anchor was established by the verifier.
 */
export function createCategorySnapshotCapability(options: {
  readonly transport: Pick<PinnedHttpsTransport, "request">;
  readonly randomUUID: () => string;
}): CategorySnapshotCapability {
  if (
    options === null ||
    typeof options !== "object" ||
    typeof options.transport?.request !== "function" ||
    typeof options.randomUUID !== "function"
  ) {
    throw new CategoryReadContractError();
  }
  const transport = options.transport;
  const randomUUID = options.randomUUID;
  let capability: CategorySnapshotCapability;
  const assertOpaqueActive: CategorySnapshotCapability["assertOpaqueActive"] = (
    value: unknown,
  ): asserts value is CategorySnapshotHandle => {
    if (
      value === null ||
      typeof value !== "object" ||
      activeOpaqueSnapshots.get(value)?.capability !== capability ||
      finalizedOpaqueSnapshots.has(value)
    ) {
      throw new CategoryReadContractError();
    }
  };
  const anchorForOpaque: CategorySnapshotCapability["anchorForOpaque"] = (value) => {
    assertOpaqueActive(value);
    const entry = activeOpaqueSnapshots.get(value);
    if (entry === undefined) throw new CategoryReadContractError();
    return Object.freeze({ ...entry.anchor });
  };
  const assertOpaqueCanonical = async (
    value: CategorySnapshotHandle,
  ): Promise<void> => {
    const anchor = anchorForOpaque(value);
    if (finalizedOpaqueSnapshots.has(value)) {
      throw new CategoryReadContractError();
    }
    try {
      const observed = await readBlockHeader(
        transport,
        randomUUID,
        anchor.number,
      );
      if (
        observed.number !== anchor.number ||
        observed.hash !== anchor.hash ||
        observed.timestamp !== anchor.timestamp
      ) {
        throw new CategoryBlockCanonicalityError();
      }
    } catch (cause) {
      if (cause instanceof CategoryBlockCanonicalityError) throw cause;
      if (isTransportPolicyViolation(cause)) {
        throw new CategoryReadContractError();
      }
      throw new CategoryBlockCanonicalityError();
    }
  };
  const withActiveSnapshot = async <Result>(
    snapshot: CategorySnapshotHandle,
    operation: (snapshot: CategorySnapshotHandle) => Promise<Result>,
  ): Promise<Result> => {
    assertOpaqueActive(snapshot);
    if (typeof operation !== "function") throw new CategoryReadContractError();
    return operation(snapshot);
  };
  const withOpaqueSnapshot = async <Result>(
    operation: (snapshot: CategorySnapshotHandle) => Promise<Result>,
  ): Promise<Result> => {
    if (typeof operation !== "function") throw new CategoryReadContractError();
    const anchor = await pinCategoryBlock(transport, randomUUID);
    const snapshot = Object.freeze({}) as CategorySnapshotHandle;
    activeOpaqueSnapshots.set(
      snapshot,
      Object.freeze({ capability: capability!, anchor: Object.freeze({ ...anchor }) }),
    );
    try {
      const result = await operation(snapshot);
      if (!finalizedOpaqueSnapshots.has(snapshot)) {
        await assertOpaqueCanonical(snapshot);
      }
      return result;
    } catch (cause) {
      if (cause instanceof CategoryBlockCanonicalityError) throw cause;
      if (isTransportPolicyViolation(cause)) throw new CategoryReadContractError();
      throw cause;
    } finally {
      finalizedOpaqueSnapshots.delete(snapshot);
      activeOpaqueSnapshots.delete(snapshot);
    }
  };
  const finalizeOpaqueSnapshot = async <Result>(
    value: CategorySnapshotHandle,
    commit: () => Promise<Result>,
  ): Promise<Result> => {
    assertOpaqueActive(value);
    if (typeof commit !== "function") {
      throw new CategoryReadContractError();
    }
    if (finalizedOpaqueSnapshots.has(value)) {
      throw new CategoryReadContractError();
    }
    await assertOpaqueCanonical(value);
    // Mark the handle before invoking the external commit. A commit may write
    // durably and then lose its response; the wrapper must never run another
    // canonicality check or attempt a compensating release in that ambiguity.
    finalizedOpaqueSnapshots.add(value);
    const result = await commit();
    return result;
  };
  capability = Object.freeze({
    async withSnapshot<Result>(
      operation: (snapshot: CategorySnapshot) => Promise<Result>,
      suppliedAnchor?: BlockAnchor,
    ): Promise<Result> {
      if (typeof operation !== "function") {
        throw new CategoryReadContractError();
      }
      const anchor =
        suppliedAnchor === undefined
          ? await pinCategoryBlock(transport, randomUUID)
          : await validateSuppliedAnchor(transport, randomUUID, suppliedAnchor);
      const snapshot = Object.freeze({
        chainId: 56 as const,
        anchor: Object.freeze({ ...anchor }),
        confirmationDepth: CATEGORY_CONFIRMATION_DEPTH,
      });
      activeSnapshots.set(snapshot, capability);
      try {
        const result = await operation(snapshot);
        const observed = await readBlockHeader(
          transport,
          randomUUID,
          snapshot.anchor.number,
        );
        if (
          observed.number !== snapshot.anchor.number ||
          observed.hash !== snapshot.anchor.hash ||
          observed.timestamp !== snapshot.anchor.timestamp
        ) {
          throw new CategoryBlockCanonicalityError();
        }
        return result;
      } catch (cause) {
        if (cause instanceof CategoryBlockCanonicalityError) throw cause;
        if (isTransportPolicyViolation(cause)) {
          throw new CategoryReadContractError();
        }
        throw cause;
      } finally {
        activeSnapshots.delete(snapshot);
      }
    },
    withOpaqueSnapshot,
    withActiveSnapshot,
    assertOpaqueActive,
    anchorForOpaque,
    assertOpaqueCanonical,
    finalizeOpaqueSnapshot,
    assertActive(value: unknown): asserts value is CategorySnapshot {
      if (
        value === null ||
        typeof value !== "object" ||
        activeSnapshots.get(value) !== capability
      ) {
        throw new CategoryReadContractError();
      }
    },
    async createReader(
      value: CategorySnapshot | CategorySnapshotHandle,
      expectedReads: readonly ExpectedCategoryRead[],
    ): Promise<TransportPinnedCategoryReader> {
      let anchor: BlockAnchor;
      if (activeOpaqueSnapshots.has(value as object)) {
        anchor = anchorForOpaque(value as CategorySnapshotHandle);
      } else {
        capability.assertActive(value as CategorySnapshot);
        anchor = (value as CategorySnapshot).anchor;
      }
      return TransportPinnedCategoryReader.create({
        transport,
        randomUUID,
        anchor,
        expectedReads,
      });
    },
  });
  return capability;
}

/**
 * Pins a confirmed BSC block for a caller that must coordinate more than one
 * verifier capability (for example ERC-8004 identity plus category reads).
 * Every consumer still rechecks this anchor's canonicality before accepting a
 * result; returning it does not grant RPC access or signing authority.
 */
export async function captureCategoryBlockAnchor(options: {
  readonly transport: Pick<PinnedHttpsTransport, "request">;
  readonly randomUUID: () => string;
}): Promise<BlockAnchor> {
  if (
    options === null ||
    typeof options !== "object" ||
    typeof options.transport?.request !== "function" ||
    typeof options.randomUUID !== "function"
  ) {
    throw new CategoryBlockPinError();
  }
  return pinCategoryBlock(options.transport, options.randomUUID);
}

export class TransportPinnedCategoryReader implements PinnedBlockReader {
  readonly #anchor: BlockAnchor;
  readonly #transport: Pick<PinnedHttpsTransport, "request">;
  readonly #randomUUID: () => string;
  readonly #expected: readonly ExpectedCategoryRead[];
  readonly #attempts: Array<CategoryReadAttempt | undefined>;
  #nextExpectedIndex = 0;
  #contractViolation = false;

  get anchor(): BlockAnchor {
    return this.#anchor;
  }

  private constructor(options: {
    transport: Pick<PinnedHttpsTransport, "request">;
    randomUUID: () => string;
    anchor: BlockAnchor;
    expectedReads: readonly ExpectedCategoryRead[];
  }) {
    this.#transport = options.transport;
    this.#randomUUID = options.randomUUID;
    this.#anchor = Object.freeze({ ...blockAnchorSchema.parse(options.anchor) });
    this.#expected = options.expectedReads;
    this.#attempts = this.#expected.map(() => undefined);
    Object.freeze(this);
  }

  static async create(options: {
    transport: Pick<PinnedHttpsTransport, "request">;
    randomUUID: () => string;
    expectedReads: readonly ExpectedCategoryRead[];
    anchor?: BlockAnchor;
  }): Promise<TransportPinnedCategoryReader> {
    if (
      options === null ||
      typeof options !== "object" ||
      typeof options.transport?.request !== "function" ||
      typeof options.randomUUID !== "function"
    ) {
      throw new CategoryReadContractError();
    }
    let expectedReads: readonly ExpectedCategoryRead[];
    try {
      expectedReads = parseExpectedReads(options.expectedReads);
    } catch {
      throw new CategoryReadContractError();
    }
    const anchor =
      options.anchor === undefined
        ? await pinCategoryBlock(options.transport, options.randomUUID)
        : blockAnchorSchema.parse(options.anchor);
    return new TransportPinnedCategoryReader({
      transport: options.transport,
      randomUUID: options.randomUUID,
      anchor,
      expectedReads,
    });
  }

  async call(request: {
    readonly label: string;
    readonly to: string;
    readonly data: string;
  }): Promise<CallOutcome | undefined> {
    const index = this.#nextExpectedIndex;
    this.#nextExpectedIndex += 1;
    let requested: ExpectedCategoryRead | undefined;
    try {
      requested = parseCallRequest(request);
    } catch {
      requested = undefined;
    }
    const expected = this.#expected[index];
    if (
      expected === undefined ||
      requested === undefined ||
      expected.label !== requested.label ||
      expected.to !== requested.to ||
      expected.data !== requested.data
    ) {
      this.#contractViolation = true;
      return undefined;
    }

    const id = `category-state-${this.#randomUUID()}`;
    const body = JSON.stringify({
      jsonrpc: "2.0",
      id,
      method: "eth_call",
      params: [
        { to: requested.to, data: requested.data },
        { blockHash: this.anchor.hash, requireCanonical: true },
      ],
    });
    const requestSha256 = computeQuoteSha256(body);
    let response: BoundedHttpResponse;
    try {
      response = await this.#transport.request({
        kind: "bsc-category-rpc",
        purpose: "state-read",
        method: "POST",
        url: BSC_MAINNET_RPC_ORIGIN,
        rpcMethod: "eth_call",
        approvedTargets: [requested.to],
        approvedCalldata: requested.data,
        approvedBlockHash: this.anchor.hash,
        body,
      });
    } catch (cause) {
      if (isTransportPolicyViolation(cause)) {
        this.#contractViolation = true;
        throw new CategoryReadContractError();
      }
      this.#attempts[index] = Object.freeze({
        label: requested.label,
        to: requested.to,
        data: requested.data,
        requestSha256,
        outcome: "unavailable",
      });
      return undefined;
    }

    const snapshot = snapshotResponse(response);
    if (snapshot === undefined) {
      this.#attempts[index] = Object.freeze({
        label: requested.label,
        to: requested.to,
        data: requested.data,
        requestSha256,
        outcome: "invalid_response",
      });
      return undefined;
    }
    const observation = Object.freeze({
      label: requested.label,
      to: requested.to,
      requestSha256,
      responseSha256: snapshot.responseSha256,
    } satisfies ReadObservation);
    const attemptCommon = {
      ...observation,
      data: requested.data,
    } as const;
    if (!snapshot.digestMatches || snapshot.status !== 200) {
      this.#attempts[index] = Object.freeze({
        ...attemptCommon,
        outcome: snapshot.digestMatches ? "unavailable" : "invalid_response",
      });
      return undefined;
    }

    let parsed: unknown;
    try {
      parsed = parseJsonBody(snapshot);
    } catch {
      this.#attempts[index] = Object.freeze({
        ...attemptCommon,
        outcome: "invalid_response",
      });
      return undefined;
    }
    if (
      !isRecord(parsed) ||
      !hasExactKeys(parsed, ["id", "jsonrpc", "result"]) ||
      parsed.jsonrpc !== "2.0" ||
      parsed.id !== id ||
      typeof parsed.result !== "string" ||
      !/^0x(?:[0-9a-f]{2})*$/.test(parsed.result)
    ) {
      this.#attempts[index] = Object.freeze({
        ...attemptCommon,
        outcome: "invalid_response",
      });
      return undefined;
    }

    this.#attempts[index] = Object.freeze({
      ...attemptCommon,
      outcome: "success",
    });
    return Object.freeze({ data: parsed.result, observation });
  }

  attempts(): readonly CategoryReadAttempt[] {
    if (
      this.#contractViolation ||
      this.#nextExpectedIndex !== this.#expected.length ||
      this.#attempts.some((attempt) => attempt === undefined)
    ) {
      throw new CategoryReadContractError();
    }
    return Object.freeze(
      this.#attempts.map((attempt) => Object.freeze({ ...attempt! })),
    );
  }

  async assertCanonical(): Promise<void> {
    try {
      const observed = await readBlockHeader(
        this.#transport,
        this.#randomUUID,
        this.anchor.number,
      );
      if (
        observed.number !== this.anchor.number ||
        observed.hash !== this.anchor.hash ||
        observed.timestamp !== this.anchor.timestamp
      ) {
        throw new CategoryBlockCanonicalityError();
      }
    } catch (cause) {
      if (cause instanceof CategoryBlockCanonicalityError) throw cause;
      if (isTransportPolicyViolation(cause)) {
        throw new CategoryReadContractError();
      }
      throw new CategoryBlockCanonicalityError();
    }
  }
}

async function pinCategoryBlock(
  transport: Pick<PinnedHttpsTransport, "request">,
  randomUUID: () => string,
): Promise<BlockAnchor> {
  try {
    const chainId = await rpcResult(transport, randomUUID, {
      purpose: "chain-id",
      rpcMethod: "eth_chainId",
      params: [],
    });
    if (parseQuantity(chainId) !== BigInt(BSC_CHAIN_ID)) {
      throw new CategoryBlockPinError();
    }
    const head = parseQuantity(
      await rpcResult(transport, randomUUID, {
        purpose: "head-block-number",
        rpcMethod: "eth_blockNumber",
        params: [],
      }),
    );
    if (head < BigInt(CATEGORY_CONFIRMATION_DEPTH)) {
      throw new CategoryBlockPinError();
    }
    const target = head - BigInt(CATEGORY_CONFIRMATION_DEPTH);
    if (target > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new CategoryBlockPinError();
    }
    return await readBlockHeader(transport, randomUUID, Number(target));
  } catch (cause) {
    if (cause instanceof CategoryBlockPinError) throw cause;
    if (cause instanceof CategoryReadContractError) throw cause;
    if (isTransportPolicyViolation(cause)) {
      throw new CategoryReadContractError();
    }
    throw new CategoryBlockPinError();
  }
}

/**
 * A caller-supplied anchor is only a coordination hint. Re-select the
 * verifier's current confirmation-depth boundary and re-read its header
 * before allowing adapter calls to use it. This prevents an arbitrary old
 * block from being smuggled into the shared-snapshot path.
 */
async function validateSuppliedAnchor(
  transport: Pick<PinnedHttpsTransport, "request">,
  randomUUID: () => string,
  supplied: unknown,
): Promise<BlockAnchor> {
  const anchor = parseSuppliedAnchor(supplied);
  try {
    const chainId = await rpcResult(transport, randomUUID, {
      purpose: "chain-id",
      rpcMethod: "eth_chainId",
      params: [],
    });
    if (parseQuantity(chainId) !== BigInt(BSC_CHAIN_ID)) {
      throw new CategoryBlockPinError();
    }
    const head = parseQuantity(
      await rpcResult(transport, randomUUID, {
        purpose: "head-block-number",
        rpcMethod: "eth_blockNumber",
        params: [],
      }),
    );
    const expected = head - BigInt(CATEGORY_CONFIRMATION_DEPTH);
    if (expected < 0n || expected !== BigInt(anchor.number)) {
      throw new CategoryBlockPinError();
    }
    const observed = await readBlockHeader(transport, randomUUID, anchor.number);
    if (
      observed.hash !== anchor.hash ||
      observed.timestamp !== anchor.timestamp
    ) {
      throw new CategoryBlockCanonicalityError();
    }
    return anchor;
  } catch (cause) {
    if (
      cause instanceof CategoryBlockPinError ||
      cause instanceof CategoryBlockCanonicalityError ||
      cause instanceof CategoryReadContractError
    ) {
      throw cause;
    }
    if (isTransportPolicyViolation(cause)) {
      throw new CategoryReadContractError();
    }
    throw new CategoryBlockPinError();
  }
}

function parseSuppliedAnchor(value: unknown): BlockAnchor {
  try {
    return blockAnchorSchema.parse(value);
  } catch {
    throw new CategoryBlockPinError();
  }
}

async function readBlockHeader(
  transport: Pick<PinnedHttpsTransport, "request">,
  randomUUID: () => string,
  blockNumber: number,
): Promise<BlockAnchor> {
  const blockHex = `0x${BigInt(blockNumber).toString(16)}`;
  const result = await rpcResult(transport, randomUUID, {
    purpose: "block-header",
    rpcMethod: "eth_getBlockByNumber",
    params: [blockHex, false],
    approvedBlockNumber: blockHex,
  });
  if (
    !isRecord(result) ||
    result.number !== blockHex ||
    typeof result.hash !== "string" ||
    !/^0x[0-9a-f]{64}$/.test(result.hash)
  ) {
    throw new CategoryBlockPinError();
  }
  const timestamp = parseQuantity(result.timestamp);
  if (timestamp > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new CategoryBlockPinError();
  }
  return blockAnchorSchema.parse({
    number: blockNumber,
    hash: result.hash,
    timestamp: Number(timestamp),
  });
}

async function rpcResult(
  transport: Pick<PinnedHttpsTransport, "request">,
  randomUUID: () => string,
  request: CategoryPinRpcRequest,
): Promise<unknown> {
  const id = `category-pin-${randomUUID()}`;
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id,
    method: request.rpcMethod,
    params: request.params,
  });
  const common = {
    kind: "bsc-category-rpc" as const,
    method: "POST" as const,
    url: BSC_MAINNET_RPC_ORIGIN,
    body,
  };
  const response = await transport.request(
    request.purpose === "chain-id"
      ? {
          ...common,
          purpose: request.purpose,
          rpcMethod: request.rpcMethod,
        }
      : request.purpose === "head-block-number"
        ? {
            ...common,
            purpose: request.purpose,
            rpcMethod: request.rpcMethod,
          }
        : {
            ...common,
            purpose: request.purpose,
            rpcMethod: request.rpcMethod,
            approvedBlockNumber: request.approvedBlockNumber,
          },
  );
  const snapshot = snapshotResponse(response);
  if (
    snapshot === undefined ||
    !snapshot.digestMatches ||
    snapshot.status !== 200
  ) {
    throw new CategoryBlockPinError();
  }
  const parsed = parseJsonBody(snapshot);
  if (
    !isRecord(parsed) ||
    !hasExactKeys(parsed, ["id", "jsonrpc", "result"]) ||
    parsed.jsonrpc !== "2.0" ||
    parsed.id !== id ||
    !("result" in parsed)
  ) {
    throw new CategoryBlockPinError();
  }
  return parsed.result;
}

type CategoryPinRpcRequest =
  | Readonly<{
      purpose: "chain-id";
      rpcMethod: "eth_chainId";
      params: readonly unknown[];
    }>
  | Readonly<{
      purpose: "head-block-number";
      rpcMethod: "eth_blockNumber";
      params: readonly unknown[];
    }>
  | Readonly<{
      purpose: "block-header";
      rpcMethod: "eth_getBlockByNumber";
      params: readonly unknown[];
      approvedBlockNumber: string;
    }>;

type CategoryResponseSnapshot = Readonly<{
  status: number;
  contentType: string | null;
  body: Uint8Array;
  responseSha256: string;
  digestMatches: boolean;
}>;

function snapshotResponse(
  response: BoundedHttpResponse,
): CategoryResponseSnapshot | undefined {
  try {
    if (
      response === null ||
      typeof response !== "object" ||
      !(response.body instanceof Uint8Array)
    ) {
      return undefined;
    }
    const body = Uint8Array.from(response.body);
    const responseSha256 = computeQuoteSha256(body);
    const status = response.status;
    const contentType = response.contentType;
    if (
      !Number.isSafeInteger(status) ||
      status < 0 ||
      status > 999 ||
      (contentType !== null && typeof contentType !== "string")
    ) {
      return undefined;
    }
    return Object.freeze({
      status,
      contentType,
      body,
      responseSha256,
      digestMatches:
        typeof response.responseSha256 === "string" &&
        /^[0-9a-f]{64}$/.test(response.responseSha256) &&
        response.responseSha256 === responseSha256,
    });
  } catch {
    return undefined;
  }
}

function parseJsonBody(response: CategoryResponseSnapshot): unknown {
  if (
    response.contentType === null ||
    !/^application\/json(?:\s*;|$)/i.test(response.contentType)
  ) {
    throw new CategoryBlockPinError();
  }
  return JSON.parse(Buffer.from(response.body).toString("utf8")) as unknown;
}

function parseExpectedReads(value: unknown): readonly ExpectedCategoryRead[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 4) {
    throw new CategoryReadContractError();
  }
  return Object.freeze(value.map((read) => parseExpectedRead(read)));
}

function parseCallRequest(value: unknown): ExpectedCategoryRead {
  return parseExpectedRead(value);
}

function parseExpectedRead(value: unknown): ExpectedCategoryRead {
  if (
    !isRecord(value) ||
    !hasExactDataKeys(value, ["data", "label", "to"]) ||
    typeof value.label !== "string" ||
    !/^[A-Za-z0-9._:-]{1,64}$/.test(value.label) ||
    typeof value.to !== "string" ||
    !/^0x[0-9a-f]{40}$/.test(value.to) ||
    typeof value.data !== "string" ||
    !/^0x(?:[0-9a-f]{2})+$/.test(value.data)
  ) {
    throw new CategoryReadContractError();
  }
  return Object.freeze({
    label: value.label,
    to: value.to,
    data: value.data,
  });
}

function parseQuantity(value: unknown): bigint {
  if (typeof value !== "string" || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(value)) {
    throw new CategoryBlockPinError();
  }
  return BigInt(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isTransportPolicyViolation(cause: unknown): cause is TransportError {
  return (
    cause instanceof TransportError &&
    [
      "INVALID_URL",
      "METHOD_NOT_ALLOWED",
      "ORIGIN_NOT_ALLOWED",
      "PATH_NOT_ALLOWED",
      "RPC_METHOD_NOT_ALLOWED",
      "REQUEST_TOO_LARGE",
    ].includes(cause.code)
  );
}

function hasExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return (
    actual.length === sortedExpected.length &&
    actual.every((key, index) => key === sortedExpected[index])
  );
}

function hasExactDataKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
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
}
