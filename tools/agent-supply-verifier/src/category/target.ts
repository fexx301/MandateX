import { createHash } from "node:crypto";

import {
  GRID_ADAPTER_ID,
  HEALTH_ADAPTER_ID,
  SELECTOR_BORROW_BALANCE_STORED,
  SELECTOR_GET_ACCOUNT_LIQUIDITY,
  SELECTOR_GET_ASSETS_IN,
  SELECTOR_GET_USER_ACCOUNT_DATA,
  SELECTOR_SLOT0,
  SELECTOR_TOTAL_ASSETS,
  SELECTOR_TOTAL_SUPPLY,
  UINT160_MAX,
  V3_MAX_SQRT_RATIO,
  V3_MAX_TICK,
  V3_MIN_SQRT_RATIO,
  V3_MIN_TICK,
  VENUS_HEALTH_ADAPTER_ID,
  YIELD_ADAPTER_ID,
  addressCalldata,
  decodeDynamicArrayLength,
  decodeInt24,
  decodeUint256,
  wordCount,
} from "@mandatex/category-adapters";

import { canonicalQuoteJson, computeQuoteSha256 } from "../quotes/protocol.js";
import {
  BSC_CATEGORY_TARGET_BEACON_IMPLEMENTATION_SELECTOR,
  BSC_CATEGORY_TARGET_BEACON_SLOT,
  BSC_CATEGORY_TARGET_IMPLEMENTATION_SLOT,
  BSC_MAINNET_RPC_ORIGIN,
  BSC_CATEGORY_TARGET_PROVENANCE_SELECTORS,
  parseJsonResponse,
  TransportError,
  type BoundedHttpResponse,
  type BscCategoryTargetRpcRoute,
  type PinnedHttpsTransport,
} from "../transport/http.js";
import type {
  CategorySnapshotCapability,
  CategorySnapshotHandle,
} from "./rpc.js";

/** The production target-observation schema used by marketplace-core. */
export const CATEGORY_TARGET_OBSERVATION_SCHEMA =
  "mandatex.marketplace.category-target-observation.v1" as const;
export const CATEGORY_TARGET_PROVENANCE_PROFILE =
  "interface-only-unendorsed-v1" as const;
export const CATEGORY_TARGET_GRID_PROVENANCE_PROFILE =
  "pancakeswap-v3-factory-membership-v1" as const;
export const CATEGORY_TARGET_AAVE_PROVENANCE_PROFILE =
  "aave-v3-addresses-provider-v1" as const;
export const CATEGORY_TARGET_VENUS_PROVENANCE_PROFILE =
  "venus-market-membership-v1" as const;
export const CATEGORY_TARGET_CONFIRMATION_DEPTH = 2 as const;

const BSC_CHAIN_ID = 56;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
const SELECTOR_FACTORY = "0xc45a0155" as const;
const SELECTOR_COMPTROLLER = "0x5fe3b567" as const;
const SELECTOR_MARKETS = "0x8e8f294b" as const;
const SELECTOR_AAVE_GET_POOL = "0x026b1d5f" as const;
const IDENTIFIER_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const ADDRESS_RE = /^0x[0-9a-f]{40}$/;
const BLOCK_HASH_RE = /^0x[0-9a-f]{64}$/;
const HEX_BYTES_RE = /^0x(?:[0-9a-f]{2})*$/;
const NONEMPTY_HEX_BYTES_RE = /^0x(?:[0-9a-f]{2})+$/;
const QUANTITY_RE = /^0x(?:0|[1-9a-f][0-9a-f]*)$/;
const FIXED_PROVENANCE_SELECTOR_SET = new Set<string>(
  BSC_CATEGORY_TARGET_PROVENANCE_SELECTORS,
);
const REGISTERED_CATEGORY_ADAPTER_IDS = Object.freeze([
  GRID_ADAPTER_ID,
  YIELD_ADAPTER_ID,
  HEALTH_ADAPTER_ID,
  VENUS_HEALTH_ADAPTER_ID,
] as const);

export type CategoryTargetAdapterId =
  (typeof REGISTERED_CATEGORY_ADAPTER_IDS)[number];

export type CategoryTargetAnchor = Readonly<{
  number: number;
  hash: string;
  timestamp: number;
}>;

export type ExpectedTargetProvenanceRead = Readonly<{
  label: string;
  to: string;
  data: string;
}>;

type CategoryTargetObservationInputBase = Readonly<{
  /** A registered adapter identifier, when the observation is projected into Core. */
  adapterId: CategoryTargetAdapterId;
  /** The manifest role for this target (for example `pool` or `vault`). */
  role: string;
  /** Required subject argument for Aave and Venus health read profiles. */
  accountAddress?: string;
  /** Optional cross-target bindings used only by the Venus membership profile. */
  comptrollerAddress?: string;
  borrowMarketAddress?: string;
  /** A verifier-owned block anchor. If omitted, this capability pins one. */
  anchor?: CategoryTargetAnchor;
  /** Opaque snapshot handle from the verifier-owned snapshot capability. */
  snapshot?: CategorySnapshotHandle | CategoryTargetAnchor;
  /** Optional low-level aliases for an anchor. Must be supplied as a complete triple. */
  blockNumber?: number;
  blockHash?: string;
  blockTimestamp?: number;
  /** Optional exact echo of the verifier-owned adapter read profile. */
  provenance?: readonly ExpectedTargetProvenanceRead[];
  provenanceReads?: readonly ExpectedTargetProvenanceRead[];
  expectedProvenance?: readonly ExpectedTargetProvenanceRead[];
}>;

/** Canonical target address; `target` is accepted as a low-level alias. */
export type CategoryTargetObservationInput =
  CategoryTargetObservationInputBase &
    Readonly<
      | { targetAddress: string; target?: string }
      | { targetAddress?: string; target: string }
    >;

export type CategoryTargetProxyObservation = Readonly<
  | { kind: "none" }
  | {
      kind: "eip1967";
      implementationAddress: string;
      implementationCodeSha256: string;
    }
  | {
      kind: "beacon";
      beaconAddress: string;
      beaconCodeSha256: string;
      implementationAddress: string;
      implementationCodeSha256: string;
    }
>;

/** Core-compatible target observation. Route evidence lives on the result wrapper. */
export type CategoryTargetObservation = Readonly<{
  schema: typeof CATEGORY_TARGET_OBSERVATION_SCHEMA;
  adapterId: CategoryTargetAdapterId;
  role: string;
  targetAddress: string;
  assurance: "protocol_instance_verified" | "interface_only_unendorsed";
  runtimeCodeSha256: string;
  proxy: CategoryTargetProxyObservation;
  provenance: Readonly<{
    status: "verified" | "unendorsed";
    source:
      | typeof CATEGORY_TARGET_PROVENANCE_PROFILE
      | typeof CATEGORY_TARGET_GRID_PROVENANCE_PROFILE
      | typeof CATEGORY_TARGET_AAVE_PROVENANCE_PROFILE
      | typeof CATEGORY_TARGET_VENUS_PROVENANCE_PROFILE;
    proofSha256: string;
  }>;
  observedAt: number;
  observedBlock: number;
  observedBlockHash: string;
}>;

export type CategoryTargetRouteEvidence = Readonly<{
  index: number;
  purpose: BscCategoryTargetRpcRoute["purpose"];
  rpcMethod: BscCategoryTargetRpcRoute["rpcMethod"];
  target?: string;
  storageSlot?: string;
  calldata?: string;
  blockHash?: string;
  requestSha256: string;
  responseSha256?: string;
  resultSha256?: string;
  status?: number;
}>;

export type CategoryTargetObservationFailureCode =
  | "INVALID_INPUT"
  | "RPC_UNAVAILABLE"
  | "RPC_INVALID_RESPONSE"
  | "SNAPSHOT_INCONSISTENT"
  | "CHAIN_ID_MISMATCH"
  | "BLOCK_PIN_FAILED"
  | "EMPTY_TARGET_CODE"
  | "MALFORMED_PROXY_SLOT"
  | "CONFLICTING_PROXY_SLOTS"
  | "EMPTY_BEACON_CODE"
  | "EMPTY_IMPLEMENTATION_CODE"
  | "UNKNOWN_PROXY"
  | "PROVENANCE_READ_FAILED"
  | "PROVENANCE_READ_INVALID";

export type CategoryTargetObservationResult =
  | Readonly<{
      outcome: "verified";
      observation: CategoryTargetObservation;
      /** Alias useful to callers that use value-oriented capability APIs. */
      value: CategoryTargetObservation;
      /** Every target RPC request, including the block pin and proxy resolution. */
      routeEvidence: readonly CategoryTargetRouteEvidence[];
      /** Alias retained for callers that call the evidence collection `reads`. */
      reads: readonly CategoryTargetRouteEvidence[];
    }>
  | Readonly<{
      outcome: "inconclusive";
      code: Exclude<CategoryTargetObservationFailureCode, "INVALID_INPUT">;
      routeEvidence: readonly CategoryTargetRouteEvidence[];
      reads: readonly CategoryTargetRouteEvidence[];
    }>;

export class CategoryTargetObservationError extends Error {
  constructor(
    readonly code: CategoryTargetObservationFailureCode,
    message = "category target observation failed closed",
  ) {
    super(message);
    this.name = "CategoryTargetObservationError";
  }
}

export interface CategoryTargetObservationCapability {
  readonly observe: (
    input: CategoryTargetObservationInput,
  ) => Promise<CategoryTargetObservationResult>;
  readonly capture: (
    input: CategoryTargetObservationInput,
  ) => Promise<CategoryTargetObservationResult>;
  readonly assertObserved: (
    value: unknown,
    input: CategoryTargetObservationInput,
  ) => asserts value is CategoryTargetObservation;
  readonly assertVerified: (
    value: unknown,
    input: CategoryTargetObservationInput,
  ) => asserts value is CategoryTargetObservation;
}

/**
 * Roots are verifier configuration, never mandate data.  Aave is deliberately
 * unset in the default BSC policy because this repository does not currently
 * pin the BSC PoolAddressesProvider deployment.  Supplying one is therefore an
 * explicit verifier deployment decision, not a caller-controlled provenance
 * claim.
 */
export type CategoryTargetProvenanceRoots = Readonly<{
  pancakeV3Factory: string;
  aavePoolAddressesProvider: string | null;
  venusComptroller: string;
}>;

type ParsedTargetInput = Readonly<{
  adapterId: CategoryTargetAdapterId;
  role: string;
  targetAddress: string;
  accountAddress?: string;
  comptrollerAddress?: string;
  borrowMarketAddress?: string;
  anchor?: CategoryTargetAnchor;
  snapshot?: CategorySnapshotHandle;
  provenanceReads: readonly ExpectedTargetProvenanceRead[];
  canonical: string;
}>;

class ObservationFailure extends Error {
  constructor(readonly failureCode: Exclude<CategoryTargetObservationFailureCode, "INVALID_INPUT">) {
    super(failureCode);
    this.name = "ObservationFailure";
  }
}

type RpcEvidence = {
  readonly index: number;
  readonly purpose: BscCategoryTargetRpcRoute["purpose"];
  readonly rpcMethod: BscCategoryTargetRpcRoute["rpcMethod"];
  readonly target?: string;
  readonly storageSlot?: string;
  readonly calldata?: string;
  readonly blockHash?: string;
  readonly requestSha256: string;
  responseSha256?: string;
  resultSha256?: string;
  status?: number;
};

type RpcSuccess = Readonly<{
  result: unknown;
  evidence: RpcEvidence;
}>;

type TrustedProvenance = Readonly<{
  capability: CategoryTargetObservationCapability;
  inputCanonical: string;
  observation: CategoryTargetObservation;
}>;

const trustedObservations = new WeakMap<object, TrustedProvenance>();

/**
 * Creates an isolated, read-only target observer. It never makes a protocol
 * membership claim: successful observations are explicitly interface-only.
 */
export function createCategoryTargetObservationCapability(options: {
  readonly transport: Pick<PinnedHttpsTransport, "request">;
  readonly randomUUID: () => string;
  readonly provenanceRoots: CategoryTargetProvenanceRoots;
  readonly snapshotCapability?: CategorySnapshotCapability;
}): CategoryTargetObservationCapability {
  assertPlainObjectWithAllowedKeys(
    options,
    ["randomUUID", "transport", "provenanceRoots", "snapshotCapability"],
    "target capability options",
  );
  const transportValue = readDataProperty(options, "transport");
  const randomUUIDValue = readDataProperty(options, "randomUUID");
  const provenanceRoots = parseProvenanceRoots(
    readDataProperty(options, "provenanceRoots"),
  );
  const snapshotCapabilityValue = Object.hasOwn(options, "snapshotCapability")
    ? readDataProperty(options, "snapshotCapability")
    : undefined;
  const snapshotCapabilityCandidate =
    snapshotCapabilityValue as Partial<CategorySnapshotCapability> | null | undefined;
  if (
    snapshotCapabilityValue !== undefined &&
    (snapshotCapabilityValue === null ||
      typeof snapshotCapabilityValue !== "object" ||
      typeof snapshotCapabilityCandidate?.assertOpaqueActive !== "function" ||
      typeof snapshotCapabilityCandidate.anchorForOpaque !== "function")
  ) {
    throw new CategoryTargetObservationError(
      "INVALID_INPUT",
      "target capability snapshot capability is invalid",
    );
  }
  const snapshotCapability =
    snapshotCapabilityValue as CategorySnapshotCapability | undefined;
  const request = readTransportRequest(transportValue);
  if (typeof randomUUIDValue !== "function") {
    throw new CategoryTargetObservationError(
      "INVALID_INPUT",
      "target capability randomUUID must be a function",
    );
  }

  // Capture callable references before any asynchronous operation. This also
  // prevents later mutation of an options object from changing the capability.
  const capturedTransport = Object.freeze({
    request: (route: BscCategoryTargetRpcRoute) =>
      request.call(transportValue, route),
  });
  const randomUUID = randomUUIDValue as () => string;

  let capability: CategoryTargetObservationCapability;
  const observe = async (
    inputValue: CategoryTargetObservationInput,
  ): Promise<CategoryTargetObservationResult> => {
    const input = parseTargetInput(inputValue, snapshotCapability);
    const evidence: RpcEvidence[] = [];
    try {
      const built = await runTargetObservation({
        input,
        transport: capturedTransport,
        randomUUID,
        provenanceRoots,
        ...(snapshotCapability === undefined ? {} : { snapshotCapability }),
        evidence,
      });
      const routeEvidence = Object.freeze(
        evidence.map((entry) => freezeEvidence(entry)),
      );
      const result = Object.freeze({
        outcome: "verified" as const,
        observation: built.observation,
        value: built.observation,
        routeEvidence,
        reads: routeEvidence,
      });
      trustedObservations.set(built.observation, {
        capability,
        inputCanonical: input.canonical,
        observation: built.observation,
      });
      return result;
    } catch (cause) {
      if (cause instanceof ObservationFailure) {
        const routeEvidence = Object.freeze(
          evidence.map((entry) => freezeEvidence(entry)),
        );
        return Object.freeze({
          outcome: "inconclusive" as const,
          code: cause.failureCode,
          routeEvidence,
          reads: routeEvidence,
        });
      }
      throw cause;
    }
  };

  const assertObserved = (
    value: unknown,
    inputValue: CategoryTargetObservationInput,
  ): asserts value is CategoryTargetObservation => {
    const input = parseTargetInput(inputValue, snapshotCapability);
    const provenance =
      value !== null && typeof value === "object"
        ? trustedObservations.get(value)
        : undefined;
    if (
      provenance === undefined ||
      provenance.capability !== capability ||
      provenance.inputCanonical !== input.canonical ||
      provenance.observation !== value
    ) {
      throw new Error(
        "category target observation lacks verifier-owned provenance for this target",
      );
    }
  };

  capability = Object.freeze({
    observe,
    capture: observe,
    assertObserved,
    assertVerified: assertObserved,
  });
  return capability;
}

async function runTargetObservation(input: {
  readonly input: ParsedTargetInput;
  readonly transport: {
    readonly request: (
      route: BscCategoryTargetRpcRoute,
    ) => Promise<BoundedHttpResponse>;
  };
  readonly randomUUID: () => string;
  readonly provenanceRoots: CategoryTargetProvenanceRoots;
  readonly snapshotCapability?: CategorySnapshotCapability;
  readonly evidence: RpcEvidence[];
}): Promise<Readonly<{ observation: CategoryTargetObservation }>> {
  const suppliedAnchor = input.input.anchor;
  const suppliedSnapshot = input.input.snapshot;
  let anchor: CategoryTargetAnchor;
  const chain = await targetRpc(input, {
    purpose: "chain-id",
    rpcMethod: "eth_chainId",
    params: [],
  });
  if (parseQuantity(chain.result) !== BigInt(BSC_CHAIN_ID)) {
    throw new ObservationFailure("CHAIN_ID_MISMATCH");
  }
  const headResult = await targetRpc(input, {
    purpose: "head-block-number",
    rpcMethod: "eth_blockNumber",
    params: [],
  });
  const head = parseQuantityOrFailure(headResult.result, "BLOCK_PIN_FAILED");
  if (head < BigInt(CATEGORY_TARGET_CONFIRMATION_DEPTH)) {
    throw new ObservationFailure("BLOCK_PIN_FAILED");
  }
  const targetNumber = head - BigInt(CATEGORY_TARGET_CONFIRMATION_DEPTH);
  if (targetNumber > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new ObservationFailure("BLOCK_PIN_FAILED");
  }
  if (suppliedSnapshot !== undefined) {
    if (input.snapshotCapability === undefined) {
      throw new ObservationFailure("BLOCK_PIN_FAILED");
    }
    try {
      anchor = input.snapshotCapability.anchorForOpaque(suppliedSnapshot);
    } catch {
      throw new ObservationFailure("BLOCK_PIN_FAILED");
    }
    if (anchor.number < 0 || anchor.number > Number(targetNumber)) {
      throw new ObservationFailure("BLOCK_PIN_FAILED");
    }
    const blockHex = `0x${anchor.number.toString(16)}`;
    const blockResult = await targetRpc(input, {
      purpose: "block-header",
      rpcMethod: "eth_getBlockByNumber",
      params: [blockHex, false],
      approvedBlockNumber: blockHex,
    });
    const observed = parseBlockAnchor(blockResult.result);
    if (
      observed.number !== anchor.number ||
      observed.hash !== anchor.hash ||
      observed.timestamp !== anchor.timestamp
    ) {
      throw new ObservationFailure("SNAPSHOT_INCONSISTENT");
    }
    anchor = observed;
  } else if (suppliedAnchor !== undefined) {
    // A shared anchor may be older than the current N-2 boundary when the
    // chain head advances during a multi-producer evaluation. It must still
    // retain the required confirmation depth and be re-read canonically.
    if (
      suppliedAnchor.number < 0 ||
      suppliedAnchor.number > Number(targetNumber)
    ) {
      throw new ObservationFailure("BLOCK_PIN_FAILED");
    }
    const blockHex = `0x${suppliedAnchor.number.toString(16)}`;
    const blockResult = await targetRpc(input, {
      purpose: "block-header",
      rpcMethod: "eth_getBlockByNumber",
      params: [blockHex, false],
      approvedBlockNumber: blockHex,
    });
    const observed = parseBlockAnchor(blockResult.result);
    if (
      observed.number !== suppliedAnchor.number ||
      observed.hash !== suppliedAnchor.hash ||
      observed.timestamp !== suppliedAnchor.timestamp
    ) {
      throw new ObservationFailure("SNAPSHOT_INCONSISTENT");
    }
    anchor = observed;
  } else {
    const blockHex = `0x${targetNumber.toString(16)}`;
    const blockResult = await targetRpc(input, {
      purpose: "block-header",
      rpcMethod: "eth_getBlockByNumber",
      params: [blockHex, false],
      approvedBlockNumber: blockHex,
    });
    anchor = parseBlockAnchor(blockResult.result);
    if (anchor.number !== Number(targetNumber)) {
      throw new ObservationFailure("BLOCK_PIN_FAILED");
    }
  }

  const targetCodeResult = await targetRpc(input, {
    purpose: "contract-code",
    rpcMethod: "eth_getCode",
    params: [input.input.targetAddress, {
      blockHash: anchor.hash,
      requireCanonical: true,
    }],
    approvedTargets: [input.input.targetAddress],
    approvedBlockHash: anchor.hash,
  });
  const targetCode = parseHexResult(targetCodeResult.result);
  if (targetCode === "0x") throw new ObservationFailure("EMPTY_TARGET_CODE");
  const runtimeCodeSha256 = hashHexBytes(targetCode);

  const implementationSlot = await targetRpc(input, {
    purpose: "proxy-slot",
    rpcMethod: "eth_getStorageAt",
    params: [
      input.input.targetAddress,
      BSC_CATEGORY_TARGET_IMPLEMENTATION_SLOT,
      { blockHash: anchor.hash, requireCanonical: true },
    ],
    approvedTargets: [input.input.targetAddress],
    approvedStorageSlot: BSC_CATEGORY_TARGET_IMPLEMENTATION_SLOT,
    approvedBlockHash: anchor.hash,
  });
  const beaconSlot = await targetRpc(input, {
    purpose: "proxy-slot",
    rpcMethod: "eth_getStorageAt",
    params: [
      input.input.targetAddress,
      BSC_CATEGORY_TARGET_BEACON_SLOT,
      { blockHash: anchor.hash, requireCanonical: true },
    ],
    approvedTargets: [input.input.targetAddress],
    approvedStorageSlot: BSC_CATEGORY_TARGET_BEACON_SLOT,
    approvedBlockHash: anchor.hash,
  });

  const implementationAddress = parseProxySlot(implementationSlot.result);
  const beaconAddress = parseProxySlot(beaconSlot.result);
  if (implementationAddress !== undefined && beaconAddress !== undefined) {
    throw new ObservationFailure("CONFLICTING_PROXY_SLOTS");
  }

  let proxy: CategoryTargetProxyObservation;
  const allowedReadTargets = new Set<string>([
    input.input.targetAddress,
  ]);
  const delegates = containsDelegateCallOpcode(targetCode);
  if (implementationAddress !== undefined) {
    if (!delegates) {
      throw new ObservationFailure("UNKNOWN_PROXY");
    }
    if (implementationAddress === input.input.targetAddress) {
      throw new ObservationFailure("UNKNOWN_PROXY");
    }
    allowedReadTargets.add(implementationAddress);
    const implementationCodeResult = await targetRpc(input, {
      purpose: "contract-code",
      rpcMethod: "eth_getCode",
      params: [implementationAddress, {
        blockHash: anchor.hash,
        requireCanonical: true,
      }],
      approvedTargets: [implementationAddress],
      approvedBlockHash: anchor.hash,
    });
    const implementationCode = parseHexResult(implementationCodeResult.result);
    if (implementationCode === "0x") {
      throw new ObservationFailure("EMPTY_IMPLEMENTATION_CODE");
    }
    proxy = Object.freeze({
      kind: "eip1967" as const,
      implementationAddress,
      implementationCodeSha256: hashHexBytes(implementationCode),
    });
  } else if (beaconAddress !== undefined) {
    if (!delegates) {
      throw new ObservationFailure("UNKNOWN_PROXY");
    }
    if (beaconAddress === input.input.targetAddress) {
      throw new ObservationFailure("UNKNOWN_PROXY");
    }
    allowedReadTargets.add(beaconAddress);
    const beaconCodeResult = await targetRpc(input, {
      purpose: "contract-code",
      rpcMethod: "eth_getCode",
      params: [beaconAddress, {
        blockHash: anchor.hash,
        requireCanonical: true,
      }],
      approvedTargets: [beaconAddress],
      approvedBlockHash: anchor.hash,
    });
    const beaconCode = parseHexResult(beaconCodeResult.result);
    if (beaconCode === "0x") {
      throw new ObservationFailure("EMPTY_BEACON_CODE");
    }
    const beaconImplementationResult = await targetRpc(input, {
      purpose: "provenance-read",
      rpcMethod: "eth_call",
      params: [
        { to: beaconAddress, data: BSC_CATEGORY_TARGET_BEACON_IMPLEMENTATION_SELECTOR },
        { blockHash: anchor.hash, requireCanonical: true },
      ],
      approvedTargets: [beaconAddress],
      approvedCalldata: BSC_CATEGORY_TARGET_BEACON_IMPLEMENTATION_SELECTOR,
      approvedBlockHash: anchor.hash,
    });
    const resolvedImplementation = parseAddressWord(beaconImplementationResult.result);
    if (resolvedImplementation === undefined) {
      throw new ObservationFailure("UNKNOWN_PROXY");
    }
    if (
      resolvedImplementation === input.input.targetAddress ||
      resolvedImplementation === beaconAddress
    ) {
      throw new ObservationFailure("UNKNOWN_PROXY");
    }
    allowedReadTargets.add(resolvedImplementation);
    const implementationCodeResult = await targetRpc(input, {
      purpose: "contract-code",
      rpcMethod: "eth_getCode",
      params: [resolvedImplementation, {
        blockHash: anchor.hash,
        requireCanonical: true,
      }],
      approvedTargets: [resolvedImplementation],
      approvedBlockHash: anchor.hash,
    });
    const implementationCode = parseHexResult(implementationCodeResult.result);
    if (implementationCode === "0x") {
      throw new ObservationFailure("EMPTY_IMPLEMENTATION_CODE");
    }
    proxy = Object.freeze({
      kind: "beacon" as const,
      beaconAddress,
      beaconCodeSha256: hashHexBytes(beaconCode),
      implementationAddress: resolvedImplementation,
      implementationCodeSha256: hashHexBytes(implementationCode),
    });
  } else {
    if (delegates) {
      throw new ObservationFailure("UNKNOWN_PROXY");
    }
    proxy = Object.freeze({ kind: "none" as const });
  }

  for (const read of input.input.provenanceReads) {
    if (!allowedReadTargets.has(read.to)) {
      throw new ObservationFailure("PROVENANCE_READ_INVALID");
    }
    const result = await targetRpc(input, {
      purpose: "provenance-read",
      rpcMethod: "eth_call",
      params: [
        { to: read.to, data: read.data },
        { blockHash: anchor.hash, requireCanonical: true },
      ],
      approvedTargets: [read.to],
      approvedCalldata: read.data,
      approvedBlockHash: anchor.hash,
    });
    const raw = parseHexResult(result.result);
    if (!isValidProvenanceResult(read.data, raw)) {
      throw new ObservationFailure("PROVENANCE_READ_INVALID");
    }
  }

  // Protocol membership is a second, verifier-owned profile.  The ordinary
  // adapter reads above only establish ABI-shaped interface behaviour and never
  // authorize a protocol claim.
  const protocolProof = await runProtocolProvenance({
    input: input.input,
    transport: input.transport,
    randomUUID: input.randomUUID,
    evidence: input.evidence,
    anchor,
    roots: input.provenanceRoots,
  });

  const finalBlock = await targetRpc(input, {
    purpose: "block-header",
    rpcMethod: "eth_getBlockByNumber",
    params: [`0x${anchor.number.toString(16)}`, false],
    approvedBlockNumber: `0x${anchor.number.toString(16)}`,
  });
  const finalAnchor = parseBlockAnchor(finalBlock.result);
  if (
    finalAnchor.number !== anchor.number ||
    finalAnchor.hash !== anchor.hash ||
    finalAnchor.timestamp !== anchor.timestamp
  ) {
    throw new ObservationFailure("SNAPSHOT_INCONSISTENT");
  }

  const proofMaterial = {
    profile: CATEGORY_TARGET_PROVENANCE_PROFILE,
    adapterId: input.input.adapterId,
    role: input.input.role,
    targetAddress: input.input.targetAddress,
    observedBlock: anchor.number,
    observedBlockHash: anchor.hash,
    observedAt: anchor.timestamp,
    runtimeCodeSha256,
    proxy,
    provenanceReads: input.input.provenanceReads,
    protocolProvenance: protocolProof.material,
    routeEvidence: input.evidence.map((entry) => ({
      purpose: entry.purpose,
      rpcMethod: entry.rpcMethod,
      target: entry.target,
      storageSlot: entry.storageSlot,
      calldata: entry.calldata,
      blockHash: entry.blockHash,
      requestSha256: entry.requestSha256,
      responseSha256: entry.responseSha256,
      resultSha256: entry.resultSha256,
      status: entry.status,
    })),
  };
  const proofSha256 = computeQuoteSha256(canonicalQuoteJson(proofMaterial));
  const provenanceStatus: "verified" | "unendorsed" =
    protocolProof.assurance === "protocol_instance_verified"
      ? "verified"
      : "unendorsed";
  const observation = deepFreeze({
    schema: CATEGORY_TARGET_OBSERVATION_SCHEMA,
    adapterId: input.input.adapterId,
    role: input.input.role,
    targetAddress: input.input.targetAddress,
    assurance: protocolProof.assurance,
    runtimeCodeSha256,
    proxy,
    provenance: {
      status: provenanceStatus,
      source: protocolProof.source,
      proofSha256,
    },
    observedAt: anchor.timestamp,
    observedBlock: anchor.number,
    observedBlockHash: anchor.hash,
  });
  return { observation };
}

type ProtocolProofResult = Readonly<{
  assurance: "protocol_instance_verified" | "interface_only_unendorsed";
  source:
    | typeof CATEGORY_TARGET_PROVENANCE_PROFILE
    | typeof CATEGORY_TARGET_GRID_PROVENANCE_PROFILE
    | typeof CATEGORY_TARGET_AAVE_PROVENANCE_PROFILE
    | typeof CATEGORY_TARGET_VENUS_PROVENANCE_PROFILE;
  material: readonly unknown[];
}>;

async function runProtocolProvenance(input: {
  readonly input: ParsedTargetInput;
  readonly transport: {
    readonly request: (
      route: BscCategoryTargetRpcRoute,
    ) => Promise<BoundedHttpResponse>;
  };
  readonly randomUUID: () => string;
  readonly evidence: RpcEvidence[];
  readonly anchor: CategoryTargetAnchor;
  readonly roots: CategoryTargetProvenanceRoots;
}): Promise<ProtocolProofResult> {
  const target = input.input.targetAddress;
  const material: unknown[] = [];
  const read = async (to: string, data: string): Promise<string> => {
    const result = await targetRpc(
      {
        transport: input.transport,
        randomUUID: input.randomUUID,
        evidence: input.evidence,
      },
      {
        purpose: "provenance-read",
        rpcMethod: "eth_call",
        params: [
          { to, data },
          { blockHash: input.anchor.hash, requireCanonical: true },
        ],
        approvedTargets: [to],
        approvedCalldata: data,
        approvedBlockHash: input.anchor.hash,
      },
    );
    const raw = parseHexResult(result.result);
    if (!isValidProvenanceResult(data, raw)) {
      throw new ObservationFailure("PROVENANCE_READ_INVALID");
    }
    material.push({ to, data, result: raw });
    return raw;
  };

  switch (input.input.adapterId) {
    case GRID_ADAPTER_ID: {
      const raw = await read(target, SELECTOR_FACTORY);
      const observedFactory = parseAddressWord(raw);
      const expectedFactory = input.roots.pancakeV3Factory;
      return {
        assurance:
          observedFactory === expectedFactory
            ? "protocol_instance_verified"
            : "interface_only_unendorsed",
        source:
          observedFactory === expectedFactory
            ? CATEGORY_TARGET_GRID_PROVENANCE_PROFILE
            : CATEGORY_TARGET_PROVENANCE_PROFILE,
        material,
      };
    }
    case HEALTH_ADAPTER_ID: {
      const provider = input.roots.aavePoolAddressesProvider;
      if (provider === null) {
        // No Aave BSC provider is pinned in the current verifier policy.  Do
        // not turn a caller-supplied address into an authority claim.
        return {
          assurance: "interface_only_unendorsed",
          source: CATEGORY_TARGET_PROVENANCE_PROFILE,
          material: Object.freeze([{ status: "provider-unpinned" }]),
        };
      }
      const raw = await read(provider, SELECTOR_AAVE_GET_POOL);
      const observedPool = parseAddressWord(raw);
      return {
        assurance:
          observedPool === target
            ? "protocol_instance_verified"
            : "interface_only_unendorsed",
        source:
          observedPool === target
            ? CATEGORY_TARGET_AAVE_PROVENANCE_PROFILE
            : CATEGORY_TARGET_PROVENANCE_PROFILE,
        material,
      };
    }
    case VENUS_HEALTH_ADAPTER_ID: {
      const comptroller = input.roots.venusComptroller;
      if (input.input.role === "comptroller") {
        const market = input.input.borrowMarketAddress;
        if (market === undefined) {
          return {
            assurance: "interface_only_unendorsed",
            source: CATEGORY_TARGET_PROVENANCE_PROFILE,
            material: Object.freeze([{ status: "borrow-market-unbound" }]),
          };
        }
        const raw = await read(
          target,
          addressCalldata(SELECTOR_MARKETS, market),
        );
        const verified =
          target === comptroller && decodeUint256(raw, 0) === 1n;
        return {
          assurance: verified
            ? "protocol_instance_verified"
            : "interface_only_unendorsed",
          source: verified
            ? CATEGORY_TARGET_VENUS_PROVENANCE_PROFILE
            : CATEGORY_TARGET_PROVENANCE_PROFILE,
          material,
        };
      }
      if (input.input.role === "borrowMarket") {
        const raw = await read(target, SELECTOR_COMPTROLLER);
        const observedComptroller = parseAddressWord(raw);
        const boundComptroller = input.input.comptrollerAddress;
        const relationshipMatches =
          observedComptroller === comptroller &&
          (boundComptroller === undefined || boundComptroller === comptroller);
        return {
          assurance:
            relationshipMatches
              ? "protocol_instance_verified"
              : "interface_only_unendorsed",
          source:
            relationshipMatches
              ? CATEGORY_TARGET_VENUS_PROVENANCE_PROFILE
              : CATEGORY_TARGET_PROVENANCE_PROFILE,
          material,
        };
      }
      return {
        assurance: "interface_only_unendorsed",
        source: CATEGORY_TARGET_PROVENANCE_PROFILE,
        material,
      };
    }
    case YIELD_ADAPTER_ID:
      return {
        assurance: "interface_only_unendorsed",
        source: CATEGORY_TARGET_PROVENANCE_PROFILE,
        material: Object.freeze([{ status: "no-approved-registry" }]),
      };
  }
}

async function targetRpc(
  context: {
    readonly transport: {
      readonly request: (
        route: BscCategoryTargetRpcRoute,
      ) => Promise<BoundedHttpResponse>;
    };
    readonly randomUUID: () => string;
    readonly evidence: RpcEvidence[];
  },
  request: TargetRpcRequest,
): Promise<RpcSuccess> {
  const id = `category-target-${safeId(context.randomUUID())}`;
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id,
    method: request.rpcMethod,
    params: request.params,
  });
  const route = deepFreeze(makeTargetRoute(request, body));
  const evidence: RpcEvidence = {
    index: context.evidence.length,
    purpose: route.purpose,
    rpcMethod: route.rpcMethod,
    ...(route.purpose === "contract-code" ||
    route.purpose === "proxy-slot" ||
    route.purpose === "provenance-read"
      ? { target: route.approvedTargets[0] }
      : {}),
    ...(route.purpose === "proxy-slot"
      ? { storageSlot: route.approvedStorageSlot }
      : {}),
    ...(route.purpose === "provenance-read"
      ? { calldata: route.approvedCalldata }
      : {}),
    ...(route.purpose === "contract-code" ||
    route.purpose === "proxy-slot" ||
    route.purpose === "provenance-read"
      ? { blockHash: route.approvedBlockHash }
      : {}),
    requestSha256: computeQuoteSha256(body),
  };
  context.evidence.push(evidence);

  let response: BoundedHttpResponse;
  try {
    response = await context.transport.request(route);
  } catch (cause) {
    if (cause instanceof TransportError && cause.code === "RPC_METHOD_NOT_ALLOWED") {
      throw new ObservationFailure("RPC_INVALID_RESPONSE");
    }
    throw new ObservationFailure("RPC_UNAVAILABLE");
  }
  evidence.status = response.status;
  if (response.status !== 200) throw new ObservationFailure("RPC_UNAVAILABLE");
  if (!(response.body instanceof Uint8Array)) {
    throw new ObservationFailure("RPC_INVALID_RESPONSE");
  }
  const actualResponseSha256 = computeQuoteSha256(response.body);
  if (
    typeof response.responseSha256 !== "string" ||
    response.responseSha256 !== actualResponseSha256
  ) {
    throw new ObservationFailure("RPC_INVALID_RESPONSE");
  }
  evidence.responseSha256 = actualResponseSha256;
  let parsed: unknown;
  try {
    parsed = parseJsonResponse(response);
  } catch {
    throw new ObservationFailure("RPC_INVALID_RESPONSE");
  }
  if (
    !isRecord(parsed) ||
    typeof parsed.jsonrpc !== "string" ||
    parsed.jsonrpc !== "2.0" ||
    parsed.id !== id
  ) {
    throw new ObservationFailure("RPC_INVALID_RESPONSE");
  }
  if (Object.hasOwn(parsed, "error")) {
    if (!hasExactKeys(parsed, ["error", "id", "jsonrpc"]) || !isRecord(parsed.error)) {
      throw new ObservationFailure("RPC_INVALID_RESPONSE");
    }
    const message =
      typeof parsed.error.message === "string"
        ? parsed.error.message.toLowerCase()
        : "";
    throw new ObservationFailure(
      isCanonicalityMessage(message)
        ? "SNAPSHOT_INCONSISTENT"
        : "RPC_INVALID_RESPONSE",
    );
  }
  if (
    !hasExactKeys(parsed, ["id", "jsonrpc", "result"]) ||
    !("result" in parsed)
  ) {
    throw new ObservationFailure("RPC_INVALID_RESPONSE");
  }
  let resultSha256: string;
  try {
    resultSha256 = computeQuoteSha256(canonicalQuoteJson(parsed.result));
  } catch {
    throw new ObservationFailure("RPC_INVALID_RESPONSE");
  }
  evidence.resultSha256 = resultSha256;
  return Object.freeze({ result: parsed.result, evidence: freezeEvidence(evidence) });
}

type TargetRpcRequest =
  | Readonly<{
      purpose: "chain-id";
      rpcMethod: "eth_chainId";
      params: readonly [];
    }>
  | Readonly<{
      purpose: "head-block-number";
      rpcMethod: "eth_blockNumber";
      params: readonly [];
    }>
  | Readonly<{
      purpose: "block-header";
      rpcMethod: "eth_getBlockByNumber";
      params: readonly [string, false];
      approvedBlockNumber: string;
    }>
  | Readonly<{
      purpose: "contract-code";
      rpcMethod: "eth_getCode";
      params: readonly [string, Readonly<{ blockHash: string; requireCanonical: true }>];
      approvedTargets: readonly [string];
      approvedBlockHash: string;
    }>
  | Readonly<{
      purpose: "proxy-slot";
      rpcMethod: "eth_getStorageAt";
      params: readonly [string, typeof BSC_CATEGORY_TARGET_IMPLEMENTATION_SLOT | typeof BSC_CATEGORY_TARGET_BEACON_SLOT, Readonly<{ blockHash: string; requireCanonical: true }>];
      approvedTargets: readonly [string];
      approvedStorageSlot:
        | typeof BSC_CATEGORY_TARGET_IMPLEMENTATION_SLOT
        | typeof BSC_CATEGORY_TARGET_BEACON_SLOT;
      approvedBlockHash: string;
    }>
  | Readonly<{
      purpose: "provenance-read";
      rpcMethod: "eth_call";
      params: readonly [Readonly<{ to: string; data: string }>, Readonly<{ blockHash: string; requireCanonical: true }>];
      approvedTargets: readonly [string];
      approvedCalldata: string;
      approvedBlockHash: string;
    }>;

function makeTargetRoute(
  request: TargetRpcRequest,
  body: string,
): BscCategoryTargetRpcRoute {
  const common = {
    kind: "bsc-category-target-rpc" as const,
    method: "POST" as const,
    url: BSC_MAINNET_RPC_ORIGIN,
    body,
  };
  switch (request.purpose) {
    case "chain-id":
      return { ...common, purpose: "chain-id", rpcMethod: "eth_chainId" };
    case "head-block-number":
      return {
        ...common,
        purpose: "head-block-number",
        rpcMethod: "eth_blockNumber",
      };
    case "block-header":
      return {
        ...common,
        purpose: request.purpose,
        rpcMethod: request.rpcMethod,
        approvedBlockNumber: request.approvedBlockNumber,
      };
    case "contract-code":
      return {
        ...common,
        purpose: request.purpose,
        rpcMethod: request.rpcMethod,
        approvedTargets: request.approvedTargets,
        approvedBlockHash: request.approvedBlockHash,
      };
    case "proxy-slot":
      return {
        ...common,
        purpose: request.purpose,
        rpcMethod: request.rpcMethod,
        approvedTargets: request.approvedTargets,
        approvedStorageSlot: request.approvedStorageSlot,
        approvedBlockHash: request.approvedBlockHash,
      };
    case "provenance-read":
      return {
        ...common,
        purpose: request.purpose,
        rpcMethod: request.rpcMethod,
        approvedTargets: request.approvedTargets,
        approvedCalldata: request.approvedCalldata,
        approvedBlockHash: request.approvedBlockHash,
      };
  }
}

function parseTargetInput(
  value: unknown,
  snapshotCapability?: CategorySnapshotCapability,
): ParsedTargetInput {
  const allowed = [
    "accountAddress",
    "adapterId",
    "anchor",
    "blockHash",
    "blockNumber",
    "blockTimestamp",
    "borrowMarketAddress",
    "comptrollerAddress",
    "expectedProvenance",
    "provenance",
    "provenanceReads",
    "role",
    "snapshot",
    "target",
    "targetAddress",
  ] as const;
  assertPlainObjectWithAllowedKeys(value, allowed, "target observation input");
  const object = value as Record<string, unknown>;
  const adapterId = object.adapterId;
  const role = object.role;
  if (
    typeof adapterId !== "string" ||
    !(REGISTERED_CATEGORY_ADAPTER_IDS as readonly string[]).includes(adapterId) ||
    typeof role !== "string" ||
    !IDENTIFIER_RE.test(role)
  ) {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
  const targetAddress = chooseCanonicalAddress(
    object.targetAddress,
    object.target,
    "target address",
  );
  const accountAddress =
    object.accountAddress === undefined
      ? undefined
      : chooseCanonicalAddress(
          object.accountAddress,
          undefined,
          "health account address",
        );
  const comptrollerAddress =
    object.comptrollerAddress === undefined
      ? undefined
      : chooseCanonicalAddress(
          object.comptrollerAddress,
          undefined,
          "Venus Comptroller address",
        );
  const borrowMarketAddress =
    object.borrowMarketAddress === undefined
      ? undefined
      : chooseCanonicalAddress(
          object.borrowMarketAddress,
          undefined,
          "Venus borrow market address",
        );
  validateRelatedTargetBindings({
    adapterId: adapterId as CategoryTargetAdapterId,
    role,
    targetAddress,
    ...(comptrollerAddress === undefined ? {} : { comptrollerAddress }),
    ...(borrowMarketAddress === undefined ? {} : { borrowMarketAddress }),
  });
  const parsedAnchor = parseInputAnchor(object, snapshotCapability);
  const provenanceValues = [
    object.provenance,
    object.provenanceReads,
    object.expectedProvenance,
  ].filter((entry) => entry !== undefined);
  if (provenanceValues.some((entry) => !Array.isArray(entry))) {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
  const expectedReads = deriveTargetReadProfile({
    adapterId: adapterId as CategoryTargetAdapterId,
    role,
    targetAddress,
    ...(accountAddress === undefined ? {} : { accountAddress }),
    ...(comptrollerAddress === undefined ? {} : { comptrollerAddress }),
    ...(borrowMarketAddress === undefined ? {} : { borrowMarketAddress }),
  });
  const provenanceArrays = provenanceValues as unknown as readonly (readonly unknown[])[];
  const suppliedReadSets = provenanceArrays.map((entry) =>
    Object.freeze(parseProvenanceReads(entry)),
  );
  const expectedReadsCanonical = canonicalQuoteJson(expectedReads);
  if (
    suppliedReadSets.some(
      (entry) => canonicalQuoteJson(entry) !== expectedReadsCanonical,
    )
  ) {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
  const provenanceReads = expectedReads;
  const canonical = canonicalQuoteJson({
    adapterId,
    role,
    targetAddress,
    ...(accountAddress === undefined ? {} : { accountAddress }),
    ...(comptrollerAddress === undefined ? {} : { comptrollerAddress }),
    ...(borrowMarketAddress === undefined ? {} : { borrowMarketAddress }),
    ...(parsedAnchor.anchor === undefined ? {} : { anchor: parsedAnchor.anchor }),
    ...(parsedAnchor.snapshot === undefined ? {} : { snapshot: parsedAnchor.snapshot }),
    provenanceReads,
  });
  return Object.freeze({
    adapterId: adapterId as CategoryTargetAdapterId,
    role,
    targetAddress,
    ...(accountAddress === undefined ? {} : { accountAddress }),
    ...(comptrollerAddress === undefined ? {} : { comptrollerAddress }),
    ...(borrowMarketAddress === undefined ? {} : { borrowMarketAddress }),
    ...(parsedAnchor.anchor === undefined ? {} : { anchor: parsedAnchor.anchor }),
    ...(parsedAnchor.snapshot === undefined ? {} : { snapshot: parsedAnchor.snapshot }),
    provenanceReads,
    canonical,
  });
}

function parseProvenanceRoots(value: unknown): CategoryTargetProvenanceRoots {
  assertPlainObjectWithAllowedKeys(
    value,
    ["aavePoolAddressesProvider", "pancakeV3Factory", "venusComptroller"],
    "target provenance roots",
  );
  const object = value as Record<string, unknown>;
  const aave =
    object.aavePoolAddressesProvider === null
      ? null
      : chooseCanonicalAddress(
          object.aavePoolAddressesProvider,
          undefined,
          "Aave PoolAddressesProvider",
        );
  const pancake = chooseCanonicalAddress(
    object.pancakeV3Factory,
    undefined,
    "Pancake V3 factory",
  );
  const venus = chooseCanonicalAddress(
    object.venusComptroller,
    undefined,
    "Venus Comptroller",
  );
  return Object.freeze({
    pancakeV3Factory: pancake,
    aavePoolAddressesProvider: aave,
    venusComptroller: venus,
  });
}

function parseInputAnchor(
  object: Record<string, unknown>,
  snapshotCapability?: CategorySnapshotCapability,
): { anchor?: CategoryTargetAnchor; snapshot?: CategorySnapshotHandle } {
  const hasAnchor = Object.hasOwn(object, "anchor");
  const hasSnapshot = Object.hasOwn(object, "snapshot");
  if (hasAnchor && hasSnapshot) {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
  const anchorValue = hasAnchor ? object.anchor : object.snapshot;
  if ((hasAnchor || hasSnapshot) && anchorValue === undefined) {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
  const aliasesPresent =
    object.blockNumber !== undefined ||
    object.blockHash !== undefined ||
    object.blockTimestamp !== undefined;
  if (anchorValue !== undefined && aliasesPresent) {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
  if (anchorValue !== undefined) {
    if (hasSnapshot && snapshotCapability !== undefined) {
      const assertSnapshotActive:
        CategorySnapshotCapability["assertOpaqueActive"] =
        snapshotCapability.assertOpaqueActive;
      try {
        assertSnapshotActive(anchorValue);
      } catch {
        throw new CategoryTargetObservationError("INVALID_INPUT");
      }
      const snapshot = anchorValue as CategorySnapshotHandle;
      return {
        snapshot,
        anchor: snapshotCapability.anchorForOpaque(snapshot),
      };
    }
    if (hasSnapshot && snapshotCapability === undefined) {
      return { anchor: parseAnchor(anchorValue) };
    }
    if (snapshotCapability !== undefined) {
      throw new CategoryTargetObservationError("INVALID_INPUT");
    }
    return { anchor: parseAnchor(anchorValue) };
  }
  if (!aliasesPresent) return {};
  if (
    object.blockNumber === undefined ||
    object.blockHash === undefined ||
    object.blockTimestamp === undefined
  ) {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
  if (snapshotCapability !== undefined) {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
  return {
    anchor: parseAnchor({
      number: object.blockNumber,
      hash: object.blockHash,
      timestamp: object.blockTimestamp,
    }),
  };
}

function parseAnchor(value: unknown): CategoryTargetAnchor {
  assertPlainObjectWithAllowedKeys(
    value,
    ["hash", "number", "timestamp"],
    "target block anchor",
  );
  const object = value as Record<string, unknown>;
  if (
    typeof object.number !== "number" ||
    !Number.isSafeInteger(object.number) ||
    object.number < 0 ||
    typeof object.timestamp !== "number" ||
    !Number.isSafeInteger(object.timestamp) ||
    object.timestamp <= 0 ||
    typeof object.hash !== "string" ||
    !BLOCK_HASH_RE.test(object.hash)
  ) {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
  return Object.freeze({
    number: object.number,
    hash: object.hash,
    timestamp: object.timestamp,
  });
}

function parseProvenanceReads(value: readonly unknown[]): readonly ExpectedTargetProvenanceRead[] {
  if (value.length > 32) throw new CategoryTargetObservationError("INVALID_INPUT");
  const labels = new Set<string>();
  return value.map((entry) => {
    assertPlainObjectWithAllowedKeys(
      entry,
      ["calldata", "data", "label", "selector", "target", "to"],
      "target provenance read",
    );
    const object = entry as Record<string, unknown>;
    if (
      typeof object.label !== "string" ||
      !IDENTIFIER_RE.test(object.label) ||
      labels.has(object.label)
    ) {
      throw new CategoryTargetObservationError("INVALID_INPUT");
    }
    labels.add(object.label);
    const to = chooseCanonicalAddress(object.to, object.target, "provenance read target");
    const data = chooseCanonicalData(
      object.data,
      object.selector,
      object.calldata,
    );
    if (!isFixedProvenanceCalldata(data)) {
      throw new CategoryTargetObservationError("INVALID_INPUT");
    }
    return Object.freeze({ label: object.label, to, data });
  });
}

function deriveTargetReadProfile(input: {
  readonly adapterId: CategoryTargetAdapterId;
  readonly role: string;
  readonly targetAddress: string;
  readonly accountAddress?: string;
  readonly comptrollerAddress?: string;
  readonly borrowMarketAddress?: string;
}): readonly ExpectedTargetProvenanceRead[] {
  const read = (label: string, data: string): ExpectedTargetProvenanceRead =>
    Object.freeze({ label, to: input.targetAddress, data });
  switch (input.adapterId) {
    case GRID_ADAPTER_ID:
      requireTargetRole(input.role, "pool");
      requireNoAccountAddress(input.accountAddress);
      return Object.freeze([read("slot0", SELECTOR_SLOT0)]);
    case YIELD_ADAPTER_ID:
      requireTargetRole(input.role, "vault");
      requireNoAccountAddress(input.accountAddress);
      return Object.freeze([
        read("totalAssets", SELECTOR_TOTAL_ASSETS),
        read("totalSupply", SELECTOR_TOTAL_SUPPLY),
      ]);
    case HEALTH_ADAPTER_ID: {
      requireTargetRole(input.role, "pool");
      const accountAddress = requireAccountAddress(input.accountAddress);
      return Object.freeze([
        read(
          "getUserAccountData",
          addressCalldata(SELECTOR_GET_USER_ACCOUNT_DATA, accountAddress),
        ),
      ]);
    }
    case VENUS_HEALTH_ADAPTER_ID: {
      const accountAddress = requireAccountAddress(input.accountAddress);
      if (input.role === "comptroller") {
        return Object.freeze([
          read(
            "getAccountLiquidity",
            addressCalldata(SELECTOR_GET_ACCOUNT_LIQUIDITY, accountAddress),
          ),
          read(
            "getAssetsIn",
            addressCalldata(SELECTOR_GET_ASSETS_IN, accountAddress),
          ),
        ]);
      }
      if (input.role === "borrowMarket") {
        return Object.freeze([
          read(
            "borrowBalanceStored",
            addressCalldata(SELECTOR_BORROW_BALANCE_STORED, accountAddress),
          ),
        ]);
      }
      throw new CategoryTargetObservationError("INVALID_INPUT");
    }
  }
}

function validateRelatedTargetBindings(input: {
  readonly adapterId: CategoryTargetAdapterId;
  readonly role: string;
  readonly targetAddress: string;
  readonly comptrollerAddress?: string;
  readonly borrowMarketAddress?: string;
}): void {
  if (input.adapterId !== VENUS_HEALTH_ADAPTER_ID) {
    if (
      input.comptrollerAddress !== undefined ||
      input.borrowMarketAddress !== undefined
    ) {
      throw new CategoryTargetObservationError("INVALID_INPUT");
    }
    return;
  }
  if (
    input.role === "comptroller" &&
    input.comptrollerAddress !== undefined &&
    input.comptrollerAddress !== input.targetAddress
  ) {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
  if (
    input.role === "borrowMarket" &&
    input.borrowMarketAddress !== undefined &&
    input.borrowMarketAddress !== input.targetAddress
  ) {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
}

function requireTargetRole(actual: string, expected: string): void {
  if (actual !== expected) {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
}

function requireAccountAddress(value: string | undefined): string {
  if (value === undefined) {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
  return value;
}

function requireNoAccountAddress(value: string | undefined): void {
  if (value !== undefined) {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
}

function chooseCanonicalAddress(
  primary: unknown,
  alias: unknown,
  label: string,
): string {
  if (primary !== undefined && alias !== undefined && primary !== alias) {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
  const value = primary ?? alias;
  if (
    typeof value !== "string" ||
    !ADDRESS_RE.test(value) ||
    value === ZERO_ADDRESS
  ) {
    throw new CategoryTargetObservationError("INVALID_INPUT", `${label} is invalid`);
  }
  return value;
}

function chooseCanonicalData(...aliases: readonly unknown[]): string {
  const supplied = aliases.filter((value) => value !== undefined);
  if (
    supplied.length < 1 ||
    supplied.some((value) => value !== supplied[0])
  ) {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
  const value = supplied[0];
  if (typeof value !== "string" || !NONEMPTY_HEX_BYTES_RE.test(value)) {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
  return value;
}

function isFixedProvenanceCalldata(value: string): boolean {
  const selector = value.slice(0, 10);
  if (!FIXED_PROVENANCE_SELECTOR_SET.has(selector)) return false;
  if (
    selector === "0x3850c7bd" ||
    selector === "0xc45a0155" ||
    selector === "0xd5f39488" ||
    selector === "0x01e1d114" ||
    selector === "0x18160ddd"
  ) {
    return value.length === 10;
  }
  if (selector === "0x6352211e") {
    return value.length === 74 && /^[0-9a-f]{64}$/.test(value.slice(10));
  }
  return value.length === 74 && /^0{24}[0-9a-f]{40}$/.test(value.slice(10));
}

function isValidProvenanceResult(calldata: string, data: string): boolean {
  const selector = calldata.slice(0, 10);
  switch (selector) {
    case SELECTOR_SLOT0: {
      const words = wordCount(data);
      const sqrtPriceX96 = decodeUint256(data, 0);
      const tick = decodeInt24(data, 1);
      return (
        words !== undefined &&
        words >= 2 &&
        sqrtPriceX96 !== undefined &&
        sqrtPriceX96 <= UINT160_MAX &&
        sqrtPriceX96 >= V3_MIN_SQRT_RATIO &&
        sqrtPriceX96 <= V3_MAX_SQRT_RATIO &&
        tick !== undefined &&
        tick >= V3_MIN_TICK &&
        tick <= V3_MAX_TICK
      );
    }
    case SELECTOR_TOTAL_ASSETS:
    case SELECTOR_TOTAL_SUPPLY:
      return wordCount(data) === 1 && decodeUint256(data, 0) !== undefined;
    case SELECTOR_GET_USER_ACCOUNT_DATA:
      return (
        wordCount(data) === 6 &&
        decodeUint256(data, 0) !== undefined &&
        decodeUint256(data, 1) !== undefined &&
        decodeUint256(data, 5) !== undefined
      );
    case SELECTOR_GET_ACCOUNT_LIQUIDITY:
      return (
        wordCount(data) === 3 &&
        decodeUint256(data, 0) !== undefined &&
        decodeUint256(data, 1) !== undefined &&
        decodeUint256(data, 2) !== undefined
      );
    case SELECTOR_GET_ASSETS_IN:
      return decodeDynamicArrayLength(data) !== undefined;
    case SELECTOR_BORROW_BALANCE_STORED: {
      const words = wordCount(data);
      return (
        words !== undefined &&
        words >= 1 &&
        decodeUint256(data, 0) !== undefined
      );
    }
    case SELECTOR_MARKETS: {
      const words = wordCount(data);
      const listed = decodeUint256(data, 0);
      return words !== undefined && words >= 1 && (listed === 0n || listed === 1n);
    }
    case "0xc45a0155":
    case SELECTOR_COMPTROLLER:
    case SELECTOR_AAVE_GET_POOL:
    case "0xd5f39488":
    case "0x6352211e":
    case BSC_CATEGORY_TARGET_BEACON_IMPLEMENTATION_SELECTOR:
      return wordCount(data) === 1 && parseAddressWord(data) !== undefined;
    default:
      return false;
  }
}

function parseQuantity(value: unknown): bigint {
  if (typeof value !== "string" || !QUANTITY_RE.test(value)) {
    throw new ObservationFailure("BLOCK_PIN_FAILED");
  }
  return BigInt(value);
}

function parseQuantityOrFailure(value: unknown, code: "BLOCK_PIN_FAILED"): bigint {
  if (typeof value !== "string" || !QUANTITY_RE.test(value)) {
    throw new ObservationFailure(code);
  }
  return BigInt(value);
}

function parseBlockAnchor(value: unknown): CategoryTargetAnchor {
  if (
    !isRecord(value) ||
    typeof value.number !== "string" ||
    typeof value.hash !== "string" ||
    typeof value.timestamp !== "string" ||
    !QUANTITY_RE.test(value.number) ||
    !BLOCK_HASH_RE.test(value.hash) ||
    !QUANTITY_RE.test(value.timestamp)
  ) {
    throw new ObservationFailure("BLOCK_PIN_FAILED");
  }
  const number = BigInt(value.number);
  const timestamp = BigInt(value.timestamp);
  if (
    number > BigInt(Number.MAX_SAFE_INTEGER) ||
    timestamp > BigInt(Number.MAX_SAFE_INTEGER) ||
    timestamp <= 0n
  ) {
    throw new ObservationFailure("BLOCK_PIN_FAILED");
  }
  return Object.freeze({
    number: Number(number),
    hash: value.hash,
    timestamp: Number(timestamp),
  });
}

function parseHexResult(value: unknown): string {
  if (typeof value !== "string" || !HEX_BYTES_RE.test(value)) {
    throw new ObservationFailure("RPC_INVALID_RESPONSE");
  }
  return value;
}

function parseProxySlot(value: unknown): string | undefined {
  if (typeof value !== "string" || !/^0x[0-9a-f]{64}$/.test(value)) {
    throw new ObservationFailure("MALFORMED_PROXY_SLOT");
  }
  if (/^0x0{64}$/.test(value)) return undefined;
  if (!/^0{24}[0-9a-f]{40}$/.test(value.slice(2))) {
    throw new ObservationFailure("MALFORMED_PROXY_SLOT");
  }
  const address = `0x${value.slice(-40)}`;
  if (address === ZERO_ADDRESS) throw new ObservationFailure("MALFORMED_PROXY_SLOT");
  return address;
}

function parseAddressWord(value: unknown): string | undefined {
  if (typeof value !== "string" || !/^0x[0-9a-f]{64}$/.test(value)) return undefined;
  if (!/^0{24}[0-9a-f]{40}$/.test(value.slice(2))) return undefined;
  const address = `0x${value.slice(-40)}`;
  return address === ZERO_ADDRESS ? undefined : address;
}

function hashHexBytes(value: string): string {
  return createHash("sha256").update(Buffer.from(value.slice(2), "hex")).digest("hex");
}

/** A non-EIP-1967 delegate proxy cannot be endorsed by this capability. */
function containsDelegateCallOpcode(value: string): boolean {
  const bytes = Buffer.from(value.slice(2), "hex");
  for (let index = 0; index < bytes.length; index += 1) {
    const opcode = bytes[index];
    if (opcode === 0xf2 || opcode === 0xf4) return true;
    // Skip PUSH data so an embedded byte does not masquerade as an opcode.
    if (opcode !== undefined && opcode >= 0x60 && opcode <= 0x7f) {
      index += opcode - 0x5f;
    }
  }
  return false;
}

function safeId(value: unknown): string {
  if (typeof value !== "string" || value.length < 1 || value.length > 96) {
    throw new ObservationFailure("RPC_INVALID_RESPONSE");
  }
  return value;
}

function freezeEvidence(value: RpcEvidence): CategoryTargetRouteEvidence {
  return Object.freeze({ ...value });
}

function isCanonicalityMessage(message: string): boolean {
  return [
    "header not found",
    "missing trie node",
    "unknown block",
    "not canonical",
    "canonical hash",
  ].some((fragment) => message.includes(fragment));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const sorted = [...expected].sort();
  return actual.length === sorted.length && actual.every((key, index) => key === sorted[index]);
}

function assertPlainObjectWithAllowedKeys(
  value: unknown,
  keys: readonly string[],
  label: string,
): asserts value is object {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new CategoryTargetObservationError("INVALID_INPUT", `${label} must be a plain object`);
  }
  const actual = Reflect.ownKeys(value);
  if (
    actual.some((key) => typeof key !== "string" || !keys.includes(key)) ||
    actual.length !== new Set(keys.filter((key) => Object.hasOwn(value, key))).size
  ) {
    throw new CategoryTargetObservationError("INVALID_INPUT", `${label} contains unsupported fields`);
  }
  for (const key of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw new CategoryTargetObservationError("INVALID_INPUT", `${label} must contain data properties`);
    }
  }
}

function assertExactDataObject(
  value: unknown,
  keys: readonly string[],
  label: string,
): asserts value is object {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw new CategoryTargetObservationError("INVALID_INPUT", `${label} must be a plain object`);
  }
  const actual = Reflect.ownKeys(value);
  if (
    actual.length !== keys.length ||
    actual.some((key) => typeof key !== "string" || !keys.includes(key))
  ) {
    throw new CategoryTargetObservationError("INVALID_INPUT", `${label} contains unsupported fields`);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw new CategoryTargetObservationError("INVALID_INPUT", `${label} must contain data properties`);
    }
  }
}

function readDataProperty(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor)) {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
  return descriptor.value;
}

function readTransportRequest(
  value: unknown,
): Pick<PinnedHttpsTransport, "request">["request"] {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new CategoryTargetObservationError(
      "INVALID_INPUT",
      "target capability transport must be an object",
    );
  }

  let ownKeys: readonly PropertyKey[];
  try {
    ownKeys = Reflect.ownKeys(value);
  } catch {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
  const ownDescriptor = Object.getOwnPropertyDescriptor(value, "request");
  if (ownDescriptor !== undefined) {
    if (
      ownKeys.length !== 1 ||
      ownKeys[0] !== "request" ||
      !("value" in ownDescriptor) ||
      ownDescriptor.enumerable !== true ||
      typeof ownDescriptor.value !== "function"
    ) {
      throw new CategoryTargetObservationError(
        "INVALID_INPUT",
        "target capability transport request must be an enumerable data property",
      );
    }
    return ownDescriptor.value as Pick<PinnedHttpsTransport, "request">["request"];
  }
  if (ownKeys.length !== 0) {
    throw new CategoryTargetObservationError(
      "INVALID_INPUT",
      "target capability transport contains unsupported fields",
    );
  }

  let prototype: object | null;
  try {
    prototype = Object.getPrototypeOf(value);
  } catch {
    throw new CategoryTargetObservationError("INVALID_INPUT");
  }
  while (prototype !== null && prototype !== Object.prototype) {
    const descriptor = Object.getOwnPropertyDescriptor(prototype, "request");
    if (descriptor !== undefined) {
      if (!("value" in descriptor) || typeof descriptor.value !== "function") {
        throw new CategoryTargetObservationError(
          "INVALID_INPUT",
          "target capability transport request must be a data method",
        );
      }
      return descriptor.value as Pick<PinnedHttpsTransport, "request">["request"];
    }
    prototype = Object.getPrototypeOf(prototype);
  }
  throw new CategoryTargetObservationError(
    "INVALID_INPUT",
    "target capability transport request must be a function",
  );
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
