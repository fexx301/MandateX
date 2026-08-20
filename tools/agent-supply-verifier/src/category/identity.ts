import { createHash } from "node:crypto";

import { canonicalQuoteJson, computeQuoteSha256 } from "../quotes/protocol.js";
import {
  BSC_MAINNET,
  verifyErc8004Ownership,
  type Erc8004Result,
  type Erc8004SharedAnchor,
} from "../sources/erc8004.js";
import { parseJsonResponse } from "../transport/http.js";
import type {
  BoundedHttpResponse,
  TransportRoute,
} from "../transport/http.js";
import type {
  CategorySnapshotCapability,
  CategorySnapshotHandle,
} from "./rpc.js";

export const CATEGORY_CANDIDATE_IDENTITY_SCHEMA =
  "mandatex.marketplace.category-candidate-identity.v1" as const;
export const CATEGORY_CANDIDATE_IDENTITY_PROFILE =
  "mandatex.agent-supply.erc8004-owner-of-capability.v1" as const;

export type CategoryCandidateIdentitySelector = Readonly<{
  chainId: 56;
  tokenId: string;
}>;

export type VerifiedCategoryCandidateIdentity = Readonly<{
  schema: typeof CATEGORY_CANDIDATE_IDENTITY_SCHEMA;
  chainId: 56;
  tokenId: string;
  registryAddress: string;
  ownerAddress: string;
  observedAt: number;
  observedBlock: number;
  observedBlockHash: string;
  confirmationDepth: 2;
  registryCodeSha256: string;
  identitySha256: string;
}>;

export type CategoryCandidateIdentityResult =
  | Readonly<{
      outcome: "verified";
      identity: VerifiedCategoryCandidateIdentity;
    }>
  | Readonly<{
      outcome: "unavailable";
      code: "TOKEN_NOT_FOUND";
    }>
  | Readonly<{
      outcome: "inconclusive";
      code: Extract<Erc8004Result, { status: "inconclusive" }>["code"];
    }>;

export interface CategoryCandidateIdentityCapability {
  readonly capture: (
    selector: CategoryCandidateIdentitySelector,
    sharedSnapshot?: CategorySnapshotHandle | Erc8004SharedAnchor,
  ) => Promise<CategoryCandidateIdentityResult>;
  readonly assertVerified: (
    value: unknown,
    selector: CategoryCandidateIdentitySelector,
  ) => asserts value is VerifiedCategoryCandidateIdentity;
  /** Return provider runtime facts only for this capability-owned identity. */
  readonly providerFor: (
    value: unknown,
    selector: CategoryCandidateIdentitySelector,
  ) => Readonly<{
    providerKind: "eoa" | "erc1271";
    providerCodeSha256: string;
  }>;
}

type IdentityProvenance = Readonly<{
  capability: CategoryCandidateIdentityCapability;
  selectorCanonical: string;
  providerKind: "eoa" | "erc1271";
  providerCodeSha256: string;
}>;

const verifiedIdentities = new WeakMap<object, IdentityProvenance>();

/**
 * Creates the verifier-owned ERC-8004 identity boundary. The selector is
 * canonicalized before the first RPC await and only canonical ownerOf results
 * receive the private capability provenance.
 */
export function createCategoryCandidateIdentityCapability(options: {
  readonly transport: {
    readonly request: (route: TransportRoute) => Promise<BoundedHttpResponse>;
  };
  readonly registryAddress: string;
  readonly snapshotCapability?: CategorySnapshotCapability;
}): CategoryCandidateIdentityCapability {
  assertExactDataObject(
    options,
    [
      "registryAddress",
      "transport",
      ...(Object.hasOwn(options, "snapshotCapability") ? ["snapshotCapability"] : []),
    ],
    "identity capability options",
  );
  const transport = readDataProperty(options, "transport");
  assertExactDataObject(
    transport,
    ["request"],
    "identity capability transport",
  );
  const request = readDataProperty(transport, "request");
  if (typeof request !== "function") {
    throw new TypeError("identity capability transport request must be a function");
  }
  const capturedTransport = Object.freeze({
    request: (route: TransportRoute) => request(route),
  });
  const registryAddressValue = readDataProperty(options, "registryAddress");
  if (typeof registryAddressValue !== "string") {
    throw new TypeError("identity capability registry address is invalid");
  }
  const registryAddress = parseAddress(registryAddressValue);
  const snapshotCapability = Object.hasOwn(options, "snapshotCapability")
    ? readDataProperty(options, "snapshotCapability")
    : undefined;
  const snapshotCapabilityCandidate =
    snapshotCapability as Partial<CategorySnapshotCapability> | null | undefined;
  if (
    snapshotCapability !== undefined &&
    (snapshotCapability === null ||
      typeof snapshotCapability !== "object" ||
      typeof snapshotCapabilityCandidate?.assertOpaqueActive !== "function" ||
      typeof snapshotCapabilityCandidate.anchorForOpaque !== "function")
  ) {
    throw new TypeError("identity capability snapshot capability is invalid");
  }
  const capturedSnapshotCapability =
    snapshotCapability as CategorySnapshotCapability | undefined;
  const snapshotAnchor:
    | CategorySnapshotCapability["anchorForOpaque"]
    | undefined = capturedSnapshotCapability?.anchorForOpaque;

  let capability: CategoryCandidateIdentityCapability;
  capability = Object.freeze({
    async capture(
      selectorInput: CategoryCandidateIdentitySelector,
      sharedSnapshotInput?: CategorySnapshotHandle | Erc8004SharedAnchor,
    ): Promise<CategoryCandidateIdentityResult> {
      const selector = parseSelector(selectorInput);
      let sharedAnchor: Erc8004SharedAnchor | undefined;
      if (
        snapshotAnchor !== undefined &&
        sharedSnapshotInput !== undefined
      ) {
        try {
          const snapshot = sharedSnapshotInput as CategorySnapshotHandle;
          sharedAnchor = snapshotAnchor(snapshot);
        } catch {
          throw new TypeError(
            "candidate identity requires an active verifier-owned snapshot handle",
          );
        }
      } else {
        sharedAnchor = parseSharedAnchor(
          sharedSnapshotInput as Erc8004SharedAnchor | undefined,
        );
      }
      const selectorCanonical = canonicalQuoteJson(selector);
      const result = await verifyErc8004Ownership({
        transport: capturedTransport,
        chainId: selector.chainId,
        tokenId: selector.tokenId,
        registryAddress,
        ...(sharedAnchor === undefined ? {} : { sharedAnchor }),
      });
      if (result.status === "unavailable") {
        return Object.freeze({ outcome: "unavailable", code: result.code });
      }
      if (result.status === "inconclusive") {
        return Object.freeze({ outcome: "inconclusive", code: result.code });
      }

      const snapshot = result.snapshot;
      const providerCode = await observeProviderCode({
        transport: capturedTransport,
        owner: parseAddress(snapshot.ownerAddress),
        blockHash: parseBytes32(snapshot.observedBlockHash),
        tokenId: selector.tokenId,
      });
      if (providerCode.status === "inconclusive") {
        return Object.freeze({
          outcome: "inconclusive",
          code: providerCode.code,
        });
      }
      const observedBlock = parseSafeDecimal(
        snapshot.observedBlockNumber,
        "identity observed block",
      );
      const observedAt =
        sharedAnchor?.timestamp ??
        parseObservationTime([
          ...snapshot.calls,
          { finishedAt: providerCode.finishedAt },
        ]);
      const unsigned = Object.freeze({
        schema: CATEGORY_CANDIDATE_IDENTITY_SCHEMA,
        chainId: selector.chainId,
        tokenId: selector.tokenId,
        registryAddress: parseAddress(snapshot.registryAddress),
        ownerAddress: parseAddress(snapshot.ownerAddress),
        observedAt,
        observedBlock,
        observedBlockHash: parseBytes32(snapshot.observedBlockHash),
        confirmationDepth: 2 as const,
        registryCodeSha256: parseSha256(snapshot.registryCodeSha256),
      });
      const identity = deepFreeze({
        ...unsigned,
        identitySha256: computeQuoteSha256(canonicalQuoteJson(unsigned)),
      });
      verifiedIdentities.set(identity, {
        capability,
        selectorCanonical,
        providerKind: providerCode.providerKind,
        providerCodeSha256: providerCode.providerCodeSha256,
      });
      return Object.freeze({ outcome: "verified", identity });
    },
    assertVerified(
      value: unknown,
      selectorInput: CategoryCandidateIdentitySelector,
    ): asserts value is VerifiedCategoryCandidateIdentity {
      const selector = parseSelector(selectorInput);
      const provenance =
        value !== null && typeof value === "object"
          ? verifiedIdentities.get(value)
          : undefined;
      const candidate =
        value !== null && typeof value === "object"
          ? (value as Partial<VerifiedCategoryCandidateIdentity>)
          : undefined;
      if (
        provenance === undefined ||
        provenance.capability !== capability ||
        provenance.selectorCanonical !== canonicalQuoteJson(selector) ||
        candidate === undefined ||
        candidate.schema !== CATEGORY_CANDIDATE_IDENTITY_SCHEMA ||
        candidate.chainId !== selector.chainId ||
        candidate.tokenId !== selector.tokenId
      ) {
        throw new Error(
          "candidate identity lacks verifier-owned ERC-8004 provenance for this selector",
        );
      }
    },
    providerFor(
      value: unknown,
      selectorInput: CategoryCandidateIdentitySelector,
    ) {
      const selector = parseSelector(selectorInput);
      const provenance =
        value !== null && typeof value === "object"
          ? verifiedIdentities.get(value)
          : undefined;
      const candidate =
        value !== null && typeof value === "object"
          ? (value as Partial<VerifiedCategoryCandidateIdentity>)
          : undefined;
      if (
        provenance === undefined ||
        provenance.capability !== capability ||
        provenance.selectorCanonical !== canonicalQuoteJson(selector) ||
        candidate === undefined
      ) {
        throw new Error(
          "candidate identity lacks verifier-owned provider provenance for this selector",
        );
      }
      return Object.freeze({
        providerKind: provenance.providerKind,
        providerCodeSha256: provenance.providerCodeSha256,
      });
    },
  });
  return capability;
}

function parseSharedAnchor(
  value: Erc8004SharedAnchor | undefined,
): Erc8004SharedAnchor | undefined {
  if (value === undefined) return undefined;
  assertExactDataObject(
    value,
    ["hash", "number", "timestamp"],
    "candidate identity shared anchor",
  );
  const number = readDataProperty(value, "number");
  const hash = readDataProperty(value, "hash");
  const timestamp = readDataProperty(value, "timestamp");
  if (
    typeof number !== "number" ||
    !Number.isSafeInteger(number) ||
    number < 0 ||
    typeof timestamp !== "number" ||
    !Number.isSafeInteger(timestamp) ||
    timestamp <= 0 ||
    typeof hash !== "string" ||
    !/^0x[0-9a-f]{64}$/.test(hash)
  ) {
    throw new TypeError("candidate identity shared anchor is invalid");
  }
  return Object.freeze({ number, hash, timestamp });
}

type ProviderCodeObservation =
  | Readonly<{
      status: "verified";
      providerKind: "eoa" | "erc1271";
      providerCodeSha256: string;
      finishedAt: string;
    }>
  | Readonly<{
      status: "inconclusive";
      code: "RPC_UNAVAILABLE" | "RPC_INVALID_RESPONSE" | "SNAPSHOT_INCONSISTENT";
    }>;

async function observeProviderCode(input: {
  transport: { readonly request: (route: TransportRoute) => Promise<BoundedHttpResponse> };
  owner: string;
  blockHash: string;
  tokenId: string;
}): Promise<ProviderCodeObservation> {
  const id = `category-owner-code-${input.tokenId}`;
  const body = JSON.stringify({
    jsonrpc: "2.0",
    id,
    method: "eth_getCode",
    params: [
      input.owner,
      { blockHash: input.blockHash, requireCanonical: true },
    ],
  });
  let response: BoundedHttpResponse;
  try {
    response = await input.transport.request({
      kind: "bsc-quote-rpc",
      method: "POST",
      url: BSC_MAINNET.rpcOrigin,
      rpcMethod: "eth_getCode",
      approvedProvider: input.owner,
      approvedBlockHash: input.blockHash,
      body,
    });
  } catch {
    return Object.freeze({ status: "inconclusive", code: "RPC_UNAVAILABLE" });
  }
  if (response.status !== 200) {
    return Object.freeze({ status: "inconclusive", code: "RPC_UNAVAILABLE" });
  }

  let parsed: unknown;
  try {
    parsed = parseJsonResponse(response);
  } catch {
    return Object.freeze({
      status: "inconclusive",
      code: "RPC_INVALID_RESPONSE",
    });
  }
  if (!isRecord(parsed) || parsed.jsonrpc !== "2.0" || parsed.id !== id) {
    return Object.freeze({
      status: "inconclusive",
      code: "RPC_INVALID_RESPONSE",
    });
  }
  if (isRecord(parsed.error)) {
    const message =
      typeof parsed.error.message === "string"
        ? parsed.error.message.toLowerCase()
        : "";
    return Object.freeze({
      status: "inconclusive",
      code: isCanonicalityError(message)
        ? "SNAPSHOT_INCONSISTENT"
        : "RPC_INVALID_RESPONSE",
    });
  }
  if (
    Reflect.ownKeys(parsed).length !== 3 ||
    typeof parsed.result !== "string" ||
    !/^0x(?:[0-9a-fA-F]{2})*$/.test(parsed.result)
  ) {
    return Object.freeze({
      status: "inconclusive",
      code: "RPC_INVALID_RESPONSE",
    });
  }

  const code = Buffer.from(parsed.result.slice(2), "hex");
  return Object.freeze({
    status: "verified",
    providerKind: code.byteLength === 0 ? "eoa" : "erc1271",
    providerCodeSha256: createHash("sha256").update(code).digest("hex"),
    finishedAt: response.finishedAt,
  });
}

function isCanonicalityError(message: string): boolean {
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

function parseSelector(input: unknown): CategoryCandidateIdentitySelector {
  assertExactDataObject(input, ["chainId", "tokenId"], "candidate selector");
  const chainId = readDataProperty(input, "chainId");
  const tokenId = readDataProperty(input, "tokenId");
  if (chainId !== 56) {
    throw new TypeError("candidate identity supports BSC mainnet only");
  }
  if (
    typeof tokenId !== "string" ||
    !/^(?:0|[1-9][0-9]*)$/.test(tokenId)
  ) {
    throw new TypeError("candidate token ID must be canonical uint256 decimal");
  }
  let parsed: bigint;
  try {
    parsed = BigInt(tokenId);
  } catch {
    throw new TypeError("candidate token ID is outside uint256");
  }
  if (parsed < 0n || parsed >= 1n << 256n) {
    throw new TypeError("candidate token ID is outside uint256");
  }
  return Object.freeze({ chainId: 56, tokenId });
}

function parseObservationTime(
  calls: readonly Readonly<{ readonly finishedAt: string }>[],
): number {
  const finishedAt = calls.at(-1)?.finishedAt;
  if (finishedAt === undefined) {
    throw new TypeError("verified identity lacks a completed RPC observation");
  }
  const milliseconds = Date.parse(finishedAt);
  if (!Number.isFinite(milliseconds) || milliseconds < 0) {
    throw new TypeError("verified identity observation time is invalid");
  }
  const seconds = Math.floor(milliseconds / 1_000);
  if (!Number.isSafeInteger(seconds) || seconds <= 0) {
    throw new TypeError("verified identity observation time is invalid");
  }
  return seconds;
}

function parseSafeDecimal(value: string, label: string): number {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new TypeError(`${label} is not canonical decimal`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new TypeError(`${label} exceeds the safe integer range`);
  }
  return parsed;
}

function parseAddress(value: string): string {
  const normalized = value.toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(normalized) || /^0x0{40}$/.test(normalized)) {
    throw new TypeError("verified identity contains an invalid address");
  }
  return normalized;
}

function parseBytes32(value: string): string {
  const normalized = value.toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(normalized)) {
    throw new TypeError("verified identity contains an invalid block hash");
  }
  return normalized;
}

function parseSha256(value: string): string {
  if (!/^[a-f0-9]{64}$/.test(value)) {
    throw new TypeError("verified identity contains an invalid SHA-256 digest");
  }
  return value;
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
    throw new TypeError(`${label} must be a plain object`);
  }
  const actual = Reflect.ownKeys(value);
  if (
    actual.length !== keys.length ||
    actual.some((key) => typeof key !== "string" || !keys.includes(key))
  ) {
    throw new TypeError(`${label} has unsupported or missing fields`);
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor)) {
      throw new TypeError(`${label} must contain data properties`);
    }
  }
}

function readDataProperty(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || !("value" in descriptor)) {
    throw new TypeError(`missing data property ${key}`);
  }
  return descriptor.value;
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
