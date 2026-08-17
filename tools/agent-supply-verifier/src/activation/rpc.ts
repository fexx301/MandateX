import { createHash } from "node:crypto";

import {
  decodeEventLog,
  decodeFunctionResult,
  encodeFunctionData,
  getAddress,
  keccak256,
  parseAbi,
  parseAbiItem,
  type Hex,
} from "viem";

import {
  BSC_ACTIVATION_IMPLEMENTATION_SLOT,
  BSC_MAINNET_RPC_ORIGIN,
  parseJsonResponse,
  type BscActivationRpcRoute,
  type PinnedHttpsTransport,
} from "../transport/http.js";
import {
  ACTIVATION_CONFIRMATION_DEPTH,
  BSC_ACTIVATION_DEPLOYMENT,
} from "./deployment.js";
import {
  activationDeploymentObservationSchema,
  activationIntentSchema,
  activationJobObservationSchema,
  activationReceiptSchema,
  type ActivationDeploymentObservation,
  type ActivationIntent,
  type ActivationJobObservation,
  type ActivationReceipt,
} from "./schema.js";

const simpleReadAbi = parseAbi([
  "function paymentToken() view returns (address)",
  "function jobHasBudget(uint256) view returns (bool)",
  "function commerce() view returns (address)",
  "function router() view returns (address)",
  "function jobPolicy(uint256) view returns (address)",
  "function policyWhitelist(address) view returns (bool)",
  "function paused() view returns (bool)",
  "function disputeWindow() view returns (uint256)",
]);

const getJobAbi = [
  {
    type: "function",
    name: "getJob",
    stateMutability: "view",
    inputs: [{ name: "jobId", type: "uint256" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "id", type: "uint256" },
          { name: "client", type: "address" },
          { name: "provider", type: "address" },
          { name: "evaluator", type: "address" },
          { name: "description", type: "string" },
          { name: "budget", type: "uint256" },
          { name: "expiredAt", type: "uint256" },
          { name: "status", type: "uint8" },
          { name: "hook", type: "address" },
          { name: "submittedAt", type: "uint256" },
          { name: "deliverable", type: "bytes32" },
        ],
      },
    ],
  },
] as const;

const jobCreatedEvent = parseAbiItem(
  "event JobCreated(uint256 indexed jobId, address indexed client, address indexed provider, address evaluator, uint256 expiredAt, address hook)",
);
const jobRegisteredEvent = parseAbiItem(
  "event JobRegistered(uint256 indexed jobId, address indexed policy, address indexed client)",
);
const jobFundedEvent = parseAbiItem(
  "event JobFunded(uint256 indexed jobId, address indexed client, address indexed provider, uint256 amount)",
);

type RpcBlock = Readonly<{
  number: string;
  hash: string;
  timestamp: string;
}>;

type RpcTransaction = Readonly<{
  hash: string;
  from: string;
  to: string | null;
  input: string;
  value: string;
  blockNumber: string | null;
  blockHash: string | null;
}>;

type RpcLog = Readonly<{
  address: string;
  data: string;
  topics: readonly string[];
}>;

type RpcReceipt = Readonly<{
  transactionHash: string;
  status: string;
  blockNumber: string;
  blockHash: string;
  logs: readonly RpcLog[];
}>;

export type ActivationReceiptObservation =
  | Readonly<{
      kind: "confirmed";
      receipt: ActivationReceipt;
      deployment: ActivationDeploymentObservation;
    }>
  | Readonly<{
      kind: "pending";
      transactionHash: string;
      observedAt: string;
    }>
  | Readonly<{
      kind: "not_found";
      transactionHash: string;
      observedAt: string;
    }>
  | Readonly<{
      kind: "unconfirmed";
      transactionHash: string;
      observedAt: string;
      blockNumber: string;
      blockHash: string;
      confirmationDepth: number;
      requiredConfirmationDepth: typeof ACTIVATION_CONFIRMATION_DEPTH;
    }>
  | Readonly<{
      kind: "reorged";
      transactionHash: string;
      observedAt: string;
    }>
  | Readonly<{
      kind: "reverted";
      transactionHash: string;
      observedAt: string;
      blockNumber: string;
      blockHash: string;
      confirmationDepth: number;
      deployment: ActivationDeploymentObservation;
    }>;

export class ActivationRpcError extends Error {
  constructor(
    readonly kind: "unavailable" | "invalid-response" | "noncanonical",
  ) {
    super("activation RPC verification failed closed");
    this.name = "ActivationRpcError";
  }
}

export class TransportActivationRpc {
  constructor(
    private readonly transport: Pick<PinnedHttpsTransport, "request">,
    private readonly randomUUID: () => string,
    private readonly now: () => Date = () => new Date(),
  ) {}

  async observeDeployment(
    blockNumber?: string,
  ): Promise<ActivationDeploymentObservation> {
    const chainId = await this.rpc("chain-id", "eth_chainId", []);
    if (chainId !== "0x38") throw new ActivationRpcError("invalid-response");
    const headHex = await this.rpc("head-block-number", "eth_blockNumber", []);
    const head = parseQuantity(headHex);
    const target =
      blockNumber === undefined
        ? head - BigInt(ACTIVATION_CONFIRMATION_DEPTH)
        : parseDecimal(blockNumber);
    if (target < 0n || head < target + BigInt(ACTIVATION_CONFIRMATION_DEPTH)) {
      throw new ActivationRpcError("noncanonical");
    }
    const block = await this.block(target);
    const blockHash = canonicalBlockHash(block.hash);
    const deployment = BSC_ACTIVATION_DEPLOYMENT;

    const [
      commerceProxyCode,
      commerceImplementationRaw,
      routerProxyCode,
      routerImplementationRaw,
      policyCode,
      tokenCode,
      commerceImplSlot,
      routerImplSlot,
      paymentToken,
      routerCommerce,
      policyCommerce,
      policyRouter,
      policyWhitelisted,
      commercePaused,
      routerPaused,
      disputeWindow,
    ] = await Promise.all([
      this.code(deployment.commerceProxy, blockHash),
      this.code(deployment.commerceImplementation, blockHash),
      this.code(deployment.routerProxy, blockHash),
      this.code(deployment.routerImplementation, blockHash),
      this.code(deployment.policy, blockHash),
      this.code(deployment.paymentToken, blockHash),
      this.storage(deployment.commerceProxy, blockHash),
      this.storage(deployment.routerProxy, blockHash),
      this.read(deployment.commerceProxy, "paymentToken", [], blockHash),
      this.read(deployment.routerProxy, "commerce", [], blockHash),
      this.read(deployment.policy, "commerce", [], blockHash),
      this.read(deployment.policy, "router", [], blockHash),
      this.read(
        deployment.routerProxy,
        "policyWhitelist",
        [deployment.policy],
        blockHash,
      ),
      this.read(deployment.commerceProxy, "paused", [], blockHash),
      this.read(deployment.routerProxy, "paused", [], blockHash),
      this.read(deployment.policy, "disputeWindow", [], blockHash),
    ]);
    const finalBlock = await this.block(target);
    if (finalBlock.hash !== block.hash || finalBlock.number !== block.number) {
      throw new ActivationRpcError("noncanonical");
    }

    return activationDeploymentObservationSchema.parse({
      chainId: 56,
      headBlockNumber: head.toString(),
      blockNumber: target.toString(),
      blockHash,
      blockTimestamp: Number(parseQuantity(block.timestamp)),
      confirmationDepth: Number(head - target),
      commerceImplementation: implementationAddress(commerceImplSlot),
      commerceProxyCodeHash: keccak256(nonEmptyCode(commerceProxyCode)),
      commerceImplementationCodeHash: keccak256(
        nonEmptyCode(commerceImplementationRaw),
      ),
      routerImplementation: implementationAddress(routerImplSlot),
      routerProxyCodeHash: keccak256(nonEmptyCode(routerProxyCode)),
      routerImplementationCodeHash: keccak256(
        nonEmptyCode(routerImplementationRaw),
      ),
      policyCodeHash: keccak256(nonEmptyCode(policyCode)),
      paymentToken: addressResult(paymentToken),
      paymentTokenCodeHash: keccak256(nonEmptyCode(tokenCode)),
      routerCommerce: addressResult(routerCommerce),
      policyCommerce: addressResult(policyCommerce),
      policyRouter: addressResult(policyRouter),
      policyWhitelisted: booleanResult(policyWhitelisted),
      commercePaused: booleanResult(commercePaused),
      routerPaused: booleanResult(routerPaused),
      disputeWindowSeconds: bigintResult(disputeWindow).toString(),
    });
  }

  async observeReceipt(
    transactionHash: string,
    intent: ActivationIntent,
  ): Promise<ActivationReceiptObservation> {
    const hash = canonicalBlockHash(transactionHash);
    const expectedIntent = parseActivationIntent(intent);
    const [transactionRaw, receiptRaw] = await Promise.all([
      this.rpc("transaction", "eth_getTransactionByHash", [hash], hash),
      this.rpc("receipt", "eth_getTransactionReceipt", [hash], hash),
    ]);

    if (transactionRaw === null) {
      return receiptRaw === null
        ? { kind: "not_found", transactionHash: hash, observedAt: this.observedAt() }
        : { kind: "reorged", transactionHash: hash, observedAt: this.observedAt() };
    }

    const transaction = rpcTransaction(transactionRaw);
    assertTransactionMatches(transaction, hash, expectedIntent);

    if (transaction.blockNumber === null || transaction.blockHash === null) {
      if (
        transaction.blockNumber === null &&
        transaction.blockHash === null &&
        receiptRaw === null
      ) {
        return {
          kind: "pending",
          transactionHash: hash,
          observedAt: this.observedAt(),
        };
      }
      return {
        kind: "reorged",
        transactionHash: hash,
        observedAt: this.observedAt(),
      };
    }

    if (receiptRaw === null) {
      return {
        kind: "reorged",
        transactionHash: hash,
        observedAt: this.observedAt(),
      };
    }

    const rawReceipt = rpcReceipt(receiptRaw);
    const transactionBlockHash = canonicalBlockHash(transaction.blockHash);
    const receiptBlockHash = canonicalBlockHash(rawReceipt.blockHash);
    if (
      canonicalBlockHash(rawReceipt.transactionHash) !== hash ||
      transaction.blockNumber !== rawReceipt.blockNumber ||
      transactionBlockHash !== receiptBlockHash
    ) {
      return {
        kind: "reorged",
        transactionHash: hash,
        observedAt: this.observedAt(),
      };
    }

    const receiptStatus = parseReceiptStatus(rawReceipt.status);
    const blockNumber = parseQuantity(rawReceipt.blockNumber);
    let head: bigint;
    let canonicalBlock: RpcBlock | null;
    try {
      [head, canonicalBlock] = await Promise.all([
        this.rpc("head-block-number", "eth_blockNumber", []).then(parseQuantity),
        this.blockOrNull(blockNumber),
      ]);
    } catch (error) {
      if (error instanceof ActivationRpcError && error.kind === "noncanonical") {
        return {
          kind: "reorged",
          transactionHash: hash,
          observedAt: this.observedAt(),
        };
      }
      throw error;
    }
    if (head < blockNumber) {
      throw new ActivationRpcError("invalid-response");
    }
    if (canonicalBlock === null || canonicalBlock.hash !== receiptBlockHash) {
      return {
        kind: "reorged",
        transactionHash: hash,
        observedAt: this.observedAt(),
      };
    }

    const confirmationDepth = boundedConfirmationDepth(head - blockNumber);
    if (confirmationDepth < ACTIVATION_CONFIRMATION_DEPTH) {
      return {
        kind: "unconfirmed",
        transactionHash: hash,
        observedAt: this.observedAt(),
        blockNumber: blockNumber.toString(),
        blockHash: receiptBlockHash,
        confirmationDepth,
        requiredConfirmationDepth: ACTIVATION_CONFIRMATION_DEPTH,
      };
    }

    let deployment: ActivationDeploymentObservation;
    try {
      deployment = await this.observeDeployment(blockNumber.toString());
    } catch (error) {
      if (error instanceof ActivationRpcError && error.kind === "noncanonical") {
        return {
          kind: "reorged",
          transactionHash: hash,
          observedAt: this.observedAt(),
        };
      }
      if (
        error instanceof ActivationRpcError &&
        error.kind === "unavailable" &&
        (await this.receiptBlockIsNoncanonical(blockNumber, receiptBlockHash))
      ) {
        return {
          kind: "reorged",
          transactionHash: hash,
          observedAt: this.observedAt(),
        };
      }
      throw error;
    }
    if (deployment.blockHash !== receiptBlockHash) {
      return {
        kind: "reorged",
        transactionHash: hash,
        observedAt: this.observedAt(),
      };
    }

    if (receiptStatus === "reverted") {
      return {
        kind: "reverted",
        transactionHash: hash,
        observedAt: this.observedAt(),
        blockNumber: blockNumber.toString(),
        blockHash: receiptBlockHash,
        confirmationDepth: deployment.confirmationDepth,
        deployment,
      };
    }

    const events = decodeActivationEvents(rawReceipt.logs);
    return {
      kind: "confirmed",
      deployment,
      receipt: activationReceiptSchema.parse({
        operation: expectedIntent.operation,
        transactionHash: hash,
        blockNumber: blockNumber.toString(),
        blockHash: receiptBlockHash,
        blockTimestamp: deployment.blockTimestamp,
        status: "success",
        from: expectedIntent.from,
        to: expectedIntent.to,
        valueWei: expectedIntent.valueWei,
        calldataSha256: expectedIntent.calldataSha256,
        events,
      }),
    };
  }

  async observeJob(
    jobIdInput: string,
    blockHashInput: string,
  ): Promise<ActivationJobObservation> {
    const jobId = BigInt(jobIdInput);
    const blockHash = canonicalBlockHash(blockHashInput);
    const [rawJob, rawHasBudget, rawPolicy] = await Promise.all([
      this.call(
        BSC_ACTIVATION_DEPLOYMENT.commerceProxy,
        encodeFunctionData({ abi: getJobAbi, functionName: "getJob", args: [jobId] }),
        blockHash,
      ),
      this.read(
        BSC_ACTIVATION_DEPLOYMENT.commerceProxy,
        "jobHasBudget",
        [jobId],
        blockHash,
      ),
      this.read(
        BSC_ACTIVATION_DEPLOYMENT.routerProxy,
        "jobPolicy",
        [jobId],
        blockHash,
      ),
    ]);
    let job: Record<string, unknown>;
    try {
      job = decodeFunctionResult({
        abi: getJobAbi,
        functionName: "getJob",
        data: rawJob,
      }) as unknown as Record<string, unknown>;
    } catch {
      throw new ActivationRpcError("invalid-response");
    }
    const status = bigintLike(job.status);
    if (status !== 0n && status !== 1n) {
      throw new ActivationRpcError("invalid-response");
    }
    return activationJobObservationSchema.parse({
      jobId: bigintLike(job.id).toString(),
      client: addressLike(job.client),
      provider: addressLike(job.provider),
      evaluator: addressLike(job.evaluator),
      hook: addressLike(job.hook),
      descriptionSha256: createHash("sha256")
        .update(stringLike(job.description), "utf8")
        .digest("hex"),
      budget: bigintLike(job.budget).toString(),
      expiredAt: bigintLike(job.expiredAt).toString(),
      status: status === 0n ? "OPEN" : "FUNDED",
      hasBudget: booleanResult(rawHasBudget),
      policy: addressResult(rawPolicy),
    });
  }

  async block(number: bigint): Promise<RpcBlock> {
    const block = await this.blockOrNull(number);
    if (block === null) throw new ActivationRpcError("noncanonical");
    return block;
  }

  private async blockOrNull(number: bigint): Promise<RpcBlock | null> {
    const approvedBlockNumber = `0x${number.toString(16)}`;
    const result = await this.rpc(
      "block-header",
      "eth_getBlockByNumber",
      [approvedBlockNumber, false],
      approvedBlockNumber,
    );
    return result === null ? null : rpcBlock(result, approvedBlockNumber);
  }

  async code(target: string, blockHash: string): Promise<Hex> {
    const result = await this.rpc(
      "contract-code",
      "eth_getCode",
      [target, { blockHash, requireCanonical: true }],
      target,
      blockHash,
    );
    return hexResult(result);
  }

  async storage(target: string, blockHash: string): Promise<Hex> {
    const result = await this.rpc(
      "proxy-implementation",
      "eth_getStorageAt",
      [
        target,
        BSC_ACTIVATION_IMPLEMENTATION_SLOT,
        { blockHash, requireCanonical: true },
      ],
      target,
      blockHash,
    );
    return hexResult(result);
  }

  async read(
    target: string,
    functionName: (typeof simpleReadAbi)[number]["name"],
    args: readonly [] | readonly [bigint] | readonly [`0x${string}`],
    blockHash: string,
  ): Promise<unknown> {
    const data = encodeFunctionData({
      abi: simpleReadAbi,
      functionName,
      args,
    } as Parameters<typeof encodeFunctionData>[0]);
    const raw = await this.call(target, data, blockHash);
    try {
      return decodeFunctionResult({
        abi: simpleReadAbi,
        functionName,
        data: raw,
      } as Parameters<typeof decodeFunctionResult>[0]);
    } catch {
      throw new ActivationRpcError("invalid-response");
    }
  }

  async call(target: string, data: Hex, blockHash: string): Promise<Hex> {
    return hexResult(
      await this.rpc(
        "state-read",
        "eth_call",
        [{ to: target, data }, { blockHash, requireCanonical: true }],
        target,
        blockHash,
      ),
    );
  }

  private async rpc(
    purpose: BscActivationRpcRoute["purpose"],
    rpcMethod: BscActivationRpcRoute["rpcMethod"],
    params: readonly unknown[],
    approved?: string,
    approvedBlockHash?: string,
  ): Promise<unknown> {
    const id = `activation-${this.randomUUID()}`;
    const body = JSON.stringify({ jsonrpc: "2.0", id, method: rpcMethod, params });
    const route = activationRoute({
      purpose,
      rpcMethod,
      body,
      ...(approved === undefined ? {} : { approved }),
      ...(approvedBlockHash === undefined ? {} : { approvedBlockHash }),
    });
    let response;
    try {
      response = await this.transport.request(route);
    } catch {
      throw new ActivationRpcError("unavailable");
    }
    if (response.status !== 200) throw new ActivationRpcError("unavailable");

    let parsed: unknown;
    try {
      parsed = parseJsonResponse(response);
    } catch {
      throw new ActivationRpcError("invalid-response");
    }
    if (!isRecord(parsed) || parsed.jsonrpc !== "2.0" || parsed.id !== id) {
      throw new ActivationRpcError("invalid-response");
    }
    if ("error" in parsed) {
      if ("result" in parsed) throw new ActivationRpcError("invalid-response");
      throw new ActivationRpcError(rpcErrorKind(parsed.error));
    }
    if (!("result" in parsed)) throw new ActivationRpcError("invalid-response");
    return parsed.result;
  }

  private observedAt(): string {
    const now = this.now();
    if (Number.isNaN(now.valueOf())) {
      throw new ActivationRpcError("invalid-response");
    }
    return now.toISOString();
  }

  private async receiptBlockIsNoncanonical(
    blockNumber: bigint,
    expectedBlockHash: string,
  ): Promise<boolean> {
    const block = await this.blockOrNull(blockNumber);
    return block === null || block.hash !== expectedBlockHash;
  }
}

function activationRoute(input: Readonly<{
  purpose: BscActivationRpcRoute["purpose"];
  rpcMethod: BscActivationRpcRoute["rpcMethod"];
  body: string;
  approved?: string;
  approvedBlockHash?: string;
}>): BscActivationRpcRoute {
  const common = {
    kind: "bsc-activation-rpc" as const,
    method: "POST" as const,
    url: BSC_MAINNET_RPC_ORIGIN,
    body: input.body,
  };
  switch (input.purpose) {
    case "chain-id":
      return { ...common, purpose: input.purpose, rpcMethod: "eth_chainId" };
    case "head-block-number":
      return { ...common, purpose: input.purpose, rpcMethod: "eth_blockNumber" };
    case "block-header":
      return {
        ...common,
        purpose: input.purpose,
        rpcMethod: "eth_getBlockByNumber",
        approvedBlockNumber: required(input.approved),
      };
    case "transaction":
      return {
        ...common,
        purpose: input.purpose,
        rpcMethod: "eth_getTransactionByHash",
        approvedTransactionHash: required(input.approved),
      };
    case "receipt":
      return {
        ...common,
        purpose: input.purpose,
        rpcMethod: "eth_getTransactionReceipt",
        approvedTransactionHash: required(input.approved),
      };
    case "contract-code":
      return {
        ...common,
        purpose: input.purpose,
        rpcMethod: "eth_getCode",
        approvedTargets: [required(input.approved)],
        approvedBlockHash: required(input.approvedBlockHash),
      };
    case "proxy-implementation":
      return {
        ...common,
        purpose: input.purpose,
        rpcMethod: "eth_getStorageAt",
        approvedTargets: [required(input.approved)],
        approvedBlockHash: required(input.approvedBlockHash),
      };
    case "state-read":
      return {
        ...common,
        purpose: input.purpose,
        rpcMethod: "eth_call",
        approvedTargets: [required(input.approved)],
        approvedBlockHash: required(input.approvedBlockHash),
      };
  }
}

function decodeActivationEvents(logs: readonly RpcLog[]) {
  const events: Array<
    | {
        name: "JobCreated";
        jobId: string;
        client: string;
        provider: string;
        evaluator: string;
        expiredAt: string;
        hook: string;
      }
    | {
        name: "JobRegistered";
        jobId: string;
        policy: string;
        client: string;
      }
    | {
        name: "JobFunded";
        jobId: string;
        client: string;
        provider: string;
        amount: string;
      }
  > = [];
  for (const log of logs) {
    const address = log.address.toLowerCase();
    const abi =
      address === BSC_ACTIVATION_DEPLOYMENT.commerceProxy
        ? [jobCreatedEvent, jobFundedEvent]
        : address === BSC_ACTIVATION_DEPLOYMENT.routerProxy
          ? [jobRegisteredEvent]
          : undefined;
    if (abi === undefined) continue;
    try {
      const decoded = decodeEventLog({
        abi,
        data: hexResult(log.data),
        topics: log.topics.map(hexResult) as [Hex, ...Hex[]],
      });
      const args = decoded.args as Record<string, unknown>;
      if (decoded.eventName === "JobCreated") {
        events.push({
          name: "JobCreated",
          jobId: bigintLike(args.jobId).toString(),
          client: addressLike(args.client),
          provider: addressLike(args.provider),
          evaluator: addressLike(args.evaluator),
          expiredAt: bigintLike(args.expiredAt).toString(),
          hook: addressLike(args.hook),
        });
      } else if (decoded.eventName === "JobRegistered") {
        events.push({
          name: "JobRegistered",
          jobId: bigintLike(args.jobId).toString(),
          policy: addressLike(args.policy),
          client: addressLike(args.client),
        });
      } else if (decoded.eventName === "JobFunded") {
        events.push({
          name: "JobFunded",
          jobId: bigintLike(args.jobId).toString(),
          client: addressLike(args.client),
          provider: addressLike(args.provider),
          amount: bigintLike(args.amount).toString(),
        });
      }
    } catch {
      continue;
    }
  }
  return events;
}

function rpcBlock(value: unknown, expectedNumber: string): RpcBlock {
  if (
    !isRecord(value) ||
    value.number !== expectedNumber ||
    typeof value.hash !== "string" ||
    typeof value.timestamp !== "string"
  ) {
    throw new ActivationRpcError("invalid-response");
  }
  canonicalBlockHash(value.hash);
  parseQuantity(value.timestamp);
  return { number: expectedNumber, hash: value.hash, timestamp: value.timestamp };
}

function rpcTransaction(value: unknown): RpcTransaction {
  if (
    !isRecord(value) ||
    typeof value.hash !== "string" ||
    typeof value.from !== "string" ||
    (typeof value.to !== "string" && value.to !== null) ||
    typeof value.input !== "string" ||
    typeof value.value !== "string" ||
    (typeof value.blockNumber !== "string" && value.blockNumber !== null) ||
    (typeof value.blockHash !== "string" && value.blockHash !== null)
  ) {
    throw new ActivationRpcError("invalid-response");
  }
  return value as unknown as RpcTransaction;
}

function parseActivationIntent(value: ActivationIntent): ActivationIntent {
  try {
    return activationIntentSchema.parse(value);
  } catch {
    throw new ActivationRpcError("invalid-response");
  }
}

function assertTransactionMatches(
  transaction: RpcTransaction,
  transactionHash: string,
  intent: ActivationIntent,
): void {
  let from: string;
  let to: string;
  let valueWei: string;
  let calldataSha256: string;
  try {
    from = getAddress(transaction.from).toLowerCase();
    if (transaction.to === null) throw new Error("contract creation is not allowed");
    to = getAddress(transaction.to).toLowerCase();
    valueWei = parseQuantity(transaction.value).toString();
    calldataSha256 = sha256Calldata(transaction.input);
  } catch (error) {
    if (error instanceof ActivationRpcError) throw error;
    throw new ActivationRpcError("invalid-response");
  }
  if (
    canonicalBlockHash(transaction.hash) !== transactionHash ||
    from !== intent.from ||
    to !== intent.to ||
    valueWei !== intent.valueWei ||
    calldataSha256 !== intent.calldataSha256
  ) {
    throw new ActivationRpcError("invalid-response");
  }
}

function rpcReceipt(value: unknown): RpcReceipt {
  if (
    !isRecord(value) ||
    typeof value.transactionHash !== "string" ||
    typeof value.status !== "string" ||
    typeof value.blockNumber !== "string" ||
    typeof value.blockHash !== "string" ||
    !Array.isArray(value.logs)
  ) {
    throw new ActivationRpcError("invalid-response");
  }
  const logs = value.logs.map((log) => {
    if (
      !isRecord(log) ||
      typeof log.address !== "string" ||
      typeof log.data !== "string" ||
      !Array.isArray(log.topics) ||
      !log.topics.every((topic) => typeof topic === "string")
    ) {
      throw new ActivationRpcError("invalid-response");
    }
    return {
      address: log.address,
      data: log.data,
      topics: log.topics,
    };
  });
  return {
    transactionHash: value.transactionHash,
    status: value.status,
    blockNumber: value.blockNumber,
    blockHash: value.blockHash,
    logs,
  };
}

function implementationAddress(value: Hex): string {
  if (value.length !== 66) throw new ActivationRpcError("invalid-response");
  return getAddress(`0x${value.slice(-40)}`).toLowerCase();
}

function nonEmptyCode(value: Hex): Hex {
  if (value === "0x") throw new ActivationRpcError("invalid-response");
  return value;
}

function canonicalBlockHash(value: string): `0x${string}` {
  if (!/^0x[0-9a-f]{64}$/.test(value)) {
    throw new ActivationRpcError("invalid-response");
  }
  return value as `0x${string}`;
}

function parseQuantity(value: unknown): bigint {
  if (typeof value !== "string" || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/.test(value)) {
    throw new ActivationRpcError("invalid-response");
  }
  return BigInt(value);
}

function parseDecimal(value: string): bigint {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new ActivationRpcError("invalid-response");
  }
  return BigInt(value);
}

function parseReceiptStatus(value: string): "success" | "reverted" {
  if (value === "0x1") return "success";
  if (value === "0x0") return "reverted";
  throw new ActivationRpcError("invalid-response");
}

function boundedConfirmationDepth(value: bigint): number {
  if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new ActivationRpcError("invalid-response");
  }
  return Number(value);
}

function rpcErrorKind(
  value: unknown,
): "unavailable" | "invalid-response" | "noncanonical" {
  if (!isRecord(value) || typeof value.code !== "number") {
    return "invalid-response";
  }
  const message = typeof value.message === "string" ? value.message : "";
  return /header not found|block not found|unknown block|non-?canonical|not canonical|missing trie node/i.test(
    message,
  )
    ? "noncanonical"
    : "unavailable";
}

function hexResult(value: unknown): Hex {
  if (typeof value !== "string" || !/^0x(?:[0-9a-f]{2})*$/.test(value)) {
    throw new ActivationRpcError("invalid-response");
  }
  return value as Hex;
}

function addressResult(value: unknown): string {
  if (typeof value !== "string") throw new ActivationRpcError("invalid-response");
  return getAddress(value).toLowerCase();
}

function booleanResult(value: unknown): boolean {
  if (typeof value !== "boolean") throw new ActivationRpcError("invalid-response");
  return value;
}

function bigintResult(value: unknown): bigint {
  if (typeof value !== "bigint") throw new ActivationRpcError("invalid-response");
  return value;
}

function bigintLike(value: unknown): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isSafeInteger(value)) return BigInt(value);
  throw new ActivationRpcError("invalid-response");
}

function addressLike(value: unknown): string {
  if (typeof value !== "string") throw new ActivationRpcError("invalid-response");
  return getAddress(value).toLowerCase();
}

function stringLike(value: unknown): string {
  if (typeof value !== "string") throw new ActivationRpcError("invalid-response");
  return value;
}

function sha256Calldata(value: string): string {
  const data = hexResult(value);
  return createHash("sha256")
    .update(Buffer.from(data.slice(2), "hex"))
    .digest("hex");
}

function required(value: string | undefined): string {
  if (value === undefined) throw new ActivationRpcError("invalid-response");
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
