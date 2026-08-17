import assert from "node:assert/strict";

import {
  ERC8183Client,
  JobStatus,
} from "@bnbagent/sdk";
import { BNB_CHAIN_ADDRESSES } from "@bnbagent/sdk/networks";
import {
  type ExecutionContext,
  type Intent,
  type IntentExecutor,
  type TxResult,
  WalletProvider,
} from "@bnbagent/sdk/wallets";
import {
  createPublicClient,
  createWalletClient,
  decodeEventLog,
  encodeFunctionData,
  getAddress,
  http,
  keccak256,
  parseAbi,
  parseAbiItem,
  toHex,
  type Address,
  type Hex,
  type PublicClient,
  type TransactionReceipt,
} from "viem";

const RPC_URL = "http://127.0.0.1:18545";
const SDK_DEPLOYMENT = BNB_CHAIN_ADDRESSES[56];
if (SDK_DEPLOYMENT === undefined) throw new Error("SDK has no BSC mainnet deployment");
// The Commerce proxy was upgraded after SDK 0.5.0 was published. The fork
// proof deliberately pins the live EIP-1967 implementation instead of
// accepting the stale SDK implementation entry.
const DEPLOYMENT = {
  ...SDK_DEPLOYMENT,
  commerceImpl: "0xd5f9b570c96b5d67702d508c0bfb8b3b09209787",
} as const;

const REGISTRY = "0x8004a169fb4a3325136eb29fa0ceb6d2e539a432";
const EIP1967_IMPLEMENTATION_SLOT =
  "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" as const;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000" as const;

const topologyAbi = parseAbi([
  "function paymentToken() view returns (address)",
  "function commerce() view returns (address)",
  "function router() view returns (address)",
  "function policyWhitelist(address) view returns (bool)",
  "function paused() view returns (bool)",
]);

const jobFundedEvent = parseAbiItem(
  "event JobFunded(uint256 indexed jobId, address indexed client, address indexed provider, uint256 amount)",
);
const jobFundedTopic = keccak256(
  toHex("JobFunded(uint256,address,address,uint256)"),
);
const transferTopic = keccak256(toHex("Transfer(address,address,uint256)"));
const approvalTopic = keccak256(toHex("Approval(address,address,uint256)"));

type CapturedExecution = Readonly<{
  intent: Intent;
  sender: Address;
  target: Address;
  value: bigint;
  data: Hex;
  transactionHash: Hex;
  receipt: TransactionReceipt;
}>;

class UnlockedAnvilWallet extends WalletProvider {
  readonly #address: Address;
  readonly executions: CapturedExecution[] = [];

  constructor(address: Address) {
    super();
    this.#address = address;
  }

  get address(): Address {
    return this.#address;
  }

  override makeExecutor(context: ExecutionContext): IntentExecutor {
    return {
      execute: async (intent) => this.#execute(context.client, intent),
    };
  }

  async #execute(client: PublicClient, intent: Intent): Promise<TxResult> {
    const call = intent.call;
    assert.ok(call, "SDK intent must carry a mechanical contract call");
    const target = getAddress(call.address);
    const value = intent.value ?? 0n;
    const data = encodeFunctionData({
      abi: call.abi,
      functionName: call.functionName,
      args: call.args,
    });
    const walletClient = createWalletClient({
      account: this.address,
      transport: http(RPC_URL),
    });
    const transactionHash = await walletClient.sendTransaction({
      account: this.address,
      chain: null,
      to: target,
      data,
      value,
    });
    const receipt = await client.waitForTransactionReceipt({
      hash: transactionHash,
      confirmations: 1,
    });
    assert.equal(receipt.status, "success", `${intent.name} reverted on the fork`);

    const transaction = await client.getTransaction({ hash: transactionHash });
    assert.equal(getAddress(transaction.from), this.address);
    assert.equal(transaction.to === null ? null : getAddress(transaction.to), target);
    assert.equal(transaction.value, value);
    assert.equal(transaction.input.toLowerCase(), data.toLowerCase());

    this.executions.push({
      intent,
      sender: this.address,
      target,
      value,
      data,
      transactionHash,
      receipt,
    });
    return { transactionHash, status: 1, receipt };
  }
}

async function main(): Promise<void> {
  const publicClient = createPublicClient({ transport: http(RPC_URL) });
  assert.equal(await publicClient.getChainId(), 56, "Anvil must be a BSC mainnet fork");
  const accounts = await createWalletClient({ transport: http(RPC_URL) }).getAddresses();
  assert.ok(accounts.length >= 2, "Anvil must expose at least two unlocked accounts");
  const clientAddress = getAddress(accounts[0]!);
  const providerAddress = getAddress(accounts[1]!);
  const wallet = new UnlockedAnvilWallet(clientAddress);

  const sdk = await ERC8183Client.create({
    walletProvider: wallet,
    network: {
      name: "mandatex-bsc-mainnet-fork",
      chainId: 56,
      rpcUrl: RPC_URL,
      usePaymaster: false,
      registryContract: REGISTRY,
      commerceContract: DEPLOYMENT.commerceProxy,
      routerContract: DEPLOYMENT.routerProxy,
      policyContract: DEPLOYMENT.policy,
    },
  });

  await assertDeploymentTopology(publicClient);

  const token = getAddress(await sdk.paymentToken());
  assert.equal(token, getAddress(DEPLOYMENT.paymentToken));
  const balanceBefore = await sdk.tokenBalance(clientAddress);
  const allowanceBefore = await sdk.tokenAllowance(
    clientAddress,
    getAddress(DEPLOYMENT.commerceProxy),
  );

  const latest = await publicClient.getBlock({ blockTag: "latest" });
  const disputeWindow = await sdk.policy.disputeWindow();
  const expiredAt = latest.timestamp + disputeWindow + 3_600n;
  const description = "MandateX zero-budget fork proof; no delivery is authorized";

  const created = await sdk.createJob({
    provider: providerAddress,
    expiredAt,
    description,
  });
  assert.notEqual(created.jobId, null, "SDK must recover JobCreated.jobId");
  const jobId = created.jobId!;
  await sdk.registerJob(jobId);
  await sdk.setBudget(jobId, 0n);
  await sdk.fund(jobId, 0n, { approveFloor: 0n });

  assert.deepEqual(
    wallet.executions.map((entry) => entry.intent.name),
    [
      "erc8183.create_job",
      "erc8183.register_job",
      "erc8183.set_budget",
      "erc8183.fund",
    ],
  );
  assert.deepEqual(
    wallet.executions.map((entry) => entry.target),
    [
      getAddress(DEPLOYMENT.commerceProxy),
      getAddress(DEPLOYMENT.routerProxy),
      getAddress(DEPLOYMENT.commerceProxy),
      getAddress(DEPLOYMENT.commerceProxy),
    ],
  );
  assert.ok(wallet.executions.every((entry) => entry.value === 0n));

  const job = await sdk.getJob(jobId);
  assert.equal(job.id, jobId);
  assert.equal(job.client, clientAddress);
  assert.equal(job.provider, providerAddress);
  assert.equal(job.evaluator, getAddress(DEPLOYMENT.routerProxy));
  assert.equal(job.hook, getAddress(DEPLOYMENT.routerProxy));
  assert.equal(job.description, description);
  assert.equal(job.budget, 0n);
  assert.equal(job.status, JobStatus.FUNDED);
  assert.equal(
    await sdk.router.jobPolicy(jobId),
    getAddress(DEPLOYMENT.policy),
  );

  const fundExecution = wallet.executions.at(-1)!;
  const fundedLogs = fundExecution.receipt.logs.filter(
    (log) =>
      log.address.toLowerCase() === DEPLOYMENT.commerceProxy.toLowerCase() &&
      log.topics[0]?.toLowerCase() === jobFundedTopic.toLowerCase(),
  );
  assert.equal(fundedLogs.length, 1, "fund(0) must emit exactly one JobFunded");
  const funded = decodeEventLog({
    abi: [jobFundedEvent],
    data: fundedLogs[0]!.data,
    topics: fundedLogs[0]!.topics,
  });
  assert.equal(funded.eventName, "JobFunded");
  assert.equal(funded.args.jobId, jobId);
  assert.equal(getAddress(funded.args.client), clientAddress);
  assert.equal(getAddress(funded.args.provider), providerAddress);
  assert.equal(funded.args.amount, 0n);

  const balanceAfter = await sdk.tokenBalance(clientAddress);
  const allowanceAfter = await sdk.tokenAllowance(
    clientAddress,
    getAddress(DEPLOYMENT.commerceProxy),
  );
  assert.equal(balanceAfter, balanceBefore, "fund(0) must not move payment tokens");
  assert.equal(allowanceAfter, allowanceBefore, "fund(0) must not alter allowance");

  const tokenWrites = wallet.executions.flatMap((entry) =>
    entry.receipt.logs.filter(
      (log) =>
        log.address.toLowerCase() === token.toLowerCase() &&
        (log.topics[0]?.toLowerCase() === transferTopic.toLowerCase() ||
          log.topics[0]?.toLowerCase() === approvalTopic.toLowerCase()),
    ),
  );
  assert.equal(tokenWrites.length, 0, "zero-budget lifecycle emitted a token write event");

  const codeHashes = await deploymentCodeHashes(publicClient);
  process.stdout.write(
    `${JSON.stringify(
      {
        proof: "mandatex.erc8183.zero-budget-fork.v1",
        chainId: 56,
        forkBlock: latest.number.toString(),
        jobId: jobId.toString(),
        protocolStatus: JobStatus[job.status],
        finalState: "FUNDED_NOT_DELIVERED",
        deliveryAuthorized: false,
        fundedAmount: "0",
        tokenBalanceUnchanged: true,
        tokenAllowanceUnchanged: true,
        tokenTransferOrApprovalEvents: 0,
        transactions: wallet.executions.map((entry) => ({
          operation: entry.intent.name,
          sender: entry.sender,
          target: entry.target,
          value: entry.value.toString(),
          calldataSha3: keccak256(entry.data),
          transactionHash: entry.transactionHash,
        })),
        codeHashes,
      },
      null,
      2,
    )}\n`,
  );
}

async function assertDeploymentTopology(client: PublicClient): Promise<void> {
  const commerceProxy = getAddress(DEPLOYMENT.commerceProxy);
  const routerProxy = getAddress(DEPLOYMENT.routerProxy);
  const policy = getAddress(DEPLOYMENT.policy);

  assert.equal(
    getAddress(
      await client.readContract({
        address: commerceProxy,
        abi: topologyAbi,
        functionName: "paymentToken",
      }),
    ),
    getAddress(DEPLOYMENT.paymentToken),
  );
  assert.equal(
    getAddress(
      await client.readContract({
        address: routerProxy,
        abi: topologyAbi,
        functionName: "commerce",
      }),
    ),
    commerceProxy,
  );
  assert.equal(
    getAddress(
      await client.readContract({
        address: policy,
        abi: topologyAbi,
        functionName: "commerce",
      }),
    ),
    commerceProxy,
  );
  assert.equal(
    getAddress(
      await client.readContract({
        address: policy,
        abi: topologyAbi,
        functionName: "router",
      }),
    ),
    routerProxy,
  );
  assert.equal(
    await client.readContract({
      address: commerceProxy,
      abi: topologyAbi,
      functionName: "paused",
    }),
    false,
  );
  assert.equal(
    await client.readContract({
      address: routerProxy,
      abi: topologyAbi,
      functionName: "policyWhitelist",
      args: [policy],
    }),
    true,
  );
  assert.equal(
    await client.readContract({
      address: routerProxy,
      abi: topologyAbi,
      functionName: "paused",
    }),
    false,
  );

  assert.equal(
    await proxyImplementation(client, commerceProxy),
    getAddress(DEPLOYMENT.commerceImpl),
  );
  assert.equal(
    await proxyImplementation(client, routerProxy),
    getAddress(DEPLOYMENT.routerImpl),
  );

  for (const address of [
    commerceProxy,
    routerProxy,
    getAddress(DEPLOYMENT.commerceImpl),
    getAddress(DEPLOYMENT.routerImpl),
    policy,
    getAddress(DEPLOYMENT.paymentToken),
  ]) {
    assert.notEqual(await client.getCode({ address }), undefined, `${address} has no code`);
  }
}

async function proxyImplementation(
  client: PublicClient,
  proxy: Address,
): Promise<Address> {
  const raw = await client.getStorageAt({
    address: proxy,
    slot: EIP1967_IMPLEMENTATION_SLOT,
  });
  assert.ok(raw, `${proxy} has no EIP-1967 implementation slot`);
  const address = `0x${raw.slice(-40)}` as Address;
  assert.notEqual(getAddress(address), ZERO_ADDRESS);
  return getAddress(address);
}

async function deploymentCodeHashes(client: PublicClient) {
  const entries = {
    commerceProxy: DEPLOYMENT.commerceProxy,
    commerceImplementation: DEPLOYMENT.commerceImpl,
    routerProxy: DEPLOYMENT.routerProxy,
    routerImplementation: DEPLOYMENT.routerImpl,
    policy: DEPLOYMENT.policy,
    paymentToken: DEPLOYMENT.paymentToken,
  } as const;
  return Object.fromEntries(
    await Promise.all(
      Object.entries(entries).map(async ([name, rawAddress]) => {
        const address = getAddress(rawAddress);
        const code = await client.getCode({ address });
        assert.ok(code && code !== "0x", `${name} has empty runtime code`);
        return [name, { address, runtimeCodeHash: keccak256(code) }];
      }),
    ),
  );
}

void main().catch((error: unknown) => {
  process.stderr.write(
    `${error instanceof Error ? error.stack ?? error.message : String(error)}\n`,
  );
  process.exitCode = 1;
});
