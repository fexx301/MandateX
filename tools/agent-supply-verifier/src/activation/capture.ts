import { createHash } from "node:crypto";

import { CommerceClient, RouterClient } from "@bnbagent/sdk/erc8183";
import {
  type ExecutionContext,
  type Intent,
  type IntentExecutor,
  WalletProvider,
} from "@bnbagent/sdk/wallets";
import {
  createPublicClient,
  custom,
  encodeFunctionData,
  getAddress,
  type Address,
  type Hex,
} from "viem";

import {
  BSC_ACTIVATION_DEPLOYMENT,
} from "./deployment.js";
import {
  activationIntentSchema,
  type ActivationIntent,
  type ActivationOperation,
} from "./schema.js";

const SDK_INTENT_NAMES: Readonly<Record<ActivationOperation, string>> = {
  create_job: "erc8183.create_job",
  register_job: "erc8183.register_job",
  set_budget: "erc8183.set_budget",
  fund: "erc8183.fund",
};

export type CaptureActivationIntentInput =
  | Readonly<{
      operation: "create_job";
      client: string;
      provider: string;
      expiredAt: bigint;
      description: string;
    }>
  | Readonly<{
      operation: "register_job" | "set_budget" | "fund";
      client: string;
      jobId: bigint;
    }>;

export class ActivationIntentCaptured extends Error {
  constructor(readonly prepared: ActivationIntent) {
    super("SDK activation intent captured; execution intentionally stopped");
    this.name = "ActivationIntentCaptured";
  }
}

class CaptureOnlyWallet extends WalletProvider {
  readonly #address: Address;
  captured: ActivationIntent | undefined;

  constructor(address: Address) {
    super();
    this.#address = address;
  }

  get address(): Address {
    return this.#address;
  }

  override makeExecutor(_context: ExecutionContext): IntentExecutor {
    return {
      execute: async (intent) => {
        if (this.captured !== undefined) {
          throw new Error("capture wallet received more than one SDK intent");
        }
        const prepared = prepareIntent(this.address, intent);
        this.captured = prepared;
        throw new ActivationIntentCaptured(prepared);
      },
    };
  }
}

export async function captureActivationIntent(
  input: CaptureActivationIntentInput,
): Promise<ActivationIntent> {
  const clientAddress = getAddress(input.client);
  const wallet = new CaptureOnlyWallet(clientAddress);
  const publicClient = createPublicClient({
    transport: custom({
      async request() {
        throw new Error("capture-only SDK client attempted an RPC request");
      },
    }),
  });
  const commerce = new CommerceClient(
    publicClient,
    BSC_ACTIVATION_DEPLOYMENT.commerceProxy,
    wallet,
  );
  const router = new RouterClient(
    publicClient,
    BSC_ACTIVATION_DEPLOYMENT.routerProxy,
    wallet,
  );

  try {
    switch (input.operation) {
      case "create_job":
        await commerce.createJob({
          provider: getAddress(input.provider),
          evaluator: BSC_ACTIVATION_DEPLOYMENT.routerProxy,
          expiredAt: input.expiredAt,
          description: input.description,
          hook: BSC_ACTIVATION_DEPLOYMENT.routerProxy,
        });
        break;
      case "register_job":
        await router.registerJob(
          input.jobId,
          BSC_ACTIVATION_DEPLOYMENT.policy,
        );
        break;
      case "set_budget":
        await commerce.setBudget(input.jobId, 0n);
        break;
      case "fund":
        await commerce.fund(input.jobId, 0n);
        break;
    }
  } catch (error) {
    if (error instanceof ActivationIntentCaptured) {
      assertCapturedOperation(error.prepared, input.operation);
      return error.prepared;
    }
    throw error;
  }
  throw new Error("SDK write returned without the capture sentinel");
}

function prepareIntent(sender: Address, intent: Intent): ActivationIntent {
  if (intent.call === null || intent.call === undefined) {
    throw new Error("SDK activation intent has no mechanical call");
  }
  const operation = operationForIntentName(intent.name);
  const data = encodeFunctionData({
    abi: intent.call.abi,
    functionName: intent.call.functionName,
    args: intent.call.args,
  }).toLowerCase() as Hex;
  const value = intent.value ?? 0n;
  if (value !== 0n) {
    throw new Error("activation intents must have zero native value");
  }
  return activationIntentSchema.parse({
    operation,
    from: sender,
    to: getAddress(intent.call.address),
    valueWei: "0",
    data,
    calldataSha256: createHash("sha256")
      .update(Buffer.from(data.slice(2), "hex"))
      .digest("hex"),
  });
}

function operationForIntentName(name: string | undefined): ActivationOperation {
  const entry = Object.entries(SDK_INTENT_NAMES).find(
    ([, expected]) => name === expected,
  );
  if (entry === undefined) {
    throw new Error("SDK emitted an unauthorized activation intent");
  }
  return entry[0] as ActivationOperation;
}

function assertCapturedOperation(
  intent: ActivationIntent,
  expected: ActivationOperation,
): void {
  if (intent.operation !== expected) {
    throw new Error("SDK activation intent did not match the requested phase");
  }
  const expectedTarget =
    expected === "register_job"
      ? BSC_ACTIVATION_DEPLOYMENT.routerProxy
      : BSC_ACTIVATION_DEPLOYMENT.commerceProxy;
  if (intent.to !== expectedTarget) {
    throw new Error("SDK activation intent targeted an unexpected contract");
  }
}
