import { randomUUID as nodeRandomUUID } from "node:crypto";

import { buildJobDescription } from "@bnbagent/sdk/erc8183";
import { getAddress } from "viem";

import {
  validateTrustedPreviewForActivation,
  type TrustedRebalanceActivationProjection,
  type ValidateTrustedPreviewDependencies,
  type ValidateTrustedPreviewOptions,
} from "../preview/validate.js";
import type {
  ActivationReplayStore,
  ReplayStore,
} from "../quotes/replay.js";
import {
  canonicalQuoteJson,
  computeQuoteSha256,
} from "../quotes/protocol.js";
import {
  BSC_ACTIVATION_DEPLOYMENT,
} from "./deployment.js";
import {
  activationPreviewSchema,
  type ActivationPreview,
  type ActivationState,
} from "./schema.js";
import { TransportActivationRpc } from "./rpc.js";
import { prepareCreateActivation } from "./state.js";
import {
  bootstrapActivationSnapshot,
  type BootstrapActivationSnapshotResult,
} from "./store.js";

export interface PrepareTrustedActivationOptions
  extends Omit<
    ValidateTrustedPreviewOptions,
    "replayCommit" | "replayStore"
  > {
  readonly replayStore: ReplayStore & ActivationReplayStore;
  readonly activationStateDirectory: string;
  readonly reportDirectory: string;
  readonly client: string;
  readonly jobExpiresAt: number;
  readonly cleanupOwner: ActivationState["cleanup"]["owner"];
  readonly acknowledgePublicJobDescription: true;
  readonly acknowledgeBuyerAddressNotProviderSigned: true;
}

export type PrepareTrustedActivationResult = Readonly<{
  previewSidecar: Awaited<ReturnType<typeof validateTrustedPreviewForActivation>>["sidecar"];
  bootstrap?: BootstrapActivationSnapshotResult;
}>;

export interface PrepareTrustedActivationDependencies
  extends Omit<ValidateTrustedPreviewDependencies, "captureProjection"> {
  readonly activationRpc?: Pick<TransportActivationRpc, "observeDeployment">;
  readonly previewValidator?: typeof validateTrustedPreviewForActivation;
  readonly prepareCreate?: typeof prepareCreateActivation;
  readonly bootstrap?: typeof bootstrapActivationSnapshot;
}

export async function prepareTrustedActivation(
  options: PrepareTrustedActivationOptions,
  dependencies: PrepareTrustedActivationDependencies = {},
): Promise<PrepareTrustedActivationResult> {
  if (
    options.acknowledgePublicJobDescription !== true ||
    options.acknowledgeBuyerAddressNotProviderSigned !== true
  ) {
    throw new Error("activation acknowledgements are required before validation");
  }
  let bootstrap: BootstrapActivationSnapshotResult | undefined;
  const result = await (
    dependencies.previewValidator ?? validateTrustedPreviewForActivation
  )(
    {
      ...options,
      replayCommit: async (candidate) => {
        const projection = candidate.projection;
        const initialPreview = activationPreview(projection);
        if (projection.verification.price !== "0") {
          throw new Error("MandateX activation currently rejects nonzero quotes");
        }
        const binding = {
          chainId: 56 as const,
          tokenId: options.candidate.tokenId,
          client: getAddress(options.client).toLowerCase(),
          provider: getAddress(
            projection.verification.validatedProvider,
          ).toLowerCase(),
          commerceProxy: BSC_ACTIVATION_DEPLOYMENT.commerceProxy,
          commerceImplementation:
            BSC_ACTIVATION_DEPLOYMENT.commerceImplementation,
          commerceImplementationCodeHash:
            BSC_ACTIVATION_DEPLOYMENT.commerceImplementationCodeHash,
          routerProxy: BSC_ACTIVATION_DEPLOYMENT.routerProxy,
          routerImplementation: BSC_ACTIVATION_DEPLOYMENT.routerImplementation,
          routerImplementationCodeHash:
            BSC_ACTIVATION_DEPLOYMENT.routerImplementationCodeHash,
          policy: BSC_ACTIVATION_DEPLOYMENT.policy,
          paymentToken: BSC_ACTIVATION_DEPLOYMENT.paymentToken,
          paymentTokenCodeHash: BSC_ACTIVATION_DEPLOYMENT.paymentTokenCodeHash,
          localReplayOnly: true as const,
          replayKey: candidate.replayKey,
          negotiationHash: projection.verification.negotiationHash,
          mandateSha256: computeQuoteSha256(
            canonicalQuoteJson(projection.mandate),
          ),
          signedTaskSha256: computeQuoteSha256(
            canonicalQuoteJson(projection.signedTask),
          ),
          transactionPlanSha256: projection.decodedPlan.transactionPlanSha256,
          previewSidecarSha256: computeQuoteSha256(
            canonicalQuoteJson(candidate.previewSidecar),
          ),
          initialPreviewSha256: computeQuoteSha256(
            canonicalQuoteJson(initialPreview),
          ),
          previewBlockNumber: initialPreview.blockNumber,
          previewBlockHash: initialPreview.blockHash,
          negotiatedAt: projection.verification.negotiatedAt,
          quoteExpiresAt: projection.verification.quoteExpiresAt,
          jobExpiresAt: options.jobExpiresAt,
          price: "0" as const,
          currency: getAddress(
            projection.verification.currency,
          ).toLowerCase(),
          jobDescription: buildJobDescription(
            projection.envelope as unknown as Record<string, unknown>,
          ),
        };

        const activationRpc =
          dependencies.activationRpc ??
          new TransportActivationRpc(
            options.transport,
            options.randomUUID ?? nodeRandomUUID,
          );
        const deployment = await activationRpc.observeDeployment();
        const state = await (
          dependencies.prepareCreate ?? prepareCreateActivation
        )({
          binding,
          signedTask: projection.signedTask,
          transactionPlan: projection.decodedPlan.plan,
          initialPreview,
          deployment,
          cleanupOwner: options.cleanupOwner,
        });
        bootstrap = await (
          dependencies.bootstrap ?? bootstrapActivationSnapshot
        )({
          state,
          deployment,
          replayKey: candidate.replayKey,
          replayMetadata: candidate.replayMetadata,
          replayStore: options.replayStore,
          stateDirectory: options.activationStateDirectory,
          reportDirectory: options.reportDirectory,
        });
        return bootstrap.status;
      },
    },
    dependencies,
  );
  if (
    result.sidecar.outcome !== "preview_simulation_passed" ||
    result.projection === undefined
  ) {
    return { previewSidecar: result.sidecar };
  }
  if (bootstrap === undefined) {
    throw new Error("passing activation preview was not durably bootstrapped");
  }
  return { previewSidecar: result.sidecar, bootstrap };
}

function activationPreview(
  projection: TrustedRebalanceActivationProjection,
): ActivationPreview {
  const blockTimestamp = Math.floor(
    Number(projection.preview.snapshot.pin.observedAt),
  );
  if (
    !/^(?:0|[1-9][0-9]*)$/.test(
      projection.preview.snapshot.pin.observedAt,
    ) ||
    !Number.isSafeInteger(blockTimestamp) ||
    blockTimestamp <= 0
  ) {
    throw new Error("activation preview returned an invalid block timestamp");
  }
  const validUntil = Math.min(
    projection.verification.quoteExpiresAt,
    projection.preview.policy.deadline,
    projection.signedTask.mandate.expires_at,
    projection.signedTask.mandate.permissions.expires_at,
  );
  return activationPreviewSchema.parse({
    schema: "mandatex.erc8183.activation-preview.v1",
    observedAt: new Date(blockTimestamp * 1_000).toISOString(),
    blockNumber: projection.preview.snapshot.pin.observedBlockNumber,
    blockHash: projection.preview.snapshot.pin.observedBlockHash,
    blockTimestamp,
    quoteExpiresAt: projection.verification.quoteExpiresAt,
    transactionPlanSha256: projection.decodedPlan.transactionPlanSha256,
    signedTaskSha256: computeQuoteSha256(
      canonicalQuoteJson(projection.signedTask),
    ),
    allGatesPass: true,
    validUntil,
  });
}
