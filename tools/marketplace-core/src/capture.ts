import {
  MarketplaceCoreError,
  type MarketplaceErrorCode,
} from "./errors.js";
import { deepFreeze, type DeepReadonly } from "./immutable.js";
import {
  displaySafeQuoteProjectionPayloadSchema,
  displaySafeQuoteProjectionSchema,
  type DisplaySafeQuoteProjection,
  type DisplaySafeQuoteProjectionPayload,
} from "./schemas.js";

declare const capturedProjectionBrand: unique symbol;
export type CapturedDisplaySafeQuoteProjection = DeepReadonly<
  DisplaySafeQuoteProjection
> & { readonly [capturedProjectionBrand]: true };

export interface TrustedProjectionIngress {
  capture(payload: DisplaySafeQuoteProjectionPayload): CapturedDisplaySafeQuoteProjection;
}

export interface ProjectionCapability {
  readonly assertCaptured: (
    value: unknown,
  ) => asserts value is CapturedDisplaySafeQuoteProjection;
}

function observeThenableRejection(
  value: unknown,
  code: MarketplaceErrorCode,
  label: string,
): boolean {
  if (
    value === null ||
    (typeof value !== "object" && typeof value !== "function")
  ) {
    return false;
  }
  let then: unknown;
  try {
    then = (value as { then?: unknown }).then;
  } catch (cause) {
    throw new MarketplaceCoreError(
      code,
      `${label} returned an unreadable result`,
      { cause },
    );
  }
  if (typeof then !== "function") return false;
  try {
    void Promise.resolve(value).catch(() => undefined);
  } catch (cause) {
    throw new MarketplaceCoreError(
      code,
      `${label} returned an invalid asynchronous result`,
      { cause },
    );
  }
  return true;
}

export function readCoreClock(clock: () => number): number {
  let value: unknown;
  try {
    value = clock();
  } catch (cause) {
    throw new MarketplaceCoreError(
      "CORE_CLOCK_INVALID",
      "the Marketplace Core clock threw while reading Unix seconds",
      { cause },
    );
  }
  if (observeThenableRejection(value, "CORE_CLOCK_INVALID", "the Marketplace Core clock")) {
    throw new MarketplaceCoreError(
      "CORE_CLOCK_INVALID",
      "the Marketplace Core clock must return synchronously",
    );
  }
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value <= 0
  ) {
    throw new MarketplaceCoreError(
      "CORE_CLOCK_INVALID",
      "the Marketplace Core clock must return positive Unix seconds",
    );
  }
  return value;
}

export function createProjectionCapability(
  installTrustedProjectionIngress: (
    ingress: TrustedProjectionIngress,
  ) => undefined,
  clock: () => number,
): ProjectionCapability {
  if (typeof installTrustedProjectionIngress !== "function") {
    throw new MarketplaceCoreError(
      "TRUSTED_INGRESS_INSTALLER_INVALID",
      "a trusted projection ingress installer function is required",
    );
  }
  if (typeof clock !== "function") {
    throw new MarketplaceCoreError(
      "CORE_CLOCK_INVALID",
      "the Marketplace Core clock must be a function",
    );
  }
  const capturedProjections = new WeakSet<object>();
  const ingress: TrustedProjectionIngress = Object.freeze({
    capture(payload: DisplaySafeQuoteProjectionPayload) {
      const parsedPayloadResult =
        displaySafeQuoteProjectionPayloadSchema.safeParse(payload);
      if (!parsedPayloadResult.success) {
        throw new MarketplaceCoreError(
          "TRUSTED_PROJECTION_INVALID",
          "trusted projection payload is invalid or contains reserved capture metadata",
          { cause: parsedPayloadResult.error },
        );
      }
      const parsedPayload = parsedPayloadResult.data;
      const capturedAt = readCoreClock(clock);
      const projectionResult = displaySafeQuoteProjectionSchema.safeParse({
        schema: "mandatex.marketplace.display-safe-quote-projection.v1",
        captureContext: "trusted-quote-validation-success",
        capturedAt,
        ...parsedPayload,
      });
      if (!projectionResult.success) {
        throw new MarketplaceCoreError(
          "TRUSTED_PROJECTION_INVALID",
          "trusted projection chronology or content is invalid",
          { cause: projectionResult.error },
        );
      }
      const parsed = projectionResult.data;
      const captured = deepFreeze(parsed) as CapturedDisplaySafeQuoteProjection;
      capturedProjections.add(captured);
      return captured;
    },
  });
  let installationResult: unknown;
  try {
    installationResult = installTrustedProjectionIngress(ingress);
  } catch (cause) {
    throw new MarketplaceCoreError(
      "TRUSTED_INGRESS_INSTALLER_INVALID",
      "the trusted projection ingress installer threw",
      { cause },
    );
  }
  if (
    observeThenableRejection(
      installationResult,
      "TRUSTED_INGRESS_INSTALLER_INVALID",
      "the trusted projection ingress installer",
    )
  ) {
    throw new MarketplaceCoreError(
      "TRUSTED_INGRESS_INSTALLER_INVALID",
      "the trusted projection ingress installer must complete synchronously",
    );
  }
  return Object.freeze({
    assertCaptured(
      value: unknown,
    ): asserts value is CapturedDisplaySafeQuoteProjection {
      if (
        value === null ||
        typeof value !== "object" ||
        !capturedProjections.has(value)
      ) {
        throw new MarketplaceCoreError(
          "DISPLAY_SAFE_PROJECTION_NOT_CAPTURED_BY_CORE",
          "this Marketplace Core instance only accepts projections captured by its installed trusted ingress",
        );
      }
    },
  });
}
