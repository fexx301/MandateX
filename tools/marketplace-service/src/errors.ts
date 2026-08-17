export type MarketplaceServiceErrorCode =
  | "ARTIFACT_INTEGRITY_INVALID"
  | "ARTIFACT_MISMATCH"
  | "ATTESTATION_EXPIRY_INVALID"
  | "ATTESTATION_SIGNER_INVALID"
  | "CLOCK_INVALID"
  | "MAPPING_FAILED"
  | "REQUEST_INVALID"
  | "SIGNING_FAILED"
  | "VERIFIER_CONFIGURATION_INVALID"
  | "VERIFIER_EVALUATION_FAILED"
  | "VERIFIER_POLICY_MISMATCH";

export class MarketplaceServiceError extends Error {
  readonly code: MarketplaceServiceErrorCode;

  constructor(
    code: MarketplaceServiceErrorCode,
    message: string,
    options: ErrorOptions = {},
  ) {
    super(message, options);
    this.name = "MarketplaceServiceError";
    this.code = code;
  }
}
