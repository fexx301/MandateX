export type MarketplaceServiceErrorCode =
  | "ACKNOWLEDGEMENT_REQUIRED"
  | "CANDIDATE_LIMIT_EXCEEDED"
  | "CANDIDATE_NOT_CONFIGURED"
  | "CLOCK_INVALID"
  | "CORE_EVALUATION_FAILED"
  | "DUPLICATE_SELECTOR"
  | "MAPPING_FAILED"
  | "REQUEST_INVALID"
  | "SERVICE_OPTIONS_INVALID"
  | "VERIFIER_API_UNAVAILABLE";

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
