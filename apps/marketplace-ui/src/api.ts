import type { ComparisonView } from "@mandatex/marketplace-api/dist/display.js";

export type { ComparisonView };
export type {
  DisplayCandidate,
  DisplayConfirmation,
  DisplayFactor,
  DisplayFinding,
  DisplayScore,
} from "@mandatex/marketplace-api/dist/display.js";

/**
 * Client for the marketplace API.
 *
 * The types above are imported from the API package rather than restated here, so
 * a change to the comparison payload is a compile error in this UI instead of a
 * field that silently renders as blank. That matters most for the ranking split:
 * if `confirmations` were ever renamed, a locally-redeclared type would let this
 * UI keep rendering four factors and quietly stop disclosing the two pinned ones.
 *
 * This module performs no evaluation, ranking, or verification. Every verdict is
 * computed by Core inside the API; the UI's job is to not misrepresent it.
 */

export interface FixtureBundle {
  readonly warning: string;
  readonly trustPinned: string;
  readonly mandate: unknown;
  readonly note: string;
  readonly comparisonSet: readonly string[];
  readonly notInComparisonSet: readonly { readonly name: unknown; readonly reason: string }[];
  readonly count: number;
}

export type ApiResult<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly status: number; readonly detail: string };

export class MarketplaceApiClient {
  constructor(
    private readonly baseUrl: string,
    private readonly timeoutMs = 15_000,
  ) {}

  get base(): string {
    return this.baseUrl;
  }

  /**
   * Development fixtures. Absent in production by design, so a 404 here is a
   * normal state and is surfaced as such rather than as a fault.
   */
  async fixtures(): Promise<ApiResult<FixtureBundle>> {
    return this.request<FixtureBundle>("GET", "/v1/fixtures");
  }

  async evaluate(input: {
    readonly mandate: unknown;
    readonly attestations: readonly string[];
  }): Promise<ApiResult<ComparisonView>> {
    return this.request<ComparisonView>("POST", "/v1/evaluate", input);
  }

  async readyz(): Promise<ApiResult<unknown>> {
    return this.request<unknown>("GET", "/readyz");
  }

  private async request<T>(
    method: "GET" | "POST",
    path: string,
    body?: unknown,
  ): Promise<ApiResult<T>> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method,
        signal: controller.signal,
        ...(body === undefined
          ? {}
          : {
              headers: { "content-type": "application/json" },
              body: JSON.stringify(body),
            }),
      });
      const text = await response.text();
      let parsed: unknown;
      try {
        parsed = text.length === 0 ? null : JSON.parse(text);
      } catch {
        return {
          ok: false,
          status: response.status,
          detail: `the API returned a non-JSON body (${response.status})`,
        };
      }
      if (!response.ok) {
        // The API's error bodies carry a code and message. Preserve them: a
        // 422 DUPLICATE_CANDIDATE is a precise, actionable answer, and
        // flattening it to "request failed" would throw away the only useful
        // part of the response.
        return { ok: false, status: response.status, detail: describe(parsed, response.status) };
      }
      return { ok: true, value: parsed as T };
    } catch (cause) {
      const aborted = cause instanceof Error && cause.name === "AbortError";
      return {
        ok: false,
        status: 0,
        detail: aborted
          ? `the marketplace API at ${this.baseUrl} did not respond within ${this.timeoutMs}ms`
          : `the marketplace API at ${this.baseUrl} is unreachable`,
      };
    } finally {
      clearTimeout(timer);
    }
  }
}

function describe(parsed: unknown, status: number): string {
  if (typeof parsed === "object" && parsed !== null) {
    const record = parsed as Record<string, unknown>;
    const code = typeof record.code === "string" ? record.code : undefined;
    const message =
      typeof record.message === "string"
        ? record.message
        : typeof record.error === "string"
          ? record.error
          : undefined;
    if (code !== undefined && message !== undefined) return `${code}: ${message}`;
    if (code !== undefined) return code;
    if (message !== undefined) return message;
  }
  return `the API rejected the request with status ${status}`;
}
