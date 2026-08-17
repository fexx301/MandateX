/**
 * Mandate input.
 *
 * A Core mandate is a deep object with interlocking timestamp rules, so this form
 * edits a *base* mandate rather than building one from nothing. The base comes
 * from the API's `/v1/fixtures`, which matters for a non-obvious reason: the
 * fixture attestations are frozen at a fixed instant, and their quotes are
 * checked against `mandate.createdAt` for ordering. A form that invented
 * `createdAt = now` would make every fixture quote fail as preceding its own
 * mandate, and the UI would look broken when it was the input that was wrong.
 *
 * So the editable surface is the part a user actually reasons about — budgets,
 * permission ceilings and freshness windows — layered over a coherent base. A raw
 * JSON escape hatch is offered for full control.
 */

/** Editable scalar fields, addressed by path into the mandate. */
export interface MandateField {
  readonly name: string;
  readonly label: string;
  readonly path: readonly string[];
  readonly kind: "integer" | "decimalString" | "text" | "csv";
  readonly hint?: string;
}

export const MANDATE_FIELDS: readonly MandateField[] = Object.freeze([
  {
    name: "mandateId",
    label: "Mandate ID",
    path: ["mandateId"],
    kind: "text",
  },
  {
    name: "maxAgentFeeUsdMicros",
    label: "Max agent fee",
    path: ["budgets", "maxAgentFeeUsdMicros"],
    kind: "decimalString",
    hint: "USD micros. The fixture set quotes a zero fee.",
  },
  {
    name: "maxGasUsdMicros",
    label: "Max gas",
    path: ["budgets", "maxGasUsdMicros"],
    kind: "decimalString",
    hint: "USD micros.",
  },
  {
    name: "maxSlippageBps",
    label: "Max slippage",
    path: ["budgets", "maxSlippageBps"],
    kind: "integer",
    hint: "Basis points. 50 = 0.5%.",
  },
  {
    name: "maxExposureUsdMicros",
    label: "Max exposure",
    path: ["budgets", "maxExposureUsdMicros"],
    kind: "decimalString",
    hint: "USD micros.",
  },
  {
    name: "maxSpendUsdMicros",
    label: "Permission spend cap",
    path: ["permissions", "maxSpendUsdMicros"],
    kind: "decimalString",
    hint: "USD micros. A quote requesting more than this is excluded.",
  },
  {
    name: "maxEvidenceAgeSeconds",
    label: "Max evidence age",
    path: ["maxEvidenceAgeSeconds"],
    kind: "integer",
    hint: "Seconds. Lower this to watch candidates fail on freshness.",
  },
  {
    name: "maxPreviewAgeSeconds",
    label: "Max preview age",
    path: ["maxPreviewAgeSeconds"],
    kind: "integer",
    hint: "Seconds.",
  },
  {
    name: "allowedProtocols",
    label: "Allowed protocols",
    path: ["permissions", "allowedProtocols"],
    kind: "csv",
    hint: "Comma separated. A quote using a protocol not listed here is excluded.",
  },
]);

/**
 * Categories offered in the form.
 *
 * Grid, yield and health are listed but **not selectable**, and the reason is
 * stated rather than implied. Marketplace Core reports all three as unsupported,
 * and there is no quote supply for them. Offering them as if they worked would
 * produce a `MANDATE_CATEGORY_MISMATCH` against the rebalancing quotes that do
 * exist — a real finding that reads like a different problem, and would leave a
 * user debugging their input instead of learning the actual state of the system.
 */
export interface CategoryOption {
  readonly value: string;
  readonly label: string;
  readonly supported: boolean;
  readonly reason?: string;
}

export const CATEGORY_OPTIONS: readonly CategoryOption[] = Object.freeze([
  { value: "rebalancing", label: "Rebalancing (PancakeSwap v3 position)", supported: true },
  {
    value: "grid",
    label: "Grid — unsupported in Core v1",
    supported: false,
    reason: "CATEGORY_GRID_UNSUPPORTED",
  },
  {
    value: "yield",
    label: "Yield — unsupported in Core v1",
    supported: false,
    reason: "CATEGORY_YIELD_UNSUPPORTED",
  },
  {
    value: "health",
    label: "Lending health — unsupported in Core v1",
    supported: false,
    reason: "CATEGORY_HEALTH_UNSUPPORTED",
  },
]);

/** Parses an `application/x-www-form-urlencoded` body into a flat map. */
export function parseFormBody(body: string): Record<string, string> {
  const output: Record<string, string> = {};
  for (const [key, value] of new URLSearchParams(body)) output[key] = value;
  return output;
}

export interface MandateBuildResult {
  readonly mandate: unknown;
  /** Problems with the submitted values, reported rather than silently coerced. */
  readonly problems: readonly string[];
  /** True when the raw JSON escape hatch supplied the mandate wholesale. */
  readonly fromRawJson: boolean;
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function setPath(target: Record<string, unknown>, path: readonly string[], value: unknown): void {
  let cursor: Record<string, unknown> = target;
  for (let index = 0; index < path.length - 1; index += 1) {
    const key = path[index];
    if (key === undefined) return;
    const next = cursor[key];
    if (typeof next !== "object" || next === null) return;
    cursor = next as Record<string, unknown>;
  }
  const last = path[path.length - 1];
  if (last !== undefined) cursor[last] = value;
}

function getPath(source: unknown, path: readonly string[]): unknown {
  let cursor: unknown = source;
  for (const key of path) {
    if (typeof cursor !== "object" || cursor === null) return undefined;
    cursor = (cursor as Record<string, unknown>)[key];
  }
  return cursor;
}

/** Current value of a field in a mandate, formatted for a form input. */
export function fieldValue(mandate: unknown, field: MandateField): string {
  const value = getPath(mandate, field.path);
  if (value === undefined || value === null) return "";
  if (Array.isArray(value)) return value.join(", ");
  return String(value);
}

/**
 * Applies submitted form values over a base mandate.
 *
 * Invalid values are collected as problems and the base value is kept, rather
 * than being coerced. Coercion here would be actively harmful: a spend cap that
 * silently became `0` or `NaN` would change every eligibility verdict on the page
 * while looking like the number the user typed.
 */
export function buildMandate(base: unknown, form: Record<string, string>): MandateBuildResult {
  const raw = (form.rawMandate ?? "").trim();
  if (raw.length > 0) {
    try {
      return { mandate: JSON.parse(raw), problems: [], fromRawJson: true };
    } catch (cause) {
      return {
        mandate: clone(base),
        problems: [`the raw mandate JSON did not parse: ${(cause as Error).message}`],
        fromRawJson: false,
      };
    }
  }

  const mandate = clone(base) as Record<string, unknown>;
  const problems: string[] = [];

  const category = form.category;
  if (category !== undefined && category.length > 0) {
    const option = CATEGORY_OPTIONS.find((entry) => entry.value === category);
    if (option === undefined) {
      problems.push(`unknown category "${category}"`);
    } else if (!option.supported) {
      problems.push(
        `category "${category}" is reported unsupported by Marketplace Core (${option.reason}), ` +
          "so it cannot be evaluated; the mandate category was left unchanged",
      );
    } else {
      mandate.category = category;
    }
  }

  for (const field of MANDATE_FIELDS) {
    const submitted = form[field.name];
    if (submitted === undefined) continue;
    const trimmed = submitted.trim();
    if (trimmed.length === 0) continue;

    if (field.kind === "integer") {
      if (!/^\d+$/.test(trimmed)) {
        problems.push(`${field.label} must be a whole number, received "${trimmed}"`);
        continue;
      }
      const parsed = Number(trimmed);
      if (!Number.isSafeInteger(parsed)) {
        problems.push(`${field.label} is too large to be represented exactly`);
        continue;
      }
      setPath(mandate, field.path, parsed);
      continue;
    }

    if (field.kind === "decimalString") {
      // Kept as a string on purpose: these are uint256 USD micros in the schema,
      // and routing them through a JS number would lose precision on large
      // values without any visible sign that it happened.
      if (!/^\d+$/.test(trimmed)) {
        problems.push(`${field.label} must be a non-negative integer, received "${trimmed}"`);
        continue;
      }
      setPath(mandate, field.path, trimmed);
      continue;
    }

    if (field.kind === "csv") {
      const parts = trimmed
        .split(",")
        .map((part) => part.trim())
        .filter((part) => part.length > 0);
      if (parts.length === 0) {
        problems.push(`${field.label} cannot be empty`);
        continue;
      }
      setPath(mandate, field.path, parts);
      continue;
    }

    setPath(mandate, field.path, trimmed);
  }

  return { mandate, problems, fromRawJson: false };
}
