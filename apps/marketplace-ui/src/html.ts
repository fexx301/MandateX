/**
 * HTML escaping and small element helpers.
 *
 * Everything this UI renders originates in a signed attestation produced by
 * somebody else — candidate names, proposed actions, contract addresses, finding
 * messages. None of it is trustworthy as markup. Verification proves an
 * attestation was signed by the pinned key; it says nothing about whether the
 * strings inside are safe to interpolate into a document.
 *
 * So there is exactly one way to put a value into the page (`text`), and it
 * always escapes. The `raw` marker exists for markup this module composed itself,
 * and is deliberately noisy to write so that reaching for it is a visible choice
 * in review rather than an accident.
 */

/** Markup this module produced, already safe to concatenate. */
export type Html = { readonly __html: string };

const AMP = /&/g;
const LT = /</g;
const GT = />/g;
const QUOT = /"/g;
const APOS = /'/g;

/**
 * Escapes the five characters that can break out of text or attribute context.
 *
 * Single and double quotes are both escaped so one function is safe in both
 * places. Two functions — one for text, one for attributes — would eventually be
 * used in the wrong context, and the failure is silent until someone crafts a
 * candidate name with a quote in it.
 */
export function escapeHtml(value: unknown): string {
  return String(value)
    .replace(AMP, "&amp;")
    .replace(LT, "&lt;")
    .replace(GT, "&gt;")
    .replace(QUOT, "&quot;")
    .replace(APOS, "&#39;");
}

/** Wraps already-safe markup. */
export function raw(markup: string): Html {
  return { __html: markup };
}

function isHtml(value: unknown): value is Html {
  return typeof value === "object" && value !== null && "__html" in value;
}

/**
 * Tagged template that escapes every interpolation unless it is `Html`.
 *
 * Arrays are joined, so a list of rendered rows can be dropped in directly.
 * `null` and `undefined` render as nothing rather than as the strings "null" and
 * "undefined", which is what a missing optional field should look like.
 */
export function html(
  strings: TemplateStringsArray,
  ...values: readonly unknown[]
): Html {
  let output = strings[0] ?? "";
  for (let index = 0; index < values.length; index += 1) {
    output += serialize(values[index]) + (strings[index + 1] ?? "");
  }
  return raw(output);
}

function serialize(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (isHtml(value)) return value.__html;
  if (Array.isArray(value)) return value.map(serialize).join("");
  return escapeHtml(value);
}

/** Renders finished markup to a string for the response body. */
export function render(value: Html): string {
  return value.__html;
}

/** Formats USD micros as dollars without going through a float. */
export function usdMicros(value: unknown): string {
  const text = String(value ?? "0");
  if (!/^\d+$/.test(text)) return escapeHtml(text);
  const micros = BigInt(text);
  const whole = micros / 1_000_000n;
  const fraction = (micros % 1_000_000n).toString(10).padStart(6, "0").replace(/0+$/, "");
  return fraction.length === 0 ? `$${whole}` : `$${whole}.${fraction}`;
}

/** Basis points as a percentage, integer arithmetic only. */
export function bps(value: unknown): string {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return escapeHtml(value);
  const whole = Math.floor(numeric / 100);
  const rest = Math.abs(numeric % 100);
  return rest === 0 ? `${whole}%` : `${whole}.${String(rest).padStart(2, "0")}%`;
}

/** Unix seconds as an ISO instant, labelled UTC so it is unambiguous. */
export function instant(value: unknown): string {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) return "—";
  return `${new Date(numeric * 1000).toISOString().replace(".000Z", "Z")}`;
}
