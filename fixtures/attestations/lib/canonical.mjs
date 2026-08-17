// Independent canonical-JSON implementation for MandateX evaluation attestations.
//
// WHY THIS EXISTS
// This is a deliberate, from-scratch reimplementation of the canonicalization
// rules in tools/marketplace-core/src/canonical.ts. It is NOT a shared import.
//
// The frozen contract (tools/marketplace-core/EVALUATION_ATTESTATION_V2.md)
// requires golden vectors that "lock the exact signing bytes before the signer
// service is deployed", and the signer is a SEPARATELY DEPLOYED runtime. If both
// the fixture generator and the evaluator called the same function, a bug in that
// function would be invisible. Two independent implementations that must agree
// byte-for-byte is the actual check. crosscheck.mjs asserts the agreement.
//
// Rules mirrored from the Marketplace Core restricted profile:
//   - strict JSON data only (null | boolean | number | string | array | plain object)
//   - object keys sorted by UTF-16 code-unit order
//   - exact array order preserved
//   - numbers must be finite safe integers (no floats, no NaN/Infinity)
//   - undefined values rejected
//   - non-plain prototypes rejected (no class instances, no Map/Set/Date)
//   - output via JSON.stringify: no whitespace, no trailing newline

/**
 * Sort comparator matching marketplace-core's compareCanonicalStrings:
 *   left < right ? -1 : left > right ? 1 : 0
 * JavaScript relational operators on strings compare UTF-16 code units, so this
 * is code-unit order — NOT Unicode code-point order. They diverge only for
 * astral-plane characters (surrogate pairs), which the strict schemas cannot
 * produce in a key position. Reproduced exactly rather than "improved".
 */
export function compareCanonicalStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function normalizeCanonical(value, path) {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) {
      throw new TypeError(`${path} must contain only finite safe integers`);
    }
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((entry, index) => normalizeCanonical(entry, `${path}[${index}]`));
  }

  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError(`${path} must contain only plain JSON objects`);
    }
    const output = {};
    for (const key of Object.keys(value).sort(compareCanonicalStrings)) {
      const entry = value[key];
      if (entry === undefined) {
        throw new TypeError(`${path}.${key} must not be undefined`);
      }
      output[key] = normalizeCanonical(entry, `${path}.${key}`);
    }
    return output;
  }

  throw new TypeError(`${path} is not canonical JSON data`);
}

/** Canonical JSON text. No whitespace, no BOM, no trailing newline. */
export function canonicalJson(value) {
  return JSON.stringify(normalizeCanonical(value, "$"));
}

/**
 * PORTABILITY CAVEAT — reported to Codex, see plan.md §7.
 *
 * Both this implementation and marketplace-core's build a plain object with keys
 * inserted in sorted order and rely on JSON.stringify preserving that order.
 * ECMAScript does NOT preserve insertion order for integer-index-like keys: it
 * emits those first, in ascending numeric order, regardless of insertion.
 *
 *   canonicalJson({ b: 1, "10": 2, "2": 3 })  →  {"2":3,"10":2,"b":1}
 *   true UTF-16 sorted order would be         →  {"10":2,"2":3,"b":1}
 *
 * The two JS implementations agree, so this is not a divergence and not
 * currently reachable: every attestation and payload schema is .strict() with
 * fixed alphabetic keys, so no integer-like key can appear. It matters only if a
 * non-JS signer is ever deployed (the contract explicitly allows a separately
 * deployed signer runtime) — a Go/Rust/Python signer sorting keys properly would
 * produce different bytes for such an object and its signature would be rejected.
 *
 * Detects whether a value contains any integer-index-like key, so the condition
 * is asserted rather than assumed.
 */
export function findIntegerLikeKeys(value, path = "$", found = []) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => findIntegerLikeKeys(entry, `${path}[${index}]`, found));
    return found;
  }
  if (value !== null && typeof value === "object") {
    for (const key of Object.keys(value)) {
      // Array-index-like per ECMAScript: canonical numeric string < 2^32 - 1.
      if (String(Number(key)) === key && Number.isInteger(Number(key)) && Number(key) >= 0) {
        found.push(`${path}.${key}`);
      }
      findIntegerLikeKeys(value[key], `${path}.${key}`, found);
    }
  }
  return found;
}
