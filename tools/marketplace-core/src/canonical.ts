import { createHash } from "node:crypto";

import { compareCanonicalStrings } from "./primitives.js";

export type CanonicalJsonValue =
  | null
  | boolean
  | number
  | string
  | CanonicalJsonValue[]
  | { [key: string]: CanonicalJsonValue };

function normalizeCanonical(value: unknown, path: string): CanonicalJsonValue {
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
    const record = value as Record<string, unknown>;
    const output: Record<string, CanonicalJsonValue> = {};
    for (const key of Object.keys(record).sort(compareCanonicalStrings)) {
      const entry = record[key];
      if (entry === undefined) throw new TypeError(`${path}.${key} must not be undefined`);
      output[key] = normalizeCanonical(entry, `${path}.${key}`);
    }
    return output;
  }
  throw new TypeError(`${path} is not canonical JSON data`);
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(normalizeCanonical(value, "$"));
}

export function canonicalSha256(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}
