import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJson, canonicalSha256 } from "../src/index.js";

test("canonical JSON sorts object keys but preserves array order", () => {
  assert.equal(
    canonicalJson({ z: 1, a: { d: true, c: false }, list: [2, 1] }),
    '{"a":{"c":false,"d":true},"list":[2,1],"z":1}',
  );
  assert.equal(
    canonicalJson({ a: 1, b: 2 }),
    canonicalJson({ b: 2, a: 1 }),
  );
  assert.notEqual(
    canonicalJson({ list: [2, 1] }),
    canonicalJson({ list: [1, 2] }),
  );
});

test("canonical JSON rejects unsafe non-JSON values", () => {
  assert.throws(() => canonicalJson({ value: Number.NaN }));
  assert.throws(() => canonicalJson({ value: 1.5 }));
  assert.throws(() => canonicalJson({ value: undefined }));
  assert.throws(() => canonicalJson(new Date(0)));
});

test("canonical SHA-256 is stable", () => {
  assert.equal(
    canonicalSha256({ b: 2, a: 1 }),
    "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
  );
});
