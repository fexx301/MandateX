import assert from "node:assert/strict";
import test from "node:test";

import {
  UsdMicrosConversionError,
  usdNumberToMicros,
} from "../src/money.js";

test("USD numbers convert to exact canonical micros", () => {
  assert.equal(usdNumberToMicros(0), "0");
  assert.equal(usdNumberToMicros(0.000001), "1");
  assert.equal(usdNumberToMicros(5), "5000000");
  assert.equal(usdNumberToMicros(12.345678), "12345678");
});

test("unsafe, negative, and over-precise USD values fail closed", () => {
  for (const value of [-1, Number.NaN, Number.POSITIVE_INFINITY, 0.0000001]) {
    assert.throws(
      () => usdNumberToMicros(value),
      (error: unknown) => error instanceof UsdMicrosConversionError,
    );
  }
});
