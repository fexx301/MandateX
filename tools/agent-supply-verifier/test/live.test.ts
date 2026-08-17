import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { manifestFileSchema } from "../src/schema.js";
import { PinnedHttpsTransport } from "../src/transport/http.js";
import { verifyManifest } from "../src/verify.js";

test(
  "live curated candidate produces a passive, never-hireable report",
  {
    skip: process.env.MANDATEX_LIVE_SUPPLY !== "1",
    timeout: 60_000,
  },
  async () => {
    const manifest = manifestFileSchema.parse(
      JSON.parse(
        await readFile(
          new URL("../config/candidates.json", import.meta.url),
          "utf8",
        ),
      ),
    );
    const report = await verifyManifest({
      manifest,
      transport: new PinnedHttpsTransport(),
    });

    assert.equal(report.schema, "mandatex.agent-supply.report.v1");
    assert.equal(report.candidates.length, 1);
    assert.notEqual(report.candidates[0]?.status, "VERIFIED_HIREABLE");
    assert.equal(
      report.candidates[0]?.gates.find((gate) => gate.gate === "quote_signature")
        ?.state,
      "unknown",
    );
  },
);
