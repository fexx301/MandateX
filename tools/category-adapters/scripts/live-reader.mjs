/**
 * A real `PinnedBlockReader` over JSON-RPC, for the operator scripts in this
 * directory.
 *
 * This is deliberately NOT part of the published package. The library exposes
 * the reader *interface* and keeps transport out, so that the verifier runtime
 * owns endpoint trust and pinning; an adapter that could open its own socket
 * would be a second, unpinned trust path into the signing service. These scripts
 * are operator tooling run by hand, so they may construct a transport — but they
 * construct it to exactly the same contract the runtime must honour:
 *
 *   - every read resolves against ONE block, captured once up front
 *   - the block's own timestamp is the observation time, never the local clock
 *   - a transport failure resolves to undefined rather than throwing, so the
 *     adapters can return a fail-closed result instead of rejecting
 *
 * Read-only. Nothing here signs, funds, or broadcasts anything, and there is no
 * private key or wallet path reachable from this file.
 */

import { createHash } from "node:crypto";

export const DEFAULT_RPC = "https://bsc-rpc.publicnode.com";
export const FALLBACK_RPC = "https://bsc-dataseed.binance.org";

const sha256 = (value) => createHash("sha256").update(value, "utf8").digest("hex");

/** Minimal JSON-RPC client with one retry onto a second endpoint. */
export function createRpc(primary = DEFAULT_RPC, fallback = FALLBACK_RPC) {
  let id = 0;
  async function once(url, method, params) {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params }),
      signal: AbortSignal.timeout(20_000),
    });
    if (!response.ok) throw new Error(`http ${response.status}`);
    const body = await response.json();
    if (body.error) throw new Error(body.error.message ?? "rpc error");
    return body.result;
  }
  return async function call(method, params) {
    try {
      return await once(primary, method, params);
    } catch (first) {
      try {
        return await once(fallback, method, params);
      } catch {
        throw first;
      }
    }
  };
}

/**
 * Captures the current head as a block anchor.
 *
 * The anchor is read once and then every subsequent call is made *at that block
 * hash*, not at "latest". Reading at "latest" across several calls is the bug
 * this exists to prevent: on a chain producing a block every 750ms, a
 * three-read adapter can straddle two blocks and derive a ratio from state that
 * never coexisted.
 */
export async function captureAnchor(rpc, blockTag = "latest") {
  const block = await rpc("eth_getBlockByNumber", [blockTag, false]);
  if (block === null) throw new Error(`block ${blockTag} not found`);
  return Object.freeze({
    number: Number.parseInt(block.number, 16),
    hash: block.hash,
    timestamp: Number.parseInt(block.timestamp, 16),
  });
}

/** A PinnedBlockReader bound to one anchor. */
export function createPinnedReader(rpc, anchor) {
  const calls = [];
  return {
    anchor,
    calls,
    async call({ label, to, data }) {
      calls.push(label);
      try {
        // Pinned by block HASH, so a reorg surfaces as a failed read rather than
        // as state from a different chain history.
        const result = await rpc("eth_call", [{ to, data }, anchor.hash]);
        if (typeof result !== "string") return undefined;
        return {
          data: result,
          observation: {
            label,
            to,
            requestSha256: sha256(`${to}:${data}`),
            responseSha256: sha256(result),
          },
        };
      } catch {
        return undefined;
      }
    },
  };
}

export { sha256 };

/** Left-pads an address into an ABI word. */
export const addressWord = (address) =>
  address.toLowerCase().replace(/^0x/, "").padStart(64, "0");

/** Reads a solidity `string` return (offset, length, bytes). */
export function decodeString(hex) {
  if (typeof hex !== "string" || hex.length < 130) return undefined;
  const body = hex.slice(2);
  const length = Number.parseInt(body.slice(64, 128), 16);
  if (!Number.isSafeInteger(length) || length === 0) return undefined;
  const bytes = body.slice(128, 128 + length * 2);
  if (bytes.length < length * 2) return undefined;
  return Buffer.from(bytes, "hex").toString("utf8");
}
