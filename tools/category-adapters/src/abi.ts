/**
 * Minimal static-ABI decoding.
 *
 * This package deliberately does not depend on viem. Every value it reads is a
 * statically-sized word in the return data of a `eth_call` with no arguments or
 * one address argument, which is a few lines of arithmetic; pulling in a full
 * ABI codec to do it would add megabytes to the one container that also holds a
 * signing key. `agent-supply-verifier` already carries viem for the paths that
 * genuinely need it.
 *
 * Everything here is total: no function throws on hostile input, they return
 * `undefined` and let the caller decide which fail-closed code that maps to.
 * Decoding is the most likely place for a malformed-but-plausible response to
 * turn into a confidently wrong number, so there are no fallbacks and no
 * coercions — a word that is not the expected width is not interpreted at all.
 */

const HEX_WORD_CHARS = 64;
const UINT256_CEILING = 1n << 256n;
const INT256_SIGN_BIT = 1n << 255n;
const INT24_MIN = -8_388_608;
const INT24_MAX = 8_388_607;

/** `type(uint256).max`, which several protocols use as an "unbounded" sentinel. */
export const UINT256_MAX = UINT256_CEILING - 1n;

/**
 * `type(uint160).max`. Needed because `sqrtPriceX96` is declared `uint160`, so a
 * word wider than 160 bits is an ABI-level violation independent of any protocol
 * rule — the encoder that produced it was not encoding a `uint160`.
 */
export const UINT160_MAX = (1n << 160n) - 1n;

/** Strips `0x` and lowercases, or returns undefined if this is not plain hex. */
function normalizeHex(value: string): string | undefined {
  const body = value.startsWith("0x") || value.startsWith("0X")
    ? value.slice(2)
    : value;
  if (body.length === 0) return undefined;
  if (!/^[0-9a-fA-F]+$/.test(body)) return undefined;
  return body.toLowerCase();
}

/**
 * Number of whole 32-byte words in `data`, or undefined if the payload is not
 * hex or is not a whole number of words. Return data that is not word-aligned
 * did not come from a well-formed static-ABI return, so it is never decoded.
 */
export function wordCount(data: string): number | undefined {
  const body = normalizeHex(data);
  if (body === undefined) return undefined;
  if (body.length % HEX_WORD_CHARS !== 0) return undefined;
  return body.length / HEX_WORD_CHARS;
}

/** Raw 32-byte word at `index` as an unsigned big integer. */
export function decodeUint256(data: string, index: number): bigint | undefined {
  const body = normalizeHex(data);
  if (body === undefined) return undefined;
  if (body.length % HEX_WORD_CHARS !== 0) return undefined;
  if (!Number.isSafeInteger(index) || index < 0) return undefined;
  const start = index * HEX_WORD_CHARS;
  if (start + HEX_WORD_CHARS > body.length) return undefined;
  const word = body.slice(start, start + HEX_WORD_CHARS);
  return BigInt(`0x${word}`);
}

/**
 * Word at `index` interpreted as a two's-complement `int24`.
 *
 * Solidity sign-extends narrow signed integers across the whole word, so this
 * reads the full 256-bit two's complement and then range-checks. A value that
 * sign-extends correctly but lands outside int24 means the word was not an
 * int24 at all, and is rejected rather than truncated — Uniswap-style ticks are
 * the field this is used for, and a truncated tick is a plausible-looking price
 * somewhere else entirely.
 */
export function decodeInt24(data: string, index: number): number | undefined {
  const raw = decodeUint256(data, index);
  if (raw === undefined) return undefined;
  const signed = raw >= INT256_SIGN_BIT ? raw - UINT256_CEILING : raw;
  if (signed < BigInt(INT24_MIN) || signed > BigInt(INT24_MAX)) return undefined;
  return Number(signed);
}

/** 4-byte function selector, `0x`-prefixed, as calldata with no arguments. */
export function selectorCalldata(selector: string): string {
  return selector;
}

/**
 * Length of a single dynamic array return, without decoding its elements.
 *
 * A static-ABI return holding one dynamic array is `[offset, ...]` where the word
 * at `offset` is the element count. Only the count is needed here — the caller
 * wants to know whether an account has entered any markets, not which — so the
 * elements are deliberately not decoded. Reading fewer fields than are present is
 * the safer direction: nothing downstream can then depend on an element this
 * function did not validate.
 *
 * Returns `undefined` unless the payload is word-aligned, the offset is itself
 * word-aligned, and the length word lies inside the data. A hostile offset
 * pointing past the end is the obvious attack on this shape, so it is bounds
 * checked rather than trusted.
 */
export function decodeDynamicArrayLength(data: string): number | undefined {
  const words = wordCount(data);
  if (words === undefined || words < 2) return undefined;
  const offset = decodeUint256(data, 0);
  if (offset === undefined) return undefined;
  if (offset % 32n !== 0n) return undefined;
  const lengthIndex = Number(offset / 32n);
  if (!Number.isSafeInteger(lengthIndex) || lengthIndex >= words) return undefined;
  const length = decodeUint256(data, lengthIndex);
  if (length === undefined) return undefined;
  // The declared length must be backed by words actually present, or the array
  // header is describing data the response does not contain.
  if (length > BigInt(words - lengthIndex - 1)) return undefined;
  return Number(length);
}

/**
 * Calldata for a single `address` argument: selector plus one left-padded word.
 * The address is validated by the caller's schema before reaching this.
 */
export function addressCalldata(selector: string, address: string): string {
  const body = normalizeHex(address);
  if (body === undefined || body.length !== 40) {
    // Unreachable through the public API: every address is parsed by
    // `evmAddressSchema` first. Kept total rather than throwing so that a
    // future caller that skips the schema degrades to a call that cannot
    // succeed, instead of an exception escaping an adapter that is supposed to
    // return fail-closed results rather than reject.
    return `${selector}${"0".repeat(HEX_WORD_CHARS)}`;
  }
  return `${selector}${body.padStart(HEX_WORD_CHARS, "0")}`;
}
