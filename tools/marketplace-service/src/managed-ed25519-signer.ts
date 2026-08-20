import {
  createHash,
  createPublicKey,
  verify as verifyEd25519,
  type KeyObject,
} from "node:crypto";

import { MarketplaceServiceError } from "./errors.js";

export const MANAGED_ED25519_RAW_MESSAGE_PROFILE =
  "mandatex-managed-ed25519-raw-message-v1" as const;
export const MAX_MANAGED_ED25519_MESSAGE_BYTES = 262_144 as const;

export interface ManagedEd25519SignerOptions {
  readonly keyId: string;
  readonly custody: "non_exportable_managed";
  readonly backendProfile: string;
  readonly publicKeySpkiDer: Uint8Array;
  readonly publicKeyFingerprintSha256: string;
  readonly signRaw: (message: Uint8Array) => Promise<Uint8Array>;
}

export interface ManagedEd25519Signature {
  readonly keyId: string;
  readonly backendProfile: string;
  readonly signatureProfile: typeof MANAGED_ED25519_RAW_MESSAGE_PROFILE;
  readonly publicKeyFingerprintSha256: string;
  readonly signature: Uint8Array;
  readonly signatureHex: string;
}

export interface ManagedEd25519Signer {
  readonly keyId: string;
  readonly custody: "non_exportable_managed";
  readonly backendProfile: string;
  readonly signatureProfile: typeof MANAGED_ED25519_RAW_MESSAGE_PROFILE;
  readonly publicKeyFingerprintSha256: string;
  readonly publicKeySpkiDer: Uint8Array;
  readonly sign: (message: Uint8Array) => Promise<ManagedEd25519Signature>;
}

const managedSignerInstances = new WeakSet<object>();

/**
 * Captures a public-only managed-key boundary. The callback must invoke an
 * external non-exportable Ed25519 key and sign the exact supplied bytes.
 */
export function createManagedEd25519Signer(
  options: ManagedEd25519SignerOptions,
): ManagedEd25519Signer {
  assertExactDataObject(
    options,
    [
      "keyId",
      "custody",
      "backendProfile",
      "publicKeySpkiDer",
      "publicKeyFingerprintSha256",
      "signRaw",
    ],
    "managed signer options",
  );
  if (options.custody !== "non_exportable_managed") {
    throw signerError("managed signer custody must be non-exportable");
  }
  const keyId = parseIdentifier(options.keyId, "managed signer key ID");
  const backendProfile = parseIdentifier(
    options.backendProfile,
    "managed signer backend profile",
  );
  const publicKeySpkiDer = parseCanonicalEd25519Spki(
    options.publicKeySpkiDer,
  );
  const publicKey = createPublicKey({
    key: publicKeySpkiDer,
    format: "der",
    type: "spki",
  });
  const fingerprint = createHash("sha256")
    .update(publicKeySpkiDer)
    .digest("hex");
  if (
    !/^[a-f0-9]{64}$/.test(options.publicKeyFingerprintSha256) ||
    fingerprint !== options.publicKeyFingerprintSha256
  ) {
    throw signerError("managed signer public-key fingerprint does not match");
  }
  const signRaw = options.signRaw;
  if (typeof signRaw !== "function") {
    throw signerError("managed signer raw-message callback must be a function");
  }

  const signer = Object.freeze({
    keyId,
    custody: "non_exportable_managed" as const,
    backendProfile,
    signatureProfile: MANAGED_ED25519_RAW_MESSAGE_PROFILE,
    get publicKeyFingerprintSha256(): string {
      return fingerprint;
    },
    get publicKeySpkiDer(): Uint8Array {
      return Uint8Array.from(publicKeySpkiDer);
    },
    async sign(message: Uint8Array): Promise<ManagedEd25519Signature> {
      const verificationMessage = parseMessage(message);
      let returned: Uint8Array;
      try {
        returned = await signRaw(Uint8Array.from(verificationMessage));
      } catch (cause) {
        throw new MarketplaceServiceError(
          "SIGNING_FAILED",
          "managed Ed25519 signing provider failed",
          { cause },
        );
      }
      if (!(returned instanceof Uint8Array) || returned.byteLength !== 64) {
        throw new MarketplaceServiceError(
          "SIGNING_FAILED",
          "managed Ed25519 signing provider returned an invalid signature",
        );
      }
      const signature = Uint8Array.from(returned);
      let valid = false;
      try {
        valid = verifyEd25519(
          null,
          verificationMessage,
          publicKey,
          signature,
        );
      } catch {
        valid = false;
      }
      if (!valid) {
        throw new MarketplaceServiceError(
          "SIGNING_FAILED",
          "managed Ed25519 signing provider returned a signature for the wrong key or message profile",
        );
      }
      const signatureHex = Buffer.from(signature).toString("hex");
      return Object.freeze({
        keyId,
        backendProfile,
        signatureProfile: MANAGED_ED25519_RAW_MESSAGE_PROFILE,
        publicKeyFingerprintSha256: fingerprint,
        get signature(): Uint8Array {
          return Uint8Array.from(signature);
        },
        signatureHex,
      });
    },
  }) satisfies ManagedEd25519Signer;
  managedSignerInstances.add(signer);
  return signer;
}

export function assertManagedEd25519Signer(
  value: unknown,
): asserts value is ManagedEd25519Signer {
  if (
    value === null ||
    typeof value !== "object" ||
    !managedSignerInstances.has(value)
  ) {
    throw signerError(
      "managed signer must be created by the marketplace service factory",
    );
  }
}

function parseMessage(message: Uint8Array): Buffer {
  if (!(message instanceof Uint8Array)) {
    throw signerError("managed signer input must be a byte array");
  }
  if (
    message.byteLength === 0 ||
    message.byteLength > MAX_MANAGED_ED25519_MESSAGE_BYTES
  ) {
    throw signerError(
      `managed signer input must contain 1-${MAX_MANAGED_ED25519_MESSAGE_BYTES} bytes`,
    );
  }
  return Buffer.from(message);
}

function parseCanonicalEd25519Spki(input: Uint8Array): Buffer {
  if (!(input instanceof Uint8Array) || input.byteLength === 0) {
    throw signerError(
      "managed signer public key must be canonical Ed25519 SPKI DER bytes",
    );
  }
  const supplied = Buffer.from(input);
  try {
    const key = createPublicKey({ key: supplied, format: "der", type: "spki" });
    if (key.asymmetricKeyType !== "ed25519") {
      throw new TypeError("public key is not Ed25519");
    }
    const exported = exportSpki(key);
    if (!exported.equals(supplied)) {
      throw new TypeError("public key is not canonical SPKI DER");
    }
    return Buffer.from(exported);
  } catch (cause) {
    throw signerError(
      "managed signer public key must be canonical Ed25519 SPKI DER bytes",
      cause,
    );
  }
}

function exportSpki(key: KeyObject): Buffer {
  const exported = key.export({ format: "der", type: "spki" });
  if (!Buffer.isBuffer(exported)) {
    throw new TypeError("public key export did not return DER bytes");
  }
  return exported;
}

function parseIdentifier(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)
  ) {
    throw signerError(`${label} is invalid`);
  }
  return value;
}

function assertExactDataObject(
  value: unknown,
  keys: readonly string[],
  label: string,
): asserts value is Record<string, unknown> {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw signerError(`${label} must be a plain object`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const actual = Object.keys(descriptors).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw signerError(`${label} contains unsupported or missing fields`);
  }
  for (const key of actual) {
    const descriptor = descriptors[key];
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    ) {
      throw signerError(`${label} must contain enumerable data properties`);
    }
  }
}

function signerError(
  message: string,
  cause?: unknown,
): MarketplaceServiceError {
  return new MarketplaceServiceError(
    "MANAGED_SIGNER_INVALID",
    message,
    cause === undefined ? undefined : { cause },
  );
}
