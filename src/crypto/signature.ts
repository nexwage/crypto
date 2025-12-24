import sodium from "libsodium-wrappers-sumo";
import { assertByteLength } from "../utils/bytes.js";
import { decodeBase64, encodeBase64 } from "../utils/encoding.js";

export type SigningKeyPair = {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
};

export type SignedMessageV1 = {
  v: 1;
  nonce: string;
  ts: number;
  message: string;
  signature: string;
};

const SIGNED_NONCE_BYTES = 24;

function canonicalizeSignedPayload(payload: Omit<SignedMessageV1, "signature">) {
  return JSON.stringify({
    v: payload.v,
    nonce: payload.nonce,
    ts: payload.ts,
    message: payload.message,
  });
}

/**
 * Generate key pair untuk tanda tangan (Ed25519).
 *
 * @returns Public/private key pair.
 */
export async function generateSigningKeyPair(): Promise<SigningKeyPair> {
  await sodium.ready;
  const { publicKey, privateKey } = sodium.crypto_sign_keypair();
  return { publicKey, privateKey };
}

/**
 * Buat signature detached untuk message.
 *
 * @param message - Data input.
 * @param privateKey - Private key Ed25519.
 * @returns Signature.
 */
export async function signMessage(
  message: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  await sodium.ready;
  assertByteLength(
    "privateKey",
    privateKey,
    sodium.crypto_sign_SECRETKEYBYTES
  );
  return sodium.crypto_sign_detached(message, privateKey);
}

/**
 * Verifikasi signature untuk message.
 *
 * @param message - Data input.
 * @param signature - Signature detached.
 * @param publicKey - Public key Ed25519.
 * @returns True jika valid.
 */
export async function verifySignature(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  await sodium.ready;
  assertByteLength(
    "publicKey",
    publicKey,
    sodium.crypto_sign_PUBLICKEYBYTES
  );
  return sodium.crypto_sign_verify_detached(signature, message, publicKey);
}

/**
 * Buat signature dengan nonce/timestamp untuk anti‑replay.
 *
 * @param message - Data input.
 * @param privateKey - Private key Ed25519.
 * @param opts - Opsi nonce/timestamp.
 * @returns Payload signature terstruktur.
 */
export async function signMessageWithNonce(
  message: Uint8Array,
  privateKey: Uint8Array,
  opts?: { nonce?: Uint8Array; timestampMs?: number }
): Promise<SignedMessageV1> {
  await sodium.ready;
  assertByteLength(
    "privateKey",
    privateKey,
    sodium.crypto_sign_SECRETKEYBYTES
  );

  const nonce = opts?.nonce ?? sodium.randombytes_buf(SIGNED_NONCE_BYTES);
  assertByteLength("nonce", nonce, SIGNED_NONCE_BYTES);

  const payload: Omit<SignedMessageV1, "signature"> = {
    v: 1,
    nonce: encodeBase64(nonce),
    ts: opts?.timestampMs ?? Date.now(),
    message: encodeBase64(message),
  };

  const toSign = canonicalizeSignedPayload(payload);
  const signature = sodium.crypto_sign_detached(
    new TextEncoder().encode(toSign),
    privateKey
  );

  return {
    ...payload,
    signature: encodeBase64(signature),
  };
}

/**
 * Verifikasi payload signature anti‑replay.
 *
 * @param payload - Payload signature.
 * @param publicKey - Public key Ed25519.
 * @returns True jika valid.
 */
export async function verifySignedMessage(
  payload: SignedMessageV1,
  publicKey: Uint8Array
): Promise<boolean> {
  await sodium.ready;
  assertByteLength(
    "publicKey",
    publicKey,
    sodium.crypto_sign_PUBLICKEYBYTES
  );
  const nonce = decodeBase64(payload.nonce);
  assertByteLength("nonce", nonce, SIGNED_NONCE_BYTES);
  const signature = decodeBase64(payload.signature);
  const toVerify = canonicalizeSignedPayload({
    v: payload.v,
    nonce: payload.nonce,
    ts: payload.ts,
    message: payload.message,
  });
  return sodium.crypto_sign_verify_detached(
    signature,
    new TextEncoder().encode(toVerify),
    publicKey
  );
}
