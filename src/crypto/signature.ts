import sodium from "libsodium-wrappers-sumo";
import { assertByteLength } from "../utils/bytes.js";

export type SigningKeyPair = {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
};

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
