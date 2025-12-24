import sodium from "libsodium-wrappers-sumo";
import { assertByteLength } from "../utils/bytes.js";
import { decodeBase64, encodeBase64 } from "../utils/encoding.js";
import type { AeadEnvelopeV1 } from "../types.js";

// Domain: file keys + file data encryption/decryption.
/**
 * Enkripsi payload dengan key menggunakan AEAD.
 *
 * @param key - Key 32-byte.
 * @param plaintext - Data plaintext.
 * @param aad - Additional authenticated data (opsional).
 * @returns Envelope hasil enkripsi.
 */
async function encryptWithKey(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array
): Promise<AeadEnvelopeV1> {
  await sodium.ready;

  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );
  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    aad ?? null,
    null,
    nonce,
    key
  );

  return {
    v: 1,
    nonce: encodeBase64(nonce),
    ct: encodeBase64(ct),
  };
}

/**
 * Dekripsi payload dengan key menggunakan AEAD.
 *
 * @param key - Key 32-byte.
 * @param wrapped - Envelope hasil enkripsi.
 * @param aad - Additional authenticated data (opsional).
 * @returns Bytes hasil dekripsi.
 */
async function decryptWithKey(
  key: Uint8Array,
  wrapped: AeadEnvelopeV1,
  aad?: Uint8Array
): Promise<Uint8Array> {
  await sodium.ready;

  const nonce = decodeBase64(wrapped.nonce);
  assertByteLength(
    "nonce",
    nonce,
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );
  const ct = decodeBase64(wrapped.ct);

  try {
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ct,
      aad ?? null,
      nonce,
      key
    );
  } catch {
    throw new Error("Gagal membuka file: ciphertext/AAD/keys tidak valid");
  }
}

/**
 * Generate file key 32-byte secara acak.
 *
 * @returns Bytes file key.
 *
 * @example
 * const fileKey = await generateFileKey();
 */
export async function generateFileKey(): Promise<Uint8Array> {
  await sodium.ready;
  return sodium.randombytes_buf(32);
}

/**
 * Bungkus file key menggunakan master key.
 *
 * @param fileKey - File key 32-byte.
 * @param masterKey - Master key 32-byte.
 * @param aad - Additional authenticated data (opsional).
 * @returns Envelope hasil wrap.
 *
 * @example
 * const wrapped = await wrapFileKeyWithMasterKey(fileKey, masterKey);
 */
export async function wrapFileKeyWithMasterKey(
  fileKey: Uint8Array,
  masterKey: Uint8Array,
  aad?: Uint8Array
): Promise<AeadEnvelopeV1> {
  assertByteLength("fileKey", fileKey, 32);
  assertByteLength("masterKey", masterKey, 32);
  return encryptWithKey(masterKey, fileKey, aad);
}

/**
 * Buka file key menggunakan master key.
 *
 * @param masterKey - Master key 32-byte.
 * @param wrapped - Envelope hasil wrap file key.
 * @param aad - Additional authenticated data (opsional).
 * @returns Bytes file key.
 *
 * @example
 * const fileKey = await unwrapFileKeyWithMasterKey(masterKey, wrapped);
 */
export async function unwrapFileKeyWithMasterKey(
  masterKey: Uint8Array,
  wrapped: AeadEnvelopeV1,
  aad?: Uint8Array
): Promise<Uint8Array> {
  assertByteLength("masterKey", masterKey, 32);
  const fileKey = await decryptWithKey(masterKey, wrapped, aad);
  assertByteLength("fileKey", fileKey, 32);
  return fileKey;
}

/**
 * Enkripsi isi file menggunakan file key.
 *
 * @param fileKey - File key 32-byte.
 * @param plaintext - Isi file (bytes).
 * @param aad - Additional authenticated data (opsional).
 * @returns Envelope hasil enkripsi file.
 *
 * @example
 * const encrypted = await encryptFileData(fileKey, fileBytes);
 */
export async function encryptFileData(
  fileKey: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array
): Promise<AeadEnvelopeV1> {
  assertByteLength("fileKey", fileKey, 32);
  return encryptWithKey(fileKey, plaintext, aad);
}

/**
 * Dekripsi isi file menggunakan file key.
 *
 * @param fileKey - File key 32-byte.
 * @param wrapped - Envelope hasil enkripsi file.
 * @param aad - Additional authenticated data (opsional).
 * @returns Bytes isi file.
 *
 * @example
 * const fileBytes = await decryptFileData(fileKey, encrypted);
 */
export async function decryptFileData(
  fileKey: Uint8Array,
  wrapped: AeadEnvelopeV1,
  aad?: Uint8Array
): Promise<Uint8Array> {
  assertByteLength("fileKey", fileKey, 32);
  return decryptWithKey(fileKey, wrapped, aad);
}
