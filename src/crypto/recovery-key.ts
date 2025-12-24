import sodium from "libsodium-wrappers-sumo";
import { assertByteLength } from "../utils/bytes.js";
import { decodeBase64, encodeBase64 } from "../utils/encoding.js";
import type { AeadEnvelopeV1 } from "../types.js";

// Domain: recovery key and its wrapping with master key.
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
    throw new Error("Gagal membuka payload: ciphertext/AAD/keys tidak valid");
  }
}

/**
 * Generate recovery key 32-byte secara acak.
 *
 * @returns Bytes recovery key.
 *
 * @example
 * const recoveryKey = await generateRecoveryKey();
 */
export async function generateRecoveryKey(): Promise<Uint8Array> {
  await sodium.ready;
  return sodium.randombytes_buf(32);
}

/**
 * Bungkus master key menggunakan recovery key.
 *
 * @param masterKey - Master key 32-byte.
 * @param recoveryKey - Recovery key 32-byte.
 * @param aad - Additional authenticated data (opsional).
 * @returns Envelope hasil wrap.
 *
 * @example
 * const wrapped = await wrapMasterKeyWithRecoveryKey(masterKey, recoveryKey);
 */
export async function wrapMasterKeyWithRecoveryKey(
  masterKey: Uint8Array,
  recoveryKey: Uint8Array,
  aad?: Uint8Array
): Promise<AeadEnvelopeV1> {
  assertByteLength("masterKey", masterKey, 32);
  assertByteLength("recoveryKey", recoveryKey, 32);
  return encryptWithKey(recoveryKey, masterKey, aad);
}

/**
 * Buka master key menggunakan recovery key.
 *
 * @param recoveryKey - Recovery key 32-byte.
 * @param wrapped - Envelope hasil wrap master key.
 * @param aad - Additional authenticated data (opsional).
 * @returns Bytes master key.
 *
 * @example
 * const masterKey = await unwrapMasterKeyWithRecoveryKey(recoveryKey, wrapped);
 */
export async function unwrapMasterKeyWithRecoveryKey(
  recoveryKey: Uint8Array,
  wrapped: AeadEnvelopeV1,
  aad?: Uint8Array
): Promise<Uint8Array> {
  assertByteLength("recoveryKey", recoveryKey, 32);
  const masterKey = await decryptWithKey(recoveryKey, wrapped, aad);
  assertByteLength("masterKey", masterKey, 32);
  return masterKey;
}

/**
 * Bungkus recovery key menggunakan master key.
 *
 * @param recoveryKey - Recovery key 32-byte.
 * @param masterKey - Master key 32-byte.
 * @param aad - Additional authenticated data (opsional).
 * @returns Envelope hasil wrap.
 *
 * @example
 * const wrapped = await wrapRecoveryKeyWithMasterKey(recoveryKey, masterKey);
 */
export async function wrapRecoveryKeyWithMasterKey(
  recoveryKey: Uint8Array,
  masterKey: Uint8Array,
  aad?: Uint8Array
): Promise<AeadEnvelopeV1> {
  assertByteLength("recoveryKey", recoveryKey, 32);
  assertByteLength("masterKey", masterKey, 32);
  return encryptWithKey(masterKey, recoveryKey, aad);
}

/**
 * Buka recovery key menggunakan master key.
 *
 * @param masterKey - Master key 32-byte.
 * @param wrapped - Envelope hasil wrap recovery key.
 * @param aad - Additional authenticated data (opsional).
 * @returns Bytes recovery key.
 *
 * @example
 * const recoveryKey = await unwrapRecoveryKeyWithMasterKey(masterKey, wrapped);
 */
export async function unwrapRecoveryKeyWithMasterKey(
  masterKey: Uint8Array,
  wrapped: AeadEnvelopeV1,
  aad?: Uint8Array
): Promise<Uint8Array> {
  assertByteLength("masterKey", masterKey, 32);
  const recoveryKey = await decryptWithKey(masterKey, wrapped, aad);
  assertByteLength("recoveryKey", recoveryKey, 32);
  return recoveryKey;
}
