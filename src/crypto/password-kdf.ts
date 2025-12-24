import sodium from "libsodium-wrappers-sumo";
import { assertByteLength } from "../utils/bytes.js";
import { decodeBase64, encodeBase64 } from "../utils/encoding.js";
import type { PasswordKdfParamsV1, PasswordWrappedKeyV1 } from "../types.js";

// Domain: password-based key derivation + key wrapping.
export interface PasswordKdfOptions {
  opslimit?: number;
  memlimit?: number;
  salt?: Uint8Array;
}

/**
 * Derivasi key 32-byte dari password menggunakan Argon2.
 *
 * @param password - Password pengguna.
 * @param opts - Opsi KDF.
 * @param opts.opslimit - Batas operasi KDF.
 * @param opts.memlimit - Batas memori KDF.
 * @param opts.salt - Salt KDF (32 bytes). Random jika tidak diisi.
 * @returns Key hasil derivasi dan parameter KDF untuk disimpan.
 *
 * @example
 * const { key, kdf } = await deriveKeyFromPassword("secret");
 */
export async function deriveKeyFromPassword(
  password: string,
  opts?: PasswordKdfOptions
): Promise<{ key: Uint8Array; kdf: PasswordKdfParamsV1 }> {
  await sodium.ready;

  const opslimit = opts?.opslimit ?? sodium.crypto_pwhash_OPSLIMIT_MODERATE;
  const memlimit = opts?.memlimit ?? sodium.crypto_pwhash_MEMLIMIT_MODERATE;
  const salt =
    opts?.salt ?? sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);

  assertByteLength("salt", salt, sodium.crypto_pwhash_SALTBYTES);

  const key = sodium.crypto_pwhash(
    32,
    password,
    salt,
    opslimit,
    memlimit,
    sodium.crypto_pwhash_ALG_DEFAULT
  );

  return {
    key,
    kdf: {
      v: 1,
      salt: encodeBase64(salt),
      opslimit,
      memlimit,
    },
  };
}

/**
 * Bungkus (wrap) key menggunakan key turunan dari password.
 *
 * @param key - Key 32-byte yang akan dibungkus.
 * @param password - Password pengguna.
 * @param opts - Opsi KDF.
 * @param aad - Additional authenticated data (opsional).
 * @returns Payload key yang sudah dibungkus.
 *
 * @example
 * const wrapped = await wrapKeyWithPassword(key, "secret");
 */
export async function wrapKeyWithPassword(
  key: Uint8Array,
  password: string,
  opts?: PasswordKdfOptions,
  aad?: Uint8Array
): Promise<PasswordWrappedKeyV1> {
  await sodium.ready;
  assertByteLength("key", key, 32);

  const { key: wrapKey, kdf } = await deriveKeyFromPassword(password, opts);
  const nonce = sodium.randombytes_buf(
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES
  );

  const ct = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    key,
    aad ?? null,
    null,
    nonce,
    wrapKey
  );

  sodium.memzero(wrapKey);

  return {
    v: 1,
    kdf,
    nonce: encodeBase64(nonce),
    ct: encodeBase64(ct),
  };
}

/**
 * Buka (unwrap) key menggunakan key turunan dari password.
 *
 * @param password - Password pengguna.
 * @param wrapped - Payload key yang dibungkus.
 * @param aad - Additional authenticated data (opsional).
 * @returns Bytes key hasil unwrap.
 *
 * @example
 * const key = await unwrapKeyWithPassword("secret", wrapped);
 */
export async function unwrapKeyWithPassword(
  password: string,
  wrapped: PasswordWrappedKeyV1,
  aad?: Uint8Array
): Promise<Uint8Array> {
  await sodium.ready;

  const salt = decodeBase64(wrapped.kdf.salt);
  assertByteLength("salt", salt, sodium.crypto_pwhash_SALTBYTES);

  const { key: wrapKey } = await deriveKeyFromPassword(password, {
    salt,
    opslimit: wrapped.kdf.opslimit,
    memlimit: wrapped.kdf.memlimit,
  });

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
      wrapKey
    );
  } catch {
    throw new Error("Gagal membuka key: ciphertext/AAD/keys tidak valid");
  } finally {
    sodium.memzero(wrapKey);
  }
}
