import sodium from "libsodium-wrappers-sumo";
import { assertByteLength } from "../utils/bytes.js";
import type { PasswordWrappedKeyV1 } from "../types.js";
import type { PasswordKdfOptions } from "./password-kdf.js";
import { unwrapKeyWithPassword, wrapKeyWithPassword } from "./password-kdf.js";

// Domain: master key lifecycle (generate/derive/wrap/unwrap).
/**
 * Generate master key 32-byte secara acak.
 *
 * @returns Bytes master key.
 *
 * @example
 * const masterKey = await generateMasterKey();
 */
export async function generateMasterKey(): Promise<Uint8Array> {
  await sodium.ready;
  return sodium.randombytes_buf(32);
}

/**
 * Generate master key baru lalu bungkus (wrap) dengan password.
 *
 * @param password - String password pengguna yang dipakai untuk KDF.
 * @param opts - Opsi KDF.
 * @param opts.opslimit - Jumlah operasi KDF (Argon2). Semakin besar -> semakin lama proses derivasi,
 *   lebih tahan brute-force.
 * @param opts.memlimit - Batas memori KDF. Semakin besar -> lebih sulit diserang GPU/ASIC,
 *   tapi lebih berat di device.
 * @param opts.salt - Salt KDF (32 bytes). Jika tidak diberikan, dibuat acak otomatis.
 * @param aad - Data tambahan yang diikat ke ciphertext (integritas) tapi tidak dienkripsi.
 *   Contoh: userId, appVersion, slot.
 * @returns Object berisi `masterKey` dan `wrapped`.
 *
 * Catatan: `nonce` untuk encrypt dibuat otomatis di wrapKeyWithPassword, tidak diisi manual.
 *
 * @example
 * const aad = sodium.from_string("uid:user_123|app:v1|slot:password");
 * const { masterKey, wrapped } = await generateMasterKeyWithPassword(
 *   "secret-password",
 *   {
 *     opslimit: sodium.crypto_pwhash_OPSLIMIT_MODERATE,
 *     memlimit: sodium.crypto_pwhash_MEMLIMIT_MODERATE,
 *   },
 *   aad
 * );
 */
export async function generateMasterKeyWithPassword(
  password: string,
  opts?: PasswordKdfOptions,
  aad?: Uint8Array
): Promise<{ masterKey: Uint8Array; wrapped: PasswordWrappedKeyV1 }> {
  const masterKey = await generateMasterKey();
  const wrapped = await wrapMasterKeyWithPassword(
    masterKey,
    password,
    opts,
    aad
  );
  return { masterKey, wrapped };
}

/**
 * Bungkus master key menggunakan key turunan dari password.
 *
 * @param masterKey - Master key 32-byte.
 * @param password - Password pengguna.
 * @param opts - Opsi KDF.
 * @param aad - Additional authenticated data (opsional).
 * @returns Payload master key yang dibungkus.
 *
 * @example
 * const wrapped = await wrapMasterKeyWithPassword(masterKey, "secret");
 */
export async function wrapMasterKeyWithPassword(
  masterKey: Uint8Array,
  password: string,
  opts?: PasswordKdfOptions,
  aad?: Uint8Array
): Promise<PasswordWrappedKeyV1> {
  assertByteLength("masterKey", masterKey, 32);
  return wrapKeyWithPassword(masterKey, password, opts, aad);
}

/**
 * Buka master key menggunakan key turunan dari password.
 *
 * @param password - Password pengguna.
 * @param wrapped - Payload master key yang dibungkus.
 * @param aad - Additional authenticated data (opsional).
 * @returns Bytes master key.
 *
 * @example
 * const masterKey = await unwrapMasterKeyWithPassword("secret", wrapped);
 */
export async function unwrapMasterKeyWithPassword(
  password: string,
  wrapped: PasswordWrappedKeyV1,
  aad?: Uint8Array
): Promise<Uint8Array> {
  return unwrapKeyWithPassword(password, wrapped, aad);
}
