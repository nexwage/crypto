import sodium from "libsodium-wrappers-sumo";

/**
 * Tunggu libsodium siap dipakai.
 */
/**
 * Panjang salt untuk KDF.
 * Nilai di-set setelah `ready()`.
 */
export let cryptoPwhashSaltBytes = 0;

/**
 * Default opslimit KDF (moderate).
 * Nilai di-set setelah `ready()`.
 */
export let cryptoPwhashOpslimitModerate = 0;

/**
 * Default memlimit KDF (moderate).
 * Nilai di-set setelah `ready()`.
 */
export let cryptoPwhashMemlimitModerate = 0;

/**
 * Panjang nonce AEAD XChaCha20-Poly1305.
 * Nilai di-set setelah `ready()`.
 */
export let aeadXChaCha20Poly1305IetfNpubBytes = 0;

/**
 * Variant base64 ORIGINAL (libsodium).
 * Nilai di-set setelah `ready()`.
 */
export let base64VariantOriginal = 0;

/**
 * Tunggu libsodium siap dipakai.
 */
export async function ready(): Promise<void> {
  await sodium.ready;
  cryptoPwhashSaltBytes = sodium.crypto_pwhash_SALTBYTES;
  cryptoPwhashOpslimitModerate = sodium.crypto_pwhash_OPSLIMIT_MODERATE;
  cryptoPwhashMemlimitModerate = sodium.crypto_pwhash_MEMLIMIT_MODERATE;
  aeadXChaCha20Poly1305IetfNpubBytes =
    sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
  base64VariantOriginal = sodium.base64_variants.ORIGINAL;
}

/**
 * Generate bytes acak.
 *
 * @param size - Panjang output (bytes).
 * @returns Bytes acak.
 */
export function randombytesBuf(size: number): Uint8Array {
  return sodium.randombytes_buf(size);
}

/**
 * Derivasi key dari password (Argon2).
 *
 * @param outLen - Panjang output key (bytes).
 * @param password - Password input.
 * @param salt - Salt KDF.
 * @param opslimit - Batas operasi KDF.
 * @param memlimit - Batas memori KDF.
 * @param alg - Algoritma KDF.
 * @returns Key hasil derivasi.
 */
export function cryptoPwhash(
  outLen: number,
  password: string,
  salt: Uint8Array,
  opslimit: number,
  memlimit: number,
  alg: number
): Uint8Array {
  return sodium.crypto_pwhash(outLen, password, salt, opslimit, memlimit, alg);
}

/**
 * Enkripsi AEAD XChaCha20-Poly1305 (IETF).
 *
 * @param message - Plaintext.
 * @param aad - Additional authenticated data.
 * @param secretNonce - Secret nonce (null untuk tidak dipakai).
 * @param publicNonce - Public nonce.
 * @param key - Key 32-byte.
 * @returns Ciphertext + tag.
 */
export function aeadXChaCha20Poly1305IetfEncrypt(
  message: Uint8Array,
  aad: Uint8Array | null,
  secretNonce: Uint8Array | null,
  publicNonce: Uint8Array,
  key: Uint8Array
): Uint8Array {
  return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    message,
    aad,
    secretNonce,
    publicNonce,
    key
  );
}

/**
 * Dekripsi AEAD XChaCha20-Poly1305 (IETF).
 *
 * @param secretNonce - Secret nonce (null untuk tidak dipakai).
 * @param ciphertext - Ciphertext + tag.
 * @param aad - Additional authenticated data.
 * @param publicNonce - Public nonce.
 * @param key - Key 32-byte.
 * @returns Plaintext.
 */
export function aeadXChaCha20Poly1305IetfDecrypt(
  secretNonce: Uint8Array | null,
  ciphertext: Uint8Array,
  aad: Uint8Array | null,
  publicNonce: Uint8Array,
  key: Uint8Array
): Uint8Array {
  return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    secretNonce,
    ciphertext,
    aad,
    publicNonce,
    key
  );
}

/**
 * Encode bytes ke base64 (variant default sodium).
 *
 * @param data - Bytes input.
 * @returns String base64.
 */
export function toBase64(data: Uint8Array): string {
  return sodium.to_base64(data);
}

/**
 * Decode string base64 ke bytes (variant default sodium).
 *
 * @param data - String base64.
 * @returns Bytes hasil decode.
 */
export function fromBase64(data: string): Uint8Array {
  return sodium.from_base64(data);
}

/**
 * Encode string ke bytes (UTF-8).
 *
 * @param data - String input.
 * @returns Bytes UTF-8.
 */
export function fromString(data: string): Uint8Array {
  return sodium.from_string(data);
}

/**
 * Decode bytes ke string (UTF-8).
 *
 * @param data - Bytes input.
 * @returns String hasil decode.
 */
export function toString(data: Uint8Array): string {
  return sodium.to_string(data);
}

/**
 * Bandingkan bytes secara aman (constant-time).
 *
 * @param a - Bytes pertama.
 * @param b - Bytes kedua.
 * @returns True jika sama.
 */
export function memcmp(a: Uint8Array, b: Uint8Array): boolean {
  return sodium.memcmp(a, b);
}

/**
 * Akses penuh ke instance libsodium.
 */
export { sodium };
