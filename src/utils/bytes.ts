/**
 * Validasi panjang buffer sesuai ekspektasi.
 *
 * @param name - Label untuk pesan error.
 * @param u8 - Bytes input.
 * @param len - Panjang yang diharapkan (bytes).
 *
 * @example
 * assertByteLength("masterKey", key, 32);
 */
export function assertByteLength(name: string, u8: Uint8Array, len: number) {
  if (u8.length !== len) {
    throw new Error(`${name} harus ${len} bytes, dapat ${u8.length}`);
  }
}
