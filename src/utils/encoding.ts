import sodium from "libsodium-wrappers-sumo";

// Shared low-level helpers for core crypto modules.
/**
 * Encode bytes ke base64 (variant original).
 *
 * @param u8 - Bytes input.
 * @returns String base64.
 *
 * @example
 * const s = encodeBase64(new Uint8Array([1, 2, 3]));
 */
export function encodeBase64(u8: Uint8Array): string {
  return sodium.to_base64(u8, sodium.base64_variants.ORIGINAL);
}

/**
 * Decode string base64 ke bytes (variant original).
 *
 * @param s - String base64.
 * @returns Bytes hasil decode.
 *
 * @example
 * const u8 = decodeBase64("AQID");
 */
export function decodeBase64(s: string): Uint8Array {
  return sodium.from_base64(s, sodium.base64_variants.ORIGINAL);
}
