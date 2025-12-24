# @nexwage/crypto

Minimal, opinionated crypto building blocks for password-based master keys, recovery keys, and file encryption. Built on libsodium with XChaCha20-Poly1305 and Argon2.

## Install

```sh
npm i @nexwage/crypto
```

## Quick Start

```ts
import {
  generateMasterKeyWithPassword,
  unwrapMasterKeyWithPassword,
  generateRecoveryKey,
  wrapMasterKeyWithRecoveryKey,
  generateFileKey,
  wrapFileKeyWithMasterKey,
  encryptFileData,
  decryptFileData,
} from "@nexwage/crypto";

const password = "strong-password";
const aad = new TextEncoder().encode("uid:user_123|app:v1|slot:password");

const { masterKey, wrapped } = await generateMasterKeyWithPassword(
  password,
  undefined,
  aad
);

const recoveryKey = await generateRecoveryKey();
const wrappedByRecovery = await wrapMasterKeyWithRecoveryKey(
  masterKey,
  recoveryKey,
  aad
);

const fileKey = await generateFileKey();
const wrappedFileKey = await wrapFileKeyWithMasterKey(fileKey, masterKey, aad);

const fileBytes = new TextEncoder().encode("file rahasia");
const encryptedFile = await encryptFileData(fileKey, fileBytes, aad);

const masterKey2 = await unwrapMasterKeyWithPassword(password, wrapped, aad);
const fileKey2 = await unwrapFileKeyWithMasterKey(
  masterKey2,
  wrappedFileKey,
  aad
);
const decryptedFile = await decryptFileData(fileKey2, encryptedFile, aad);
```

## Project Structure

| Path | Purpose |
| --- | --- |
| `src/index.ts` | Public exports. |
| `src/types.ts` | Payload types + versioning. |
| `src/crypto/password-kdf.ts` | Password KDF + key wrapping. |
| `src/crypto/master-key.ts` | Master key lifecycle. |
| `src/crypto/recovery-key.ts` | Recovery key wrapping. |
| `src/crypto/file-encryption.ts` | File key + file encryption. |
| `src/utils/encoding.ts` | Base64 helpers. |
| `src/utils/bytes.ts` | Byte length assertions. |
| `src/sodium.ts` | libsodium wrapper exports. |
| `examples/basic-flow.ts` | End-to-end flow. |
| `examples/master-key-example.ts` | Master key example. |

## AAD and Versioning

- AAD (Additional Authenticated Data) binds ciphertext to context (userId, slot, fileId).
- Versioning (`v`) keeps payloads forward-compatible when formats or algorithms change.

## Manual Test

See `examples/basic-flow.ts` for the full 3-flow example.

## Glossary

Panduan ringkas istilah dan konsep yang dipakai di modul ini.

| Term | Meaning |
| --- | --- |
| Master Key (MK) | Kunci utama untuk membuka kunci lain (file key, recovery key). |
| Recovery Key | Kunci cadangan jika lupa password. |
| File Key | Kunci khusus per file. |
| Wrap/Unwrap | Membungkus dan membuka kunci menggunakan enkripsi. |
| AEAD | Enkripsi + integritas dalam satu skema. |
| AAD | Metadata yang diikat ke ciphertext tanpa dienkripsi. |
| KDF | Mengubah password menjadi key yang kuat. |
| Nonce | Angka acak sekali pakai untuk enkripsi. |
| Ciphertext (ct) | Hasil enkripsi. |
| Envelope | Struktur payload berisi `nonce`, `ct`, dan `v`. |
| Versioning (v) | Versi format payload. |

## libsodium Functions Used

| Function/Property | Description |
| --- | --- |
| `sodium.ready` | Menunggu libsodium siap dipakai. |
| `sodium.randombytes_buf` | Generate bytes acak (kunci, nonce). |
| `sodium.crypto_pwhash` | Derivasi key dari password (Argon2). |
| `sodium.crypto_pwhash_SALTBYTES` | Panjang salt untuk KDF. |
| `sodium.crypto_pwhash_OPSLIMIT_MODERATE` | Default opslimit KDF. |
| `sodium.crypto_pwhash_MEMLIMIT_MODERATE` | Default memlimit KDF. |
| `sodium.crypto_aead_xchacha20poly1305_ietf_encrypt` | Enkripsi AEAD XChaCha20-Poly1305. |
| `sodium.crypto_aead_xchacha20poly1305_ietf_decrypt` | Dekripsi AEAD XChaCha20-Poly1305. |
| `sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES` | Panjang nonce AEAD XChaCha20-Poly1305. |
| `sodium.to_base64` | Encode bytes ke base64. |
| `sodium.from_base64` | Decode base64 ke bytes. |
| `sodium.base64_variants.ORIGINAL` | Variant base64 yang dipakai. |
| `sodium.from_string` | Encode string ke bytes (UTF-8). |
| `sodium.to_string` | Decode bytes ke string (UTF-8). |
| `sodium.memcmp` | Bandingkan bytes secara aman (constant-time). |

## Planned libsodium Functions

| Function/Property | Planned use |
| --- | --- |
| `sodium.crypto_generichash` | Hash konteks/AAD jika perlu bentuk stabil dan ringkas. |
| `sodium.crypto_kdf_derive_from_key` | Derivasi sub-key per domain dari satu kunci root. |
| `sodium.crypto_aead_aes256gcm_encrypt` | Alternatif AEAD dengan akselerasi hardware. |
| `sodium.crypto_aead_aes256gcm_decrypt` | Pasangan decrypt AES-GCM. |
| `sodium.crypto_secretbox_easy` | Enkripsi simetris sederhana untuk payload non-AEAD. |
| `sodium.crypto_secretbox_open_easy` | Dekripsi secretbox. |

## AAD Example

```ts
import { fromString } from "@nexwage/crypto";

const aad = fromString("uid:user_123|app:v1|slot:password");
```

## KDF Parameters

| Parameter | Purpose |
| --- | --- |
| opslimit | Jumlah operasi KDF (lebih besar = lebih lambat, lebih tahan brute-force). |
| memlimit | Batas memori KDF (lebih besar = lebih tahan GPU/ASIC). |
| salt | Salt acak 32-byte untuk mencegah rainbow table. |

## Envelope Format

```json
{
  "v": 1,
  "nonce": "base64",
  "ct": "base64"
}
```

## Versioning Rules

1. Saat encrypt, isi `v` dengan versi terbaru.
2. Saat decrypt, cek `v` lalu pilih logika yang sesuai.
3. Jika `v` tidak didukung, tolak dekripsi atau lakukan migrasi.

Contoh payload:

```json
{
  "v": 1,
  "kdf": { "v": 1, "salt": "...", "opslimit": 3, "memlimit": 268435456 },
  "nonce": "....",
  "ct": "...."
}
```
