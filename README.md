# @nexwage/crypto

Library kripto minimal berbasis libsodium untuk alur master key, recovery key, dan enkripsi file. Menggunakan XChaCha20-Poly1305 untuk AEAD dan Argon2 untuk KDF password.

## Instalasi

```sh
npm i @nexwage/crypto
```

## Kompatibilitas

- ESM (type: module)
- Node.js 18+ (direkomendasikan)

## Mulai Cepat

```ts
import {
  generateMasterKeyWithPassword,
  unwrapMasterKeyWithPassword,
  generateRecoveryKey,
  wrapMasterKeyWithRecoveryKey,
  generateFileKey,
  wrapFileKeyWithMasterKey,
  unwrapFileKeyWithMasterKey,
  encryptFileData,
  decryptFileData,
  fromString,
} from "@nexwage/crypto";

const password = "strong-password";
const aad = fromString("uid:user_123|app:v1|slot:password");

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

const fileBytes = fromString("file rahasia");
const encryptedFile = await encryptFileData(fileKey, fileBytes, aad);

const masterKey2 = await unwrapMasterKeyWithPassword(password, wrapped, aad);
const fileKey2 = await unwrapFileKeyWithMasterKey(
  masterKey2,
  wrappedFileKey,
  aad
);
const decryptedFile = await decryptFileData(fileKey2, encryptedFile, aad);
```

## Konsep Utama

- Master Key: kunci utama untuk membuka kunci lain.
- Recovery Key: kunci cadangan jika password hilang.
- File Key: kunci khusus per file.
- Wrap/Unwrap: membungkus dan membuka kunci memakai AEAD.
- AAD: data konteks yang diikat ke ciphertext (tidak dienkripsi).
- Versioning: field `v` pada payload untuk kompatibilitas format.

## Alur Dasar

Alur 1: Setup awal + upload
1) Generate master key lalu wrap dengan password.
2) Generate recovery key.
3) Wrap master key dengan recovery key (recovery).
4) Wrap recovery key dengan master key (backup recovery key).
5) Generate file key.
6) Wrap file key dengan master key.
7) Enkripsi file pakai file key.

Alur 2: Buka file (login normal)
1) Ambil wrapped master key.
2) Unwrap master key pakai password.
3) Unwrap file key pakai master key.
4) Dekripsi file.

Alur 3: Recovery + re-encrypt
1) Ambil wrapped master key.
2) Unwrap master key pakai recovery key.
3) Re-wrap master key dengan password baru.

## Referensi API

Semua fungsi diekspor dari `@nexwage/crypto`.

### Peta Penggunaan di Kasus Industri (Per Domain)

#### Simetris (Password + File + Recovery)

| Metode/Fitur | Kasus Industri Nyata | Kenapa Dipakai | Contoh Implementasi |
| --- | --- | --- | --- |
| Master Key + Password KDF | Zero‑knowledge SaaS (password vault, secure notes) | Password tidak pernah dikirim ke server; master key tetap terenkripsi | `generateMasterKeyWithPassword` saat signup, simpan `wrapped` di server |
| Recovery Key | Recovery akun tanpa reset password | Memberi opsi recovery tanpa membuka password | Simpan `wrapMasterKeyWithRecoveryKey` di server, recovery key dipegang user |
| File Key + Wrap | Enkripsi per file untuk performa dan isolasi | Setiap file punya key sendiri; kompromi satu file tidak bocor semua | `generateFileKey` + `wrapFileKeyWithMasterKey` per file |
| AEAD XChaCha20-Poly1305 | Enkripsi data at rest/in transit | Authenticated encryption, tahan tampering | `encryptFileData` / `decryptFileData` |
| AAD | Bind data ke konteks (userId, fileId, slot) | Mencegah swap/replay antar konteks | AAD berisi `userId|fileId|slot` |
| Versioning (`v`) | Migrasi format/enkripsi | Menjaga kompatibilitas payload lama | Simpan `v` di payload, upgrade saat decrypt |

#### Asimetris (Key Exchange + Signature)

| Metode/Fitur | Kasus Industri Nyata | Kenapa Dipakai | Contoh Implementasi |
| --- | --- | --- | --- |
| Key Exchange (X25519) | Secure session key (chat, realtime sync) | Negosiasi kunci simetris tanpa berbagi rahasia | `deriveClientSessionKeys` + `deriveServerSessionKeys` |
| Sealed Box | Share ke penerima tanpa keypair pengirim | Enkripsi langsung ke public key penerima | `encryptSealedBox` untuk file sharing 1:1 |
| Signature (Ed25519) | Audit log, proof of authorship | Verifikasi integritas dan sumber data | Tanda tangan metadata/commit dengan `signMessage` |

#### Group (MLS-like)

| Metode/Fitur | Kasus Industri Nyata | Kenapa Dipakai | Contoh Implementasi |
| --- | --- | --- | --- |
| Group Commit + Epoch | Team sharing (drive tim, workspace) | Rotasi kunci saat member berubah | `createGroupCommit` + `applyGroupCommit` setiap perubahan anggota |
| Group Key Derivation | Enkripsi grup skala besar | Satu group key untuk banyak file | `deriveGroupKey` untuk wrap file key |
| Welcome Payload | Onboarding member baru | Distribusi secret awal dengan aman | `createGroupState` + `openGroupWelcome` |

#### Wrapper libsodium

| Metode/Fitur | Kasus Industri Nyata | Kenapa Dipakai | Contoh Implementasi |
| --- | --- | --- | --- |
| libsodium Wrapper | Akses primitive low-level | Integrasi fleksibel ke arsitektur existing | `cryptoPwhash`, `aeadXChaCha20Poly1305IetfEncrypt` |

### Tipe Export

- `AeadEnvelopeV1`
- `PasswordKdfParamsV1`
- `PasswordWrappedKeyV1`
- `PasswordKdfOptions`
- `KeyExchangeKeyPair`
- `SessionKeys`
- `SigningKeyPair`
- `GroupMember`
- `GroupMemberWire`
- `GroupState`
- `GroupWelcome`
- `GroupCommit`
- `GroupCommitAction`

### Master Key

- `generateMasterKey(): Promise<Uint8Array>`
- `generateMasterKeyWithPassword(password, opts?, aad?): Promise<{ masterKey; wrapped }>`
- `wrapMasterKeyWithPassword(masterKey, password, opts?, aad?): Promise<PasswordWrappedKeyV1>`
- `unwrapMasterKeyWithPassword(password, wrapped, aad?): Promise<Uint8Array>`

### Recovery Key

- `generateRecoveryKey(): Promise<Uint8Array>`
- `wrapMasterKeyWithRecoveryKey(masterKey, recoveryKey, aad?): Promise<AeadEnvelopeV1>`
- `unwrapMasterKeyWithRecoveryKey(recoveryKey, wrapped, aad?): Promise<Uint8Array>`
- `wrapRecoveryKeyWithMasterKey(recoveryKey, masterKey, aad?): Promise<AeadEnvelopeV1>`
- `unwrapRecoveryKeyWithMasterKey(masterKey, wrapped, aad?): Promise<Uint8Array>`

### File Encryption

- `generateFileKey(): Promise<Uint8Array>`
- `wrapFileKeyWithMasterKey(fileKey, masterKey, aad?): Promise<AeadEnvelopeV1>`
- `unwrapFileKeyWithMasterKey(masterKey, wrapped, aad?): Promise<Uint8Array>`
- `encryptFileData(fileKey, plaintext, aad?): Promise<AeadEnvelopeV1>`
- `decryptFileData(fileKey, wrapped, aad?): Promise<Uint8Array>`

### Password KDF

- `deriveKeyFromPassword(password, opts?): Promise<{ key; kdf }>`
- `wrapKeyWithPassword(key, password, opts?, aad?): Promise<PasswordWrappedKeyV1>`
- `unwrapKeyWithPassword(password, wrapped, aad?): Promise<Uint8Array>`

Opsi KDF (`PasswordKdfOptions`):
- `opslimit` (number)
- `memlimit` (number)
- `salt` (Uint8Array)

### Utilitas Encoding

- `encodeBase64(u8): string`
- `decodeBase64(s): Uint8Array`
- `fromString(s): Uint8Array`
- `toString(u8): string`

### Wrapper libsodium

Wrapper disediakan agar fungsi libsodium bisa dipanggil dari library ini:

- `sodiumReady(): Promise<void>`: wajib dipanggil jika ingin akses konstanta libsodium secara aman.
- `randombytesBuf(size): Uint8Array`
- `cryptoPwhash(outLen, password, salt, opslimit, memlimit, alg): Uint8Array`
- `cryptoPwhashSaltBytes`
- `cryptoPwhashOpslimitModerate`
- `cryptoPwhashMemlimitModerate`
- `aeadXChaCha20Poly1305IetfEncrypt(message, aad, secretNonce, publicNonce, key)`
- `aeadXChaCha20Poly1305IetfDecrypt(secretNonce, ciphertext, aad, publicNonce, key)`
- `aeadXChaCha20Poly1305IetfNpubBytes`
- `toBase64(u8): string`
- `fromBase64(s): Uint8Array`
- `base64VariantOriginal`
- `memcmp(a, b): boolean`
- `sodium` (akses penuh ke instance libsodium)

Catatan: konstanta seperti `cryptoPwhashSaltBytes` diisi setelah `sodiumReady()` dipanggil.

### Asimetris: Key Exchange & Signature

Library ini menyediakan dua keypair terpisah:
1) X25519 untuk key exchange/shared key.
2) Ed25519 untuk tanda tangan digital.

Key exchange (X25519):
- `generateKeyExchangeKeyPair(): Promise<{ publicKey; privateKey }>`
- `deriveClientSessionKeys(clientKeyPair, serverPublicKey): Promise<{ rx; tx }>`
- `deriveServerSessionKeys(serverKeyPair, clientPublicKey): Promise<{ rx; tx }>`
- `encryptSealedBox(message, recipientPublicKey): Promise<Uint8Array>`
- `decryptSealedBox(ciphertext, recipientKeyPair): Promise<Uint8Array>`

Signature (Ed25519):
- `generateSigningKeyPair(): Promise<{ publicKey; privateKey }>`
- `signMessage(message, privateKey): Promise<Uint8Array>`
- `verifySignature(message, signature, publicKey): Promise<boolean>`

### Group (MLS-like, tahap awal)

Implementasi awal untuk group key management dengan commit + epoch. Saat ini masih O(n) karena secret baru dibagikan via sealed box ke setiap member. Struktur API disiapkan agar dapat ditingkatkan ke tree-based MLS.

- `createGroupState(groupId, members): Promise<{ state; welcome }>`
- `openGroupWelcome(welcome, recipientId, recipientKeyPair): Promise<GroupState>`
- `deriveGroupKey(state): Promise<Uint8Array>`
- `createGroupCommit(state, senderId, senderSignPrivateKey, action, updates?): Promise<{ commit; state }>`
- `verifyGroupCommitSignature(commit, senderSignPublicKey): Promise<boolean>`
- `applyGroupCommit(state, commit, recipientId, recipientKeyPair, senderSignPublicKey): Promise<GroupState>`

Catatan:
- `GroupMember.signPublicKey` bersifat opsional dan hanya diperlukan jika kamu ingin menyimpan public key signature di metadata group.
- Semua payload group disarankan disimpan sebagai JSON di server (zero-knowledge friendly).

## Format Payload

AEAD envelope:
```json
{
  "v": 1,
  "nonce": "base64",
  "ct": "base64"
}
```

Password-wrapped key:
```json
{
  "v": 1,
  "kdf": { "v": 1, "salt": "...", "opslimit": 3, "memlimit": 268435456 },
  "nonce": "....",
  "ct": "...."
}
```

## AAD (Additional Authenticated Data)

AAD digunakan untuk mengikat ciphertext ke konteks (mis. userId, slot, fileId). Jika AAD salah, proses decrypt akan gagal.

Contoh AAD:
```ts
import { fromString } from "@nexwage/crypto";
const aad = fromString("uid:user_123|app:v1|slot:password");
```

## Penanganan Error

- Jika ukuran key/salt/nonce salah, fungsi akan melempar error validasi.
- Jika password/AAD salah, decrypt akan gagal dan melempar error.

## Struktur Proyek

| Path | Tujuan |
| --- | --- |
| `src/index.ts` | Public exports. |
| `src/types.ts` | Tipe payload dan versioning. |
| `src/crypto/password-kdf.ts` | KDF password + wrap/unwrap key. |
| `src/crypto/master-key.ts` | Lifecycle master key. |
| `src/crypto/recovery-key.ts` | Recovery key wrapping. |
| `src/crypto/file-encryption.ts` | File key + enkripsi/dekripsi file. |
| `src/crypto/key-exchange.ts` | Key exchange (X25519) + sealed box. |
| `src/crypto/signature.ts` | Tanda tangan digital (Ed25519). |
| `src/crypto/group.ts` | Group key management (MLS-like tahap awal). |
| `src/utils/encoding.ts` | Helper base64. |
| `src/utils/bytes.ts` | Validasi panjang bytes. |
| `src/sodium.ts` | Wrapper libsodium. |
| `examples/basic-flow.ts` | Contoh alur end-to-end. |
| `examples/master-key-example.ts` | Contoh master key + KDF. |
| `examples/asymmetric-key-exchange.ts` | Contoh key exchange + sealed box. |
| `examples/asymmetric-signature.ts` | Contoh signature. |
| `examples/group-basic.ts` | Contoh group basic. |
| `SIMULATION.md` | Simulasi ringkas simetris & asimetris. |

## Pengujian

```sh
npm test
```

## Build

```sh
npm run build
```

## Examples

Jalankan contoh:

```sh
npm run example:kx
npm run example:sign
npm run example:basic
npm run example:group
```

Contoh output (ringkas):

Key exchange + sealed box:
```text
[kx] generate keypairs
[kx] client public key (b64): ...
[kx] server public key (b64): ...
[kx] derive session keys
[kx] client tx (b64): ...
[kx] client rx (b64): ...
[kx] server tx (b64): ...
[kx] server rx (b64): ...
[kx] shared tx/rx matches (base64 compare):
[kx] client tx == server rx: true
[kx] client rx == server tx: true
[sealed] encrypt to server public key
[sealed] ciphertext (b64): ...
[sealed] ciphertext bytes: ...
[sealed] decrypt with server keypair
[sealed] plaintext: hello sealed box
```

Signature:
```text
[sign] generate keypair
[sign] public key (b64): ...
[sign] private key bytes: 64
[sign] message bytes: ...
[sign] create signature
[sign] signature (b64): ...
[sign] signature bytes: 64
[sign] verify signature (valid)
[sign] result: true
[sign] verify signature (invalid)
[sign] result: false
```

Basic flow:
```text
[alur1] masterKey: ...
[alur1] wrappedMasterKey: ...
[alur1] wrappedMasterKeyByRecovery: ...
[alur1] wrappedRecoveryKey: ...
[alur1] wrappedFileKey: ...
[alur1] encryptedFile: ...
[alur2] masterKey2: ...
[alur2] fileKey2: ...
[alur2] fileBytes2: file rahasia
[alur3] masterKey3: ...
[alur3] wrappedMasterKeyNew: ...
[alur3] wrappedMasterKeyByRecoveryNew: ...
[done] semua alur OK
```

Contoh output error (AAD/password salah):
```text
Error: Gagal membuka file: ciphertext/AAD/keys tidak valid
Error: Gagal membuka key: ciphertext/AAD/keys tidak valid
Error: Gagal membuka payload: ciphertext/AAD/keys tidak valid
```

Group:
```text
[group] create members
[group] create group state
[group] welcome epoch: 0
[group] members: alice, bob
[group] bob open welcome
[group] bob groupKey epoch 0 (b64): ...
[group] add carol with commit
[group] commit epoch: 1
[group] commit action: add
[group] commit members: alice, bob, carol
[group] bob apply commit
[group] bob groupKey epoch 1 (b64): ...
```

## Glossary

| Istilah | Makna |
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

## Lisensi

ISC
