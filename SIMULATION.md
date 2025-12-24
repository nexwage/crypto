# Simulasi Kripto (Simetris & Asimetris)

Dokumen ini berisi simulasi ringkas alur simetris dan asimetris menggunakan API dari `@nexwage/crypto`.

## Risiko Tanpa vs Dengan Kriptografi

Ringkasan risiko utama di sistem penyimpanan/pertukaran data.

| Area | Tanpa Kripto | Dengan Kripto (Library Ini) | Risiko yang Masih Ada |
| --- | --- | --- | --- |
| Data at rest | Admin/server bisa membaca isi data | Data terenkripsi; server hanya simpan ciphertext | Metadata (ukuran, waktu akses) tetap terlihat |
| Data in transit | Bisa disadap dan diubah | AEAD melindungi kerahasiaan + integritas | Jika kunci bocor, data tetap terbuka |
| Password | Password bisa bocor lewat server | Password tidak dikirim; KDF di client | Brute‑force jika KDF terlalu lemah |
| File sharing | Enkripsi manual/berulang | Sealed box / wrap file key | Salah AAD atau kunci salah = data tidak bisa dibuka |
| Replay | Request bisa diulang | Signature + nonce/timestamp | Perlu storage nonce untuk anti‑replay efektif |
| Insider risk | Admin bisa akses data | Zero‑knowledge: admin tidak pegang key | Kebocoran client tetap berbahaya |
| Rotasi member group | Kunci lama tetap berlaku | Commit + epoch untuk rotasi | O(n) distribusi secret (tahap awal) |

## 1) Simulasi Simetris (Master Key, Recovery Key, File)

Tujuan:
- Membuat master key dari password
- Membuat recovery key
- Membungkus master key dengan recovery key
- Membuat file key dan mengenkripsi file
- Membuka file kembali

```ts
import {
  generateMasterKeyWithPassword,
  unwrapMasterKeyWithPassword,
  generateRecoveryKey,
  wrapMasterKeyWithRecoveryKey,
  wrapRecoveryKeyWithMasterKey,
  unwrapMasterKeyWithRecoveryKey,
  generateFileKey,
  wrapFileKeyWithMasterKey,
  unwrapFileKeyWithMasterKey,
  encryptFileData,
  decryptFileData,
  fromString,
  toString,
  memcmp,
} from "@nexwage/crypto";

const password = "password-kuat";
const aad = fromString("uid:user_123|app:v1|slot:password");

// 1) Master key + wrap dengan password
const { masterKey, wrapped: wrappedMasterKey } =
  await generateMasterKeyWithPassword(password, undefined, aad);

// 2) Recovery key + wrap master key
const recoveryKey = await generateRecoveryKey();
const wrappedMasterByRecovery = await wrapMasterKeyWithRecoveryKey(
  masterKey,
  recoveryKey,
  aad
);

// 3) Backup recovery key dengan master key
const wrappedRecoveryKey = await wrapRecoveryKeyWithMasterKey(
  recoveryKey,
  masterKey,
  aad
);

// 4) File key + encrypt file
const fileKey = await generateFileKey();
const wrappedFileKey = await wrapFileKeyWithMasterKey(fileKey, masterKey, aad);
const fileBytes = fromString("file rahasia");
const encryptedFile = await encryptFileData(fileKey, fileBytes, aad);

// 5) Buka file dengan password
const masterKey2 = await unwrapMasterKeyWithPassword(
  password,
  wrappedMasterKey,
  aad
);
const fileKey2 = await unwrapFileKeyWithMasterKey(
  masterKey2,
  wrappedFileKey,
  aad
);
const fileBytes2 = await decryptFileData(fileKey2, encryptedFile, aad);

// Validasi
console.log("master key sama:", memcmp(masterKey, masterKey2));
console.log("file sama:", toString(fileBytes2));

// 6) Recovery flow (lupa password)
const masterKey3 = await unwrapMasterKeyWithRecoveryKey(
  recoveryKey,
  wrappedMasterByRecovery,
  aad
);
console.log("recovery master key sama:", memcmp(masterKey, masterKey3));
```

Ringkasan:
- Semua data sensitif (master key, file key, recovery key) selalu dalam bentuk **encrypted envelope** saat tersimpan/ditransmisikan.
- AAD mengikat ciphertext ke konteks yang benar.
Risiko yang masih ada:
- Jika password lemah, attacker bisa brute‑force KDF.
- Jika recovery key bocor, master key bisa dibuka tanpa password.

## 2) Simulasi Asimetris (Key Exchange + Sealed Box)

Tujuan:
- Membuat keypair X25519 untuk client dan server
- Menurunkan shared session keys
- Mengirim pesan ke public key server (sealed box)

```ts
import {
  generateKeyExchangeKeyPair,
  deriveClientSessionKeys,
  deriveServerSessionKeys,
  encryptSealedBox,
  decryptSealedBox,
  fromString,
  toString,
  memcmp,
} from "@nexwage/crypto";

// 1) Keypair
const client = await generateKeyExchangeKeyPair();
const server = await generateKeyExchangeKeyPair();

// 2) Session keys
const clientSession = await deriveClientSessionKeys(client, server.publicKey);
const serverSession = await deriveServerSessionKeys(server, client.publicKey);

console.log("client tx == server rx:", memcmp(clientSession.tx, serverSession.rx));
console.log("client rx == server tx:", memcmp(clientSession.rx, serverSession.tx));

// 3) Sealed box (encrypt to server public key)
const message = fromString("halo server");
const ciphertext = await encryptSealedBox(message, server.publicKey);
const plaintext = await decryptSealedBox(ciphertext, server);
console.log("sealed box plaintext:", toString(plaintext));
```

Ringkasan:
- Key exchange menghasilkan `tx/rx` yang cocok antara client dan server.
- Sealed box memungkinkan enkripsi ke public key penerima tanpa perlu keypair pengirim.
Risiko yang masih ada:
- Jika public key palsu (MITM), attacker bisa menerima ciphertext.
- Perlu mekanisme trust untuk verifikasi public key (fingerprint, signature, PKI).

## 3) Simulasi Asimetris (Signature)

Tujuan:
- Membuat keypair Ed25519
- Sign dan verify pesan

```ts
import {
  generateSigningKeyPair,
  signMessage,
  verifySignature,
  fromString,
} from "@nexwage/crypto";

const { publicKey, privateKey } = await generateSigningKeyPair();
const message = fromString("pesan penting");

const signature = await signMessage(message, privateKey);
const ok = await verifySignature(message, signature, publicKey);
const fail = await verifySignature(fromString("pesan lain"), signature, publicKey);

console.log("valid:", ok);
console.log("invalid:", fail);
```

Ringkasan:
- Signature memastikan **integritas** dan **keaslian** pesan.
- Public key cukup untuk verifikasi.
Risiko yang masih ada:
- Tanpa nonce/timestamp, pesan bisa di‑replay.

## 3b) Simulasi Signature Anti‑Replay (Nonce + Timestamp)

Tujuan:
- Menambahkan nonce/timestamp agar pesan tidak bisa di‑replay.

```ts
import {
  generateSigningKeyPair,
  signMessageWithNonce,
  verifySignedMessage,
  fromString,
} from "@nexwage/crypto";

const { publicKey, privateKey } = await generateSigningKeyPair();
const message = fromString("aksi penting");

const payload = await signMessageWithNonce(message, privateKey);
const ok = await verifySignedMessage(payload, publicKey);
console.log("valid:", ok);

// Anti‑replay: simpan payload.nonce di cache/DB dan tolak jika sudah pernah dipakai.
```

Catatan:
- Anti‑replay butuh storage nonce di server/client.
- Bisa juga gunakan `timestamp` untuk membatasi window validitas.
Risiko yang masih ada:
- Jika nonce tidak disimpan, replay tetap mungkin.
- Jika clock tidak sinkron, verifikasi timestamp bisa gagal.

## 4) Simulasi Group (MLS-like, tahap awal)

Tujuan:
- Membuat group dengan beberapa member
- Member membuka welcome payload
- Admin melakukan commit add member baru
- Member lain meng-apply commit dan mendapatkan group key baru

```ts
import {
  applyGroupCommit,
  createGroupCommit,
  createGroupState,
  deriveGroupKey,
  generateKeyExchangeKeyPair,
  generateSigningKeyPair,
  openGroupWelcome,
  encodeBase64,
} from "@nexwage/crypto";

const aliceEnc = await generateKeyExchangeKeyPair();
const bobEnc = await generateKeyExchangeKeyPair();
const aliceSign = await generateSigningKeyPair();

// 1) Admin (Alice) membuat group
const { state, welcome } = await createGroupState("group-1", [
  { id: "alice", encPublicKey: aliceEnc.publicKey, signPublicKey: aliceSign.publicKey },
  { id: "bob", encPublicKey: bobEnc.publicKey },
]);

// 2) Bob buka welcome
const bobState = await openGroupWelcome(welcome, "bob", bobEnc);
const bobGroupKey1 = await deriveGroupKey(bobState);
console.log("bob groupKey epoch 0:", encodeBase64(bobGroupKey1));

// 3) Admin menambah member baru (Carol)
const carolEnc = await generateKeyExchangeKeyPair();
const { commit } = await createGroupCommit(
  state,
  "alice",
  aliceSign.privateKey,
  "add",
  { add: [{ id: "carol", encPublicKey: carolEnc.publicKey }] }
);

// 4) Bob apply commit
const bobNextState = await applyGroupCommit(
  bobState,
  commit,
  "bob",
  bobEnc,
  aliceSign.publicKey
);
const bobGroupKey2 = await deriveGroupKey(bobNextState);
console.log("bob groupKey epoch 1:", encodeBase64(bobGroupKey2));
```

Ringkasan:
- Setiap commit menghasilkan **epoch baru** dan secret baru.
- Member hanya bisa melanjutkan jika menerima secret terenkripsi untuk dirinya.
Risiko yang masih ada:
- Distribusi secret masih O(n), perlu optimasi jika group sangat besar.
- Kompromi device member masih membuka akses ke group key.
