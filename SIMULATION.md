# Simulasi Kripto (Simetris & Asimetris)

Dokumen ini berisi simulasi ringkas alur simetris dan asimetris menggunakan API dari `@nexwage/crypto`.

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
