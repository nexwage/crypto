import {
  aeadXChaCha20Poly1305IetfNpubBytes,
  aeadXChaCha20Poly1305IetfEncrypt,
  aeadXChaCha20Poly1305IetfDecrypt,
  cryptoPwhash,
  cryptoPwhashMemlimitModerate,
  cryptoPwhashOpslimitModerate,
  cryptoPwhashSaltBytes,
  base64VariantOriginal,
  decryptFileData,
  decryptSealedBox,
  deriveKeyFromPassword,
  deriveClientSessionKeys,
  deriveServerSessionKeys,
  encodeBase64,
  decodeBase64,
  encryptFileData,
  encryptSealedBox,
  generateFileKey,
  generateKeyExchangeKeyPair,
  generateMasterKeyWithPassword,
  generateRecoveryKey,
  generateSigningKeyPair,
  memcmp,
  fromBase64,
  fromString,
  randombytesBuf,
  signMessage,
  sodiumReady,
  sodium,
  toBase64,
  toString,
  unwrapFileKeyWithMasterKey,
  unwrapMasterKeyWithPassword,
  unwrapMasterKeyWithRecoveryKey,
  unwrapRecoveryKeyWithMasterKey,
  wrapFileKeyWithMasterKey,
  wrapMasterKeyWithRecoveryKey,
  wrapRecoveryKeyWithMasterKey,
  verifySignature,
} from "../src/index.js";

describe("crypto flows", () => {
  beforeAll(async () => {
    await sodiumReady();
  });

  test("base64 helpers round-trip", () => {
    const data = new Uint8Array([1, 2, 3, 4, 5, 255]);
    const encoded = encodeBase64(data);
    const decoded = decodeBase64(encoded);
    expect(memcmp(data, decoded)).toBe(true);
  });

  test("libsodium helper wrappers", () => {
    const data = new Uint8Array([9, 8, 7, 6]);
    const encoded = toBase64(data);
    const decoded = fromBase64(encoded);
    expect(memcmp(data, decoded)).toBe(true);

    const text = "halo";
    const bytes = fromString(text);
    const roundTrip = toString(bytes);
    expect(roundTrip).toBe(text);
    expect(base64VariantOriginal).toBe(sodium.base64_variants.ORIGINAL);
  });

  test("deriveKeyFromPassword is deterministic with same salt", async () => {
    const salt = randombytesBuf(cryptoPwhashSaltBytes);
    const first = await deriveKeyFromPassword("secret", { salt });
    const second = await deriveKeyFromPassword("secret", { salt });
    expect(memcmp(first.key, second.key)).toBe(true);
  });

  test("crypto_pwhash wrapper matches deriveKeyFromPassword output", async () => {
    const salt = randombytesBuf(cryptoPwhashSaltBytes);
    const { key } = await deriveKeyFromPassword("secret", {
      salt,
      opslimit: cryptoPwhashOpslimitModerate,
      memlimit: cryptoPwhashMemlimitModerate,
    });
    const raw = cryptoPwhash(
      32,
      "secret",
      salt,
      cryptoPwhashOpslimitModerate,
      cryptoPwhashMemlimitModerate,
      sodium.crypto_pwhash_ALG_DEFAULT
    );
    expect(memcmp(key, raw)).toBe(true);
  });

  test("deriveKeyFromPassword rejects invalid salt size", async () => {
    await expect(
      deriveKeyFromPassword("secret", { salt: new Uint8Array(1) })
    ).rejects.toThrow("salt harus");
  });

  test("password unwrap fails on wrong password", async () => {
    const { wrapped } = await generateMasterKeyWithPassword("pw-1");
    await expect(
      unwrapMasterKeyWithPassword("pw-2", wrapped)
    ).rejects.toThrow("Gagal membuka key");
  });

  test("file encryption round-trip", async () => {
    const fileKey = await generateFileKey();
    const aad = randombytesBuf(8);
    const plaintext = new TextEncoder().encode("file rahasia");
    const encrypted = await encryptFileData(fileKey, plaintext, aad);
    const decrypted = await decryptFileData(fileKey, encrypted, aad);
    expect(new TextDecoder().decode(decrypted)).toBe("file rahasia");
  });

  test("file encryption round-trip without AAD", async () => {
    const fileKey = await generateFileKey();
    const plaintext = new TextEncoder().encode("tanpa aad");
    const encrypted = await encryptFileData(fileKey, plaintext);
    const decrypted = await decryptFileData(fileKey, encrypted);
    expect(new TextDecoder().decode(decrypted)).toBe("tanpa aad");
  });

  test("AEAD wrapper round-trip", () => {
    const key = randombytesBuf(32);
    const nonce = randombytesBuf(aeadXChaCha20Poly1305IetfNpubBytes);
    const aad = randombytesBuf(6);
    const plaintext = new TextEncoder().encode("data");

    const ciphertext = aeadXChaCha20Poly1305IetfEncrypt(
      plaintext,
      aad,
      null,
      nonce,
      key
    );
    const decrypted = aeadXChaCha20Poly1305IetfDecrypt(
      null,
      ciphertext,
      aad,
      nonce,
      key
    );

    expect(new TextDecoder().decode(decrypted)).toBe("data");
  });

  test("key exchange session keys match", async () => {
    const clientKeyPair = await generateKeyExchangeKeyPair();
    const serverKeyPair = await generateKeyExchangeKeyPair();
    const client = await deriveClientSessionKeys(
      clientKeyPair,
      serverKeyPair.publicKey
    );
    const server = await deriveServerSessionKeys(
      serverKeyPair,
      clientKeyPair.publicKey
    );
    expect(memcmp(client.tx, server.rx)).toBe(true);
    expect(memcmp(client.rx, server.tx)).toBe(true);
  });

  test("sealed box round-trip", async () => {
    const recipient = await generateKeyExchangeKeyPair();
    const message = fromString("sealed");
    const ciphertext = await encryptSealedBox(message, recipient.publicKey);
    const plaintext = await decryptSealedBox(ciphertext, recipient);
    expect(toString(plaintext)).toBe("sealed");
  });

  test("signature sign/verify", async () => {
    const { publicKey, privateKey } = await generateSigningKeyPair();
    const message = fromString("pesan");
    const signature = await signMessage(message, privateKey);
    const ok = await verifySignature(message, signature, publicKey);
    expect(ok).toBe(true);
    const fail = await verifySignature(fromString("lain"), signature, publicKey);
    expect(fail).toBe(false);
  });

  test("file decryption fails on wrong AAD", async () => {
    const fileKey = await generateFileKey();
    const aad = randombytesBuf(8);
    const plaintext = new TextEncoder().encode("file rahasia");
    const encrypted = await encryptFileData(fileKey, plaintext, aad);
    await expect(
      decryptFileData(fileKey, encrypted, randombytesBuf(8))
    ).rejects.toThrow("Gagal membuka file");
  });

  test("master/recovery flow matches original master key", async () => {
    const password = "password-kuat";
    const aad = randombytesBuf(12);

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

    const unwrappedByPassword = await unwrapMasterKeyWithPassword(
      password,
      wrapped,
      aad
    );
    const unwrappedByRecovery = await unwrapMasterKeyWithRecoveryKey(
      recoveryKey,
      wrappedByRecovery,
      aad
    );

    expect(memcmp(masterKey, unwrappedByPassword)).toBe(true);
    expect(memcmp(masterKey, unwrappedByRecovery)).toBe(true);
  });

  test("recovery unwrap fails on wrong key", async () => {
    const aad = randombytesBuf(8);
    const recoveryKey = await generateRecoveryKey();
    const { masterKey } = await generateMasterKeyWithPassword("pw");
    const wrappedByRecovery = await wrapMasterKeyWithRecoveryKey(
      masterKey,
      recoveryKey,
      aad
    );
    await expect(
      unwrapMasterKeyWithRecoveryKey(randombytesBuf(32), wrappedByRecovery, aad)
    ).rejects.toThrow("Gagal membuka payload");
  });

  test("recovery key wrap/unwrap round-trip and failure", async () => {
    const aad = randombytesBuf(8);
    const recoveryKey = await generateRecoveryKey();
    const { masterKey } = await generateMasterKeyWithPassword("pw");
    const wrapped = await wrapRecoveryKeyWithMasterKey(
      recoveryKey,
      masterKey,
      aad
    );
    const unwrapped = await unwrapRecoveryKeyWithMasterKey(
      masterKey,
      wrapped,
      aad
    );
    expect(memcmp(recoveryKey, unwrapped)).toBe(true);
    await expect(
      unwrapRecoveryKeyWithMasterKey(randombytesBuf(32), wrapped, aad)
    ).rejects.toThrow("Gagal membuka payload");
  });

  test("recovery key wrap/unwrap without AAD", async () => {
    const recoveryKey = await generateRecoveryKey();
    const { masterKey } = await generateMasterKeyWithPassword("pw");
    const wrapped = await wrapRecoveryKeyWithMasterKey(recoveryKey, masterKey);
    const unwrapped = await unwrapRecoveryKeyWithMasterKey(masterKey, wrapped);
    expect(memcmp(recoveryKey, unwrapped)).toBe(true);
  });

  test("file key wrapping uses expected key size", async () => {
    const fileKey = await generateFileKey();
    const { masterKey } = await generateMasterKeyWithPassword("pw");
    const aad = randombytesBuf(4);

    const wrappedFileKey = await wrapFileKeyWithMasterKey(
      fileKey,
      masterKey,
      aad
    );
    const unwrappedFileKey = await unwrapFileKeyWithMasterKey(
      masterKey,
      wrappedFileKey,
      aad
    );

    expect(memcmp(fileKey, unwrappedFileKey)).toBe(true);
  });

  test("AEAD nonce size matches libsodium constant", () => {
    expect(aeadXChaCha20Poly1305IetfNpubBytes).toBe(24);
  });

  test("crypto helpers reject invalid key sizes", async () => {
    await expect(
      wrapFileKeyWithMasterKey(new Uint8Array(31), new Uint8Array(32))
    ).rejects.toThrow("fileKey harus");
  });
});
