import {
  aeadXChaCha20Poly1305IetfNpubBytes,
  cryptoPwhash,
  cryptoPwhashMemlimitModerate,
  cryptoPwhashOpslimitModerate,
  cryptoPwhashSaltBytes,
  decryptFileData,
  deriveKeyFromPassword,
  encodeBase64,
  decodeBase64,
  encryptFileData,
  generateFileKey,
  generateMasterKeyWithPassword,
  generateRecoveryKey,
  memcmp,
  randombytesBuf,
  sodiumReady,
  sodium,
  unwrapFileKeyWithMasterKey,
  unwrapMasterKeyWithPassword,
  unwrapMasterKeyWithRecoveryKey,
  wrapFileKeyWithMasterKey,
  wrapMasterKeyWithRecoveryKey,
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

  test("deriveKeyFromPassword is deterministic with same salt", async () => {
    const salt = new Uint8Array(cryptoPwhashSaltBytes);
    const first = await deriveKeyFromPassword("secret", { salt });
    const second = await deriveKeyFromPassword("secret", { salt });
    expect(memcmp(first.key, second.key)).toBe(true);
  });

  test("crypto_pwhash wrapper matches deriveKeyFromPassword output", async () => {
    const salt = new Uint8Array(cryptoPwhashSaltBytes);
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

  test("file encryption round-trip", async () => {
    const fileKey = await generateFileKey();
    const aad = randombytesBuf(8);
    const plaintext = new TextEncoder().encode("file rahasia");
    const encrypted = await encryptFileData(fileKey, plaintext, aad);
    const decrypted = await decryptFileData(fileKey, encrypted, aad);
    expect(new TextDecoder().decode(decrypted)).toBe("file rahasia");
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
});
