export type { AeadEnvelopeV1, PasswordKdfParamsV1, PasswordWrappedKeyV1 } from "./types.js";

export {
  generateFileKey,
  wrapFileKeyWithMasterKey,
  unwrapFileKeyWithMasterKey,
  encryptFileData,
  decryptFileData,
} from "./crypto/file-encryption.js";

export {
  generateMasterKey,
  generateMasterKeyWithPassword,
  wrapMasterKeyWithPassword,
  unwrapMasterKeyWithPassword,
} from "./crypto/master-key.js";

export {
  generateRecoveryKey,
  wrapMasterKeyWithRecoveryKey,
  unwrapMasterKeyWithRecoveryKey,
  wrapRecoveryKeyWithMasterKey,
  unwrapRecoveryKeyWithMasterKey,
} from "./crypto/recovery-key.js";

export type { KeyExchangeKeyPair, SessionKeys } from "./crypto/key-exchange.js";
export {
  generateKeyExchangeKeyPair,
  deriveClientSessionKeys,
  deriveServerSessionKeys,
  encryptSealedBox,
  decryptSealedBox,
} from "./crypto/key-exchange.js";

export type { SigningKeyPair } from "./crypto/signature.js";
export {
  generateSigningKeyPair,
  signMessage,
  verifySignature,
} from "./crypto/signature.js";

export type { PasswordKdfOptions } from "./crypto/password-kdf.js";
export {
  deriveKeyFromPassword,
  wrapKeyWithPassword,
  unwrapKeyWithPassword,
} from "./crypto/password-kdf.js";

export { encodeBase64, decodeBase64 } from "./utils/encoding.js";

export {
  sodium,
  ready as sodiumReady,
  randombytesBuf,
  cryptoPwhash,
  cryptoPwhashSaltBytes,
  cryptoPwhashOpslimitModerate,
  cryptoPwhashMemlimitModerate,
  aeadXChaCha20Poly1305IetfEncrypt,
  aeadXChaCha20Poly1305IetfDecrypt,
  aeadXChaCha20Poly1305IetfNpubBytes,
  toBase64,
  fromBase64,
  base64VariantOriginal,
  fromString,
  toString,
  memcmp,
} from "./sodium.js";
