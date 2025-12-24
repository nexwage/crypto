import sodium from "libsodium-wrappers-sumo";
import { assertByteLength } from "../utils/bytes.js";

export type KeyExchangeKeyPair = {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
};

export type SessionKeys = {
  rx: Uint8Array;
  tx: Uint8Array;
};

/**
 * Generate key pair untuk key exchange (X25519).
 *
 * @returns Public/private key pair.
 */
export async function generateKeyExchangeKeyPair(): Promise<KeyExchangeKeyPair> {
  await sodium.ready;
  const { publicKey, privateKey } = sodium.crypto_kx_keypair();
  return { publicKey, privateKey };
}

/**
 * Generate public key (X25519) dari private key untuk key exchange.
 *
 * @param privateKey - Private key X25519.
 * @returns Public key X25519.
 */
export async function deriveKeyExchangePublicKeyFromPrivateKey(
  privateKey: Uint8Array
): Promise<Uint8Array> {
  await sodium.ready;
  assertByteLength(
    "privateKey",
    privateKey,
    sodium.crypto_kx_SECRETKEYBYTES
  );
  return sodium.crypto_scalarmult_base(privateKey);
}

/**
 * Rekonstruksi keypair key exchange dari private key (public key akan diderivasi).
 *
 * @param privateKey - Private key X25519.
 * @returns Public/private key pair.
 */
export async function keyExchangeKeyPairFromPrivateKey(
  privateKey: Uint8Array
): Promise<KeyExchangeKeyPair> {
  const publicKey = await deriveKeyExchangePublicKeyFromPrivateKey(privateKey);
  return { publicKey, privateKey };
}

/**
 * Derivasi session keys untuk sisi client.
 *
 * @param clientKeyPair - Key pair client.
 * @param serverPublicKey - Public key server.
 * @returns Session keys { rx, tx }.
 */
export async function deriveClientSessionKeys(
  clientKeyPair: KeyExchangeKeyPair,
  serverPublicKey: Uint8Array
): Promise<SessionKeys> {
  await sodium.ready;
  assertByteLength(
    "clientPublicKey",
    clientKeyPair.publicKey,
    sodium.crypto_kx_PUBLICKEYBYTES
  );
  assertByteLength(
    "clientPrivateKey",
    clientKeyPair.privateKey,
    sodium.crypto_kx_SECRETKEYBYTES
  );
  assertByteLength(
    "serverPublicKey",
    serverPublicKey,
    sodium.crypto_kx_PUBLICKEYBYTES
  );
  const { sharedRx, sharedTx } = sodium.crypto_kx_client_session_keys(
    clientKeyPair.publicKey,
    clientKeyPair.privateKey,
    serverPublicKey
  );
  return { rx: sharedRx, tx: sharedTx };
}

/**
 * Derivasi session keys untuk sisi server.
 *
 * @param serverKeyPair - Key pair server.
 * @param clientPublicKey - Public key client.
 * @returns Session keys { rx, tx }.
 */
export async function deriveServerSessionKeys(
  serverKeyPair: KeyExchangeKeyPair,
  clientPublicKey: Uint8Array
): Promise<SessionKeys> {
  await sodium.ready;
  assertByteLength(
    "serverPublicKey",
    serverKeyPair.publicKey,
    sodium.crypto_kx_PUBLICKEYBYTES
  );
  assertByteLength(
    "serverPrivateKey",
    serverKeyPair.privateKey,
    sodium.crypto_kx_SECRETKEYBYTES
  );
  assertByteLength(
    "clientPublicKey",
    clientPublicKey,
    sodium.crypto_kx_PUBLICKEYBYTES
  );
  const { sharedRx, sharedTx } = sodium.crypto_kx_server_session_keys(
    serverKeyPair.publicKey,
    serverKeyPair.privateKey,
    clientPublicKey
  );
  return { rx: sharedRx, tx: sharedTx };
}

/**
 * Enkripsi sealed box ke penerima menggunakan public key (tanpa keypair pengirim).
 *
 * @param message - Plaintext.
 * @param recipientPublicKey - Public key penerima.
 * @returns Ciphertext.
 */
export async function encryptSealedBox(
  message: Uint8Array,
  recipientPublicKey: Uint8Array
): Promise<Uint8Array> {
  await sodium.ready;
  assertByteLength(
    "recipientPublicKey",
    recipientPublicKey,
    sodium.crypto_box_PUBLICKEYBYTES
  );
  return sodium.crypto_box_seal(message, recipientPublicKey);
}

/**
 * Dekripsi sealed box menggunakan keypair penerima.
 *
 * @param ciphertext - Ciphertext.
 * @param recipientKeyPair - Key pair penerima.
 * @returns Plaintext.
 */
export async function decryptSealedBox(
  ciphertext: Uint8Array,
  recipientKeyPair: KeyExchangeKeyPair
): Promise<Uint8Array> {
  await sodium.ready;
  assertByteLength(
    "recipientPublicKey",
    recipientKeyPair.publicKey,
    sodium.crypto_box_PUBLICKEYBYTES
  );
  assertByteLength(
    "recipientPrivateKey",
    recipientKeyPair.privateKey,
    sodium.crypto_box_SECRETKEYBYTES
  );
  return sodium.crypto_box_seal_open(
    ciphertext,
    recipientKeyPair.publicKey,
    recipientKeyPair.privateKey
  );
}
