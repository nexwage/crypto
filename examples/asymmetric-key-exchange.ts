import {
  decodeBase64,
  decryptSealedBox,
  deriveClientSessionKeys,
  deriveServerSessionKeys,
  encodeBase64,
  encryptSealedBox,
  fromString,
  generateKeyExchangeKeyPair,
  sodiumReady,
  toString,
} from "../src/index.js";

(async () => {
  await sodiumReady();

  console.log("[kx] generate keypairs");
  const clientKeyPair = await generateKeyExchangeKeyPair();
  const serverKeyPair = await generateKeyExchangeKeyPair();

  console.log("[kx] client public key (b64):", encodeBase64(clientKeyPair.publicKey));
  console.log("[kx] server public key (b64):", encodeBase64(serverKeyPair.publicKey));

  console.log("[kx] derive session keys");
  const clientSession = await deriveClientSessionKeys(
    clientKeyPair,
    serverKeyPair.publicKey
  );
  const serverSession = await deriveServerSessionKeys(
    serverKeyPair,
    clientKeyPair.publicKey
  );

  console.log("[kx] client tx (b64):", encodeBase64(clientSession.tx));
  console.log("[kx] client rx (b64):", encodeBase64(clientSession.rx));
  console.log("[kx] server tx (b64):", encodeBase64(serverSession.tx));
  console.log("[kx] server rx (b64):", encodeBase64(serverSession.rx));

  console.log("[kx] shared tx/rx matches (base64 compare):");
  console.log(
    "[kx] client tx == server rx:",
    encodeBase64(clientSession.tx) === encodeBase64(serverSession.rx)
  );
  console.log(
    "[kx] client rx == server tx:",
    encodeBase64(clientSession.rx) === encodeBase64(serverSession.tx)
  );

  console.log("[sealed] encrypt to server public key");
  const message = fromString("hello sealed box");
  const ciphertext = await encryptSealedBox(message, serverKeyPair.publicKey);
  const ciphertextB64 = encodeBase64(ciphertext);
  console.log("[sealed] ciphertext (b64):", ciphertextB64);
  console.log("[sealed] ciphertext bytes:", ciphertext.length);

  console.log("[sealed] decrypt with server keypair");
  const ciphertextDecoded = decodeBase64(ciphertextB64);
  const plaintext = await decryptSealedBox(ciphertextDecoded, serverKeyPair);
  console.log("[sealed] plaintext:", toString(plaintext));
})();
