import {
  encodeBase64,
  fromString,
  generateSigningKeyPair,
  signMessage,
  sodiumReady,
  verifySignature,
} from "../src/index.js";

(async () => {
  await sodiumReady();

  console.log("[sign] generate keypair");
  const { publicKey, privateKey } = await generateSigningKeyPair();
  console.log("[sign] public key (b64):", encodeBase64(publicKey));
  console.log("[sign] private key bytes:", privateKey.length);

  const message = fromString("pesan yang ditandatangani");
  console.log("[sign] message bytes:", message.length);

  console.log("[sign] create signature");
  const signature = await signMessage(message, privateKey);
  console.log("[sign] signature (b64):", encodeBase64(signature));
  console.log("[sign] signature bytes:", signature.length);

  console.log("[sign] verify signature (valid)");
  const ok = await verifySignature(message, signature, publicKey);
  console.log("[sign] result:", ok);

  console.log("[sign] verify signature (invalid)");
  const bad = await verifySignature(
    fromString("pesan lain"),
    signature,
    publicKey
  );
  console.log("[sign] result:", bad);
})();
