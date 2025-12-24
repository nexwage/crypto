import {
  applyGroupCommit,
  createGroupCommit,
  createGroupState,
  deriveGroupKey,
  generateKeyExchangeKeyPair,
  generateSigningKeyPair,
  openGroupWelcome,
  sodiumReady,
  encodeBase64,
} from "../src/index.js";

(async () => {
  await sodiumReady();

  console.log("[group] create members");
  const aliceEnc = await generateKeyExchangeKeyPair();
  const bobEnc = await generateKeyExchangeKeyPair();
  const aliceSign = await generateSigningKeyPair();

  console.log("[group] create group state");
  const { state, welcome } = await createGroupState("group-1", [
    { id: "alice", encPublicKey: aliceEnc.publicKey, signPublicKey: aliceSign.publicKey },
    { id: "bob", encPublicKey: bobEnc.publicKey },
  ]);

  console.log("[group] welcome epoch:", welcome.epoch);
  console.log("[group] members:", welcome.members.map((m) => m.id).join(", "));

  console.log("[group] bob open welcome");
  const bobState = await openGroupWelcome(welcome, "bob", bobEnc);
  const bobGroupKey1 = await deriveGroupKey(bobState);
  console.log("[group] bob groupKey epoch 0 (b64):", encodeBase64(bobGroupKey1));

  console.log("[group] add carol with commit");
  const carolEnc = await generateKeyExchangeKeyPair();
  const { commit } = await createGroupCommit(
    state,
    "alice",
    aliceSign.privateKey,
    "add",
    { add: [{ id: "carol", encPublicKey: carolEnc.publicKey }] }
  );

  console.log("[group] commit epoch:", commit.epoch);
  console.log("[group] commit action:", commit.action);
  console.log("[group] commit members:", commit.members.map((m) => m.id).join(", "));

  console.log("[group] bob apply commit");
  const bobNextState = await applyGroupCommit(
    bobState,
    commit,
    "bob",
    bobEnc,
    aliceSign.publicKey
  );
  const bobGroupKey2 = await deriveGroupKey(bobNextState);
  console.log("[group] bob groupKey epoch 1 (b64):", encodeBase64(bobGroupKey2));
})();
