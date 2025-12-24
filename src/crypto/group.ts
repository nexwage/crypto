import sodium from "libsodium-wrappers-sumo";
import { assertByteLength } from "../utils/bytes.js";
import { decodeBase64, encodeBase64 } from "../utils/encoding.js";

export type GroupMember = {
  id: string;
  encPublicKey: Uint8Array;
  signPublicKey?: Uint8Array;
};

export type GroupMemberWire = {
  id: string;
  encPublicKey: string;
  signPublicKey?: string;
};

export type GroupState = {
  groupId: string;
  epoch: number;
  members: GroupMember[];
  secret: Uint8Array;
};

export type GroupWelcome = {
  groupId: string;
  epoch: number;
  members: GroupMemberWire[];
  encryptedSecrets: Record<string, string>;
};

export type GroupCommitAction = "add" | "remove" | "rotate";

export type GroupCommit = {
  groupId: string;
  epoch: number;
  senderId: string;
  action: GroupCommitAction;
  members: GroupMemberWire[];
  removedMemberIds?: string[];
  encryptedSecrets: Record<string, string>;
  signature: string;
};

type KeyPair = { publicKey: Uint8Array; privateKey: Uint8Array };

function sortMembers<T extends { id: string }>(members: T[]): T[] {
  return [...members].sort((a, b) => a.id.localeCompare(b.id));
}

function toWireMember(member: GroupMember): GroupMemberWire {
  const base = {
    id: member.id,
    encPublicKey: encodeBase64(member.encPublicKey),
  };
  return member.signPublicKey
    ? { ...base, signPublicKey: encodeBase64(member.signPublicKey) }
    : base;
}

function toStateMember(member: GroupMemberWire): GroupMember {
  const base = {
    id: member.id,
    encPublicKey: decodeBase64(member.encPublicKey),
  };
  return member.signPublicKey
    ? { ...base, signPublicKey: decodeBase64(member.signPublicKey) }
    : base;
}

function canonicalizeCommitForSigning(commit: Omit<GroupCommit, "signature">) {
  const members = sortMembers(commit.members);
  const encryptedSecrets = Object.keys(commit.encryptedSecrets)
    .sort()
    .reduce<Record<string, string>>((acc, key) => {
      const value = commit.encryptedSecrets[key];
      if (value) {
        acc[key] = value;
      }
      return acc;
    }, {});
  return JSON.stringify({
    groupId: commit.groupId,
    epoch: commit.epoch,
    senderId: commit.senderId,
    action: commit.action,
    members,
    removedMemberIds: commit.removedMemberIds ?? [],
    encryptedSecrets,
  });
}

async function encryptSecretForMember(
  secret: Uint8Array,
  member: GroupMember
): Promise<string> {
  await sodium.ready;
  assertByteLength(
    "encPublicKey",
    member.encPublicKey,
    sodium.crypto_box_PUBLICKEYBYTES
  );
  const ciphertext = sodium.crypto_box_seal(secret, member.encPublicKey);
  return encodeBase64(ciphertext);
}

async function decryptSecretForMember(
  ciphertextB64: string,
  keyPair: KeyPair
): Promise<Uint8Array> {
  await sodium.ready;
  assertByteLength(
    "encPublicKey",
    keyPair.publicKey,
    sodium.crypto_box_PUBLICKEYBYTES
  );
  assertByteLength(
    "encPrivateKey",
    keyPair.privateKey,
    sodium.crypto_box_SECRETKEYBYTES
  );
  const ciphertext = decodeBase64(ciphertextB64);
  return sodium.crypto_box_seal_open(
    ciphertext,
    keyPair.publicKey,
    keyPair.privateKey
  );
}

/**
 * Buat group baru dengan secret awal.
 *
 * @param groupId - ID group.
 * @param members - Daftar member awal.
 * @returns State group dan welcome payload.
 */
export async function createGroupState(
  groupId: string,
  members: GroupMember[]
): Promise<{ state: GroupState; welcome: GroupWelcome }> {
  await sodium.ready;
  const secret = sodium.randombytes_buf(32);
  const sortedMembers = sortMembers(members);
  const encryptedSecrets: Record<string, string> = {};

  for (const member of sortedMembers) {
    encryptedSecrets[member.id] = await encryptSecretForMember(secret, member);
  }

  return {
    state: {
      groupId,
      epoch: 0,
      members: sortedMembers,
      secret,
    },
    welcome: {
      groupId,
      epoch: 0,
      members: sortedMembers.map(toWireMember),
      encryptedSecrets,
    },
  };
}

/**
 * Buka welcome payload untuk memperoleh state group.
 *
 * @param welcome - Welcome payload.
 * @param recipientId - ID member penerima.
 * @param recipientKeyPair - Keypair enkripsi penerima.
 * @returns State group.
 */
export async function openGroupWelcome(
  welcome: GroupWelcome,
  recipientId: string,
  recipientKeyPair: KeyPair
): Promise<GroupState> {
  const ciphertextB64 = welcome.encryptedSecrets[recipientId];
  if (!ciphertextB64) {
    throw new Error("Welcome tidak berisi secret untuk member ini");
  }
  const secret = await decryptSecretForMember(ciphertextB64, recipientKeyPair);
  return {
    groupId: welcome.groupId,
    epoch: welcome.epoch,
    members: welcome.members.map(toStateMember),
    secret,
  };
}

/**
 * Derivasi group key dari secret + epoch.
 *
 * @param state - State group.
 * @returns Group key 32-byte.
 */
export async function deriveGroupKey(state: GroupState): Promise<Uint8Array> {
  await sodium.ready;
  const epochBytes = new Uint8Array(4);
  const view = new DataView(epochBytes.buffer);
  view.setUint32(0, state.epoch, false);
  const context = new TextEncoder().encode("group-key");
  const input = new Uint8Array(
    context.length + epochBytes.length + state.secret.length
  );
  input.set(context, 0);
  input.set(epochBytes, context.length);
  input.set(state.secret, context.length + epochBytes.length);
  return sodium.crypto_generichash(32, input);
}

/**
 * Buat commit untuk add/remove/rotate member.
 *
 * @param state - State group saat ini.
 * @param senderId - ID pengirim commit.
 * @param senderSignPrivateKey - Private key Ed25519 pengirim.
 * @param action - Jenis aksi commit.
 * @param memberUpdates - Member yang ditambah/dihapus.
 * @returns Commit + state baru.
 */
export async function createGroupCommit(
  state: GroupState,
  senderId: string,
  senderSignPrivateKey: Uint8Array,
  action: GroupCommitAction,
  memberUpdates?: {
    add?: GroupMember[];
    removeIds?: string[];
  }
): Promise<{ commit: GroupCommit; state: GroupState }> {
  await sodium.ready;
  assertByteLength(
    "senderSignPrivateKey",
    senderSignPrivateKey,
    sodium.crypto_sign_SECRETKEYBYTES
  );

  const removeIds = new Set(memberUpdates?.removeIds ?? []);
  const members =
    action === "add"
      ? sortMembers([...(state.members ?? []), ...(memberUpdates?.add ?? [])])
      : action === "remove"
      ? sortMembers(state.members.filter((m) => !removeIds.has(m.id)))
      : sortMembers(state.members);

  const secret = sodium.randombytes_buf(32);
  const encryptedSecrets: Record<string, string> = {};

  for (const member of members) {
    encryptedSecrets[member.id] = await encryptSecretForMember(secret, member);
  }

  const basePayload = {
    groupId: state.groupId,
    epoch: state.epoch + 1,
    senderId,
    action,
    members: members.map(toWireMember),
    encryptedSecrets,
  };
  const payload: Omit<GroupCommit, "signature"> =
    action === "remove"
      ? {
          ...basePayload,
          removedMemberIds: Array.from(removeIds.values()),
        }
      : basePayload;

  const toSign = canonicalizeCommitForSigning(payload);
  const signature = sodium.crypto_sign_detached(
    new TextEncoder().encode(toSign),
    senderSignPrivateKey
  );

  return {
    commit: {
      ...payload,
      signature: encodeBase64(signature),
    },
    state: {
      groupId: state.groupId,
      epoch: state.epoch + 1,
      members,
      secret,
    },
  };
}

/**
 * Verifikasi signature commit.
 *
 * @param commit - Commit payload.
 * @param senderSignPublicKey - Public key Ed25519 pengirim.
 * @returns True jika valid.
 */
export async function verifyGroupCommitSignature(
  commit: GroupCommit,
  senderSignPublicKey: Uint8Array
): Promise<boolean> {
  await sodium.ready;
  assertByteLength(
    "senderSignPublicKey",
    senderSignPublicKey,
    sodium.crypto_sign_PUBLICKEYBYTES
  );
  const { signature, ...payload } = commit;
  const toVerify = canonicalizeCommitForSigning(payload);
  return sodium.crypto_sign_verify_detached(
    decodeBase64(signature),
    new TextEncoder().encode(toVerify),
    senderSignPublicKey
  );
}

/**
 * Apply commit ke state lokal.
 *
 * @param state - State saat ini.
 * @param commit - Commit terbaru.
 * @param recipientId - ID member penerima.
 * @param recipientKeyPair - Keypair enkripsi penerima.
 * @param senderSignPublicKey - Public key Ed25519 pengirim.
 * @returns State baru.
 */
export async function applyGroupCommit(
  state: GroupState,
  commit: GroupCommit,
  recipientId: string,
  recipientKeyPair: KeyPair,
  senderSignPublicKey: Uint8Array
): Promise<GroupState> {
  if (commit.groupId !== state.groupId) {
    throw new Error("groupId commit tidak cocok");
  }
  if (commit.epoch !== state.epoch + 1) {
    throw new Error("epoch commit tidak valid");
  }
  const ok = await verifyGroupCommitSignature(commit, senderSignPublicKey);
  if (!ok) {
    throw new Error("signature commit tidak valid");
  }
  const ciphertextB64 = commit.encryptedSecrets[recipientId];
  if (!ciphertextB64) {
    throw new Error("commit tidak berisi secret untuk member ini");
  }
  const secret = await decryptSecretForMember(ciphertextB64, recipientKeyPair);
  return {
    groupId: commit.groupId,
    epoch: commit.epoch,
    members: commit.members.map(toStateMember),
    secret,
  };
}
