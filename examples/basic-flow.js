import sodium from "libsodium-wrappers-sumo";
import { decodeBase64, decryptFileData, encodeBase64, encryptFileData, generateFileKey, generateMasterKeyWithPassword, generateRecoveryKey, unwrapFileKeyWithMasterKey, unwrapMasterKeyWithPassword, unwrapMasterKeyWithRecoveryKey, wrapFileKeyWithMasterKey, wrapMasterKeyWithRecoveryKey, wrapRecoveryKeyWithMasterKey, } from "../src/index.js";
const password = "password-kuat";
const newPassword = "password-baru";
(async () => {
    await sodium.ready;
    const aad = sodium.from_string("uid:user_123|app:v1|slot:password");
    // ===========================
    // Alur 1: Setup awal + upload
    // ===========================
    const { masterKey, wrapped: wrappedMasterKey } = await generateMasterKeyWithPassword(password, {}, aad);
    const recoveryKey = await generateRecoveryKey();
    const encRecoveryKey64 = encodeBase64(recoveryKey);
    const decRecoveryKeyBuffArray = decodeBase64(encRecoveryKey64);
    const encRecoveryKeyAfterDec64 = encodeBase64(recoveryKey);
    console.log("recovery ori", recoveryKey);
    console.log("recovery key b64", encRecoveryKey64);
    console.log("recovery key array buff", decRecoveryKeyBuffArray);
    console.log("recovery after dec key b64", encRecoveryKeyAfterDec64);
    console.log("test value", sodium.memcmp(recoveryKey, decRecoveryKeyBuffArray));
    const wrappedMasterKeyByRecovery = await wrapMasterKeyWithRecoveryKey(masterKey, recoveryKey, aad);
    const wrappedRecoveryKey = await wrapRecoveryKeyWithMasterKey(recoveryKey, masterKey, aad);
    const fileKey = await generateFileKey();
    const wrappedFileKey = await wrapFileKeyWithMasterKey(fileKey, masterKey, aad);
    const fileBytes = sodium.from_string("file rahasia");
    const encryptedFile = await encryptFileData(fileKey, fileBytes, aad);
    console.log("[alur1] masterKey:", masterKey);
    console.log("[alur1] wrappedMasterKey:", wrappedMasterKey);
    console.log("[alur1] wrappedMasterKeyByRecovery:", wrappedMasterKeyByRecovery);
    console.log("[alur1] wrappedRecoveryKey:", wrappedRecoveryKey);
    console.log("[alur1] wrappedFileKey:", wrappedFileKey);
    console.log("[alur1] encryptedFile:", encryptedFile);
    // ===========================
    // Alur 2: Buka file (login)
    // ===========================
    const masterKey2 = await unwrapMasterKeyWithPassword(password, wrappedMasterKey, aad);
    const fileKey2 = await unwrapFileKeyWithMasterKey(masterKey2, wrappedFileKey, aad);
    const fileBytes2 = await decryptFileData(fileKey2, encryptedFile, aad);
    console.log("[alur2] masterKey2:", masterKey2);
    console.log("[alur2] fileKey2:", fileKey2);
    console.log("[alur2] fileBytes2:", sodium.to_string(fileBytes2));
    // Manual test: masterKey dan file harus sama
    if (!sodium.memcmp(masterKey, masterKey2)) {
        throw new Error("[alur2] masterKey tidak sama");
    }
    if (!sodium.memcmp(fileBytes, fileBytes2)) {
        throw new Error("[alur2] fileBytes tidak sama");
    }
    // ===========================
    // Alur 3: Recovery + re-encrypt
    // ===========================
    const masterKey3 = await unwrapMasterKeyWithRecoveryKey(recoveryKey, wrappedMasterKeyByRecovery, aad);
    const wrappedMasterKeyNew = await generateMasterKeyWithPassword(newPassword, {}, aad);
    const wrappedMasterKeyByRecoveryNew = await wrapMasterKeyWithRecoveryKey(masterKey3, recoveryKey, aad);
    console.log("[alur3] masterKey3:", masterKey3);
    console.log("[alur3] wrappedMasterKeyNew:", wrappedMasterKeyNew);
    console.log("[alur3] wrappedMasterKeyByRecoveryNew:", wrappedMasterKeyByRecoveryNew);
    // Manual test: masterKey hasil recovery sama dengan masterKey asli
    if (!sodium.memcmp(masterKey, masterKey3)) {
        throw new Error("[alur3] masterKey hasil recovery tidak sama");
    }
    console.log("[done] semua alur OK");
})();
//# sourceMappingURL=basic-flow.js.map