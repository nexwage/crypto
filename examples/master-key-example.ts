import sodium from "libsodium-wrappers-sumo";
import { generateMasterKeyWithPassword } from "../src/index.js";

/**
 * Contoh penggunaan generateMasterKeyWithPassword dengan AAD dan opsi KDF.
 *
 * @returns Objek berisi masterKey dan payload wrapped.
 *
 * @example
 * const result = await exampleGenerateMasterKeyWithPassword();
 * console.log(result.wrapped);
 */
export async function exampleGenerateMasterKeyWithPassword() {
  await sodium.ready;

  const password = "example-password";

  // AAD = data tambahan yang ikut dikunci integritasnya (tidak dienkripsi).
  // Isi bebas, contoh: binding ke userId + appVersion.
  const aad = sodium.from_string("uid:user_123|app:v1");

  // opslimit & memlimit = tingkat kesulitan KDF (Argon2).
  // Lebih tinggi = lebih aman tapi lebih lambat/boros memori.
  const { masterKey, wrapped } = await generateMasterKeyWithPassword(
    password,
    {
      opslimit: sodium.crypto_pwhash_OPSLIMIT_MODERATE,
      memlimit: sodium.crypto_pwhash_MEMLIMIT_MODERATE,
    },
    aad
  );

  return { masterKey, wrapped };
}
