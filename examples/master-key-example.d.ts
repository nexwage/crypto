/**
 * Contoh penggunaan generateMasterKeyWithPassword dengan AAD dan opsi KDF.
 *
 * @returns Objek berisi masterKey dan payload wrapped.
 *
 * @example
 * const result = await exampleGenerateMasterKeyWithPassword();
 * console.log(result.wrapped);
 */
export declare function exampleGenerateMasterKeyWithPassword(): Promise<{
    masterKey: Uint8Array<ArrayBufferLike>;
    wrapped: import("../src/types.js").PasswordWrappedKeyV1;
}>;
//# sourceMappingURL=master-key-example.d.ts.map