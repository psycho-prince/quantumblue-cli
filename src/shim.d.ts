declare module '@noble/hashes/hkdf.js' { // Updated to .js
    export function hkdf(
        hash: any, // Use any for hash function type for simplicity in shim
        ikm: Uint8Array,
        salt?: Uint8Array,
        info?: Uint8Array,
        length?: number
    ): Uint8Array;
}

declare module '@noble/hashes/sha2.js' { // Updated to sha2.js
    // This assumes a simple structure; adjust if more specific methods are needed.
    // Given the previous error context, the sha512 object itself is likely the issue.
    // This shim provides a minimal declaration to let TypeScript pass.
    export const sha512: any; // Using 'any' for simplicity to allow compilation
}

declare module '@noble/ciphers/aes.js' { // Updated to .js
    export function gcm(key: Uint8Array, iv: Uint8Array): {
        encrypt(data: Uint8Array, aad?: Uint8Array): Promise<Uint8Array>; // Returns combined ciphertext + tag
        decrypt(ciphertextWithTag: Uint8Array, aad?: Uint8Array): Promise<Uint8Array>; // Takes combined ciphertext + tag
    };
}
