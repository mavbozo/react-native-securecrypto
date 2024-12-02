import { Buffer } from 'buffer';
const Securecrypto = require('./NativeSecurecrypto').default;

// Just keep the type exports and constants
export const MAX_STRING_SIZE = 1024 * 1024; // 1MB
export const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

/**
 * Parameters for AES-GCM encryption/decryption.
 * Currently only supports AES-GCM with:
 * - 256-bit keys (32 bytes, base64 encoded)
 * - 12-byte randomly generated nonce/IV
 * - 16-byte (128-bit) authentication tag
 */
export interface AESGCMParams {
  /** Algorithm identifier, must be 'AES-GCM' */
  algorithm: 'AES-GCM';
  /**
   * Encryption/decryption key as base64 string.
   * Must be a 32-byte key (256 bits) encoded as base64.
   * The base64 string will be ~44 characters long.
   */
  key: string;
}

/**
 * Union type of supported cipher parameters.
 * Currently only supports AES-GCM parameters.
 */
export type CipherParams = AESGCMParams;

// Utility functions for converting between Uint8Array and base64
const toBase64 = (buffer: Uint8Array): string => {
  return Buffer.from(buffer).toString('base64');
};

const fromBase64 = (base64: string): Uint8Array => {
  const buffer = Buffer.from(base64, 'base64');
  return new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.length);
};

/**
 * Cryptographically secure random number generation functions
 *
 * for now, the size of the message is limited to 1 MB
 * and for file the maximum size is 10 MB
 */
export const random = {
  /**
   * Generates random bytes of specified length.
   * @param length - Number of random bytes to generate (1 to 1,048,576 bytes)
   * @returns Promise resolving to Uint8Array containing random bytes
   * @throws {Error} If length is invalid or random generation fails
   * - INVALID_SIZE: Length must be between 1 and 1MB
   * - RANDOM_GENERATION_ERROR: System random number generation failed
   */
  generateRandomBytes: (length: number): Promise<Uint8Array> => {
    return Securecrypto.generateRandomBytes(length);
  },

  /**
   * Generates random bytes and returns them as a hexadecimal string
   * @param length - Number of random bytes to generate (1 to 1,048,576 bytes)
   * @returns Promise resolving to hex string of random bytes
   * @throws {Error} If length is invalid or random generation fails
   * - INVALID_SIZE: Length must be between 1 and 1MB
   * - RANDOM_GENERATION_ERROR: System random number generation failed
   */
  generateRandomBytesAsHex: (length: number): Promise<string> => {
    return Securecrypto.generateRandomBytesAsHex(length);
  },

  /**
   * Generates random bytes and returns them as a base64 string
   * @param length - Number of random bytes to generate (1 to 1,048,576 bytes)
   * @returns Promise resolving to base64 string of random bytes
   * @throws {Error} If length is invalid or random generation fails
   * - INVALID_SIZE: Length must be between 1 and 1MB
   * - RANDOM_GENERATION_ERROR: System random number generation failed
   */
  generateRandomBytesAsBase64: (length: number): Promise<string> => {
    return Securecrypto.generateRandomBytesAsBase64(length);
  },
};

/**
 * Encryption and decryption operations using AES-GCM
 */
export const cipher = {
  /**
   * Encrypts a string using AES-GCM.
   * @param params - Encryption parameters
   * @param data - String to encrypt (max 1MB)
   * @returns Promise resolving to encrypted data as base64 string
   * @throws {Error}
   * - INVALID_SIZE: Input data exceeds 1MB limit
   * - INVALID_PARAMS: Invalid key or algorithm parameters
   * - ENCRYPTION_ERROR: Encryption operation failed
   */
  encryptString: async (
    params: CipherParams,
    data: string
  ): Promise<string> => {
    return Securecrypto.encryptString(params, data);
  },

  /**
   * Decrypts a previously encrypted string using AES-GCM.
   * @param params - Decryption parameters (must match encryption)
   * @param data - Encrypted data as base64 string
   * @returns Promise resolving to decrypted string
   * @throws {Error}
   * - INVALID_PARAMS: Invalid key or algorithm parameters
   * - DECRYPTION_ERROR: Decryption failed (wrong key or corrupted data)
   */
  decryptString: async (
    params: CipherParams,
    data: string
  ): Promise<string> => {
    return Securecrypto.decryptString(params, data);
  },

  /**
   * Encrypts binary data using AES-GCM.
   * @param params - Encryption parameters
   * @param data - Data to encrypt as Uint8Array (max 1MB)
   * @returns Promise resolving to encrypted data as Uint8Array
   * @throws {Error}
   * - INVALID_SIZE: Input data exceeds 1MB limit
   * - INVALID_PARAMS: Invalid key or algorithm parameters
   * - ENCRYPTION_ERROR: Encryption operation failed
   */
  encryptBytes: async (
    params: CipherParams,
    data: Uint8Array
  ): Promise<Uint8Array> => {
    const base64Data = toBase64(data);
    const encryptedBase64 = await Securecrypto.encryptBytes(params, base64Data);
    return fromBase64(encryptedBase64);
  },

  /**
   * Decrypts binary data using AES-GCM.
   * @param params - Decryption parameters (must match encryption)
   * @param data - Encrypted data as Uint8Array
   * @returns Promise resolving to decrypted data as Uint8Array
   * @throws {Error}
   * - INVALID_PARAMS: Invalid key or algorithm parameters
   * - DECRYPTION_ERROR: Decryption failed (wrong key or corrupted data)
   */
  decryptBytes: async (
    params: CipherParams,
    data: Uint8Array
  ): Promise<Uint8Array> => {
    const base64Data = toBase64(data);
    const decryptedBase64 = await Securecrypto.decryptBytes(params, base64Data);
    return fromBase64(decryptedBase64);
  },

  /**
   * Encrypts a file using AES-GCM.
   * @param params - Encryption parameters
   * @param sourcePath - Path to source file (max 10MB)
   * @param destPath - Path where encrypted file will be written
   * @returns Promise resolving to true if encryption succeeds
   * @throws {Error}
   * - FILE_NOT_FOUND: Source file does not exist
   * - INVALID_SIZE: Source file exceeds 10MB limit
   * - INVALID_PARAMS: Invalid key or algorithm parameters
   * - ENCRYPTION_ERROR: Encryption operation failed
   */
  encryptFile: async (
    params: CipherParams,
    sourcePath: string,
    destPath: string
  ): Promise<boolean> => {
    return Securecrypto.encryptFile(params, sourcePath, destPath);
  },

  /**
   * Decrypts a previously encrypted file using AES-GCM.
   * @param params - Decryption parameters (must match encryption)
   * @param sourcePath - Path to encrypted file
   * @param destPath - Path where decrypted file will be written
   * @returns Promise resolving to true if decryption succeeds
   * @throws {Error}
   * - FILE_NOT_FOUND: Source file does not exist
   * - INVALID_PARAMS: Invalid key or algorithm parameters
   * - DECRYPTION_ERROR: Decryption failed (wrong key or corrupted data)
   */
  decryptFile: async (
    params: CipherParams,
    sourcePath: string,
    destPath: string
  ): Promise<boolean> => {
    return Securecrypto.decryptFile(params, sourcePath, destPath);
  },
};

/**
 * Parameters for key derivation.
 * Uses HKDF (HMAC-based Key Derivation Function) to derive subkeys
 * from a master key with domain separation.
 */
export interface DeriveKeyParams {
  /**
   * Hash algorithm to use for HKDF.
   * @default 'SHA-256'
   */
  algorithm?: 'SHA-256' | 'SHA-512' | 'SHA-1';

  /**
   * Master key as base64 string.
   * For SHA-256: minimum 32 bytes (256 bits)
   * For SHA-512: minimum 64 bytes (512 bits)
   * For SHA-1: minimum 20 bytes (160 bits)
   */
  masterKey: string;

  /**
   * Domain separation string to ensure derived keys from same master key
   * are independent. Example: 'auth' or 'encryption'
   */
  domain: string;

  /**
   * Additional context string for key derivation.
   * Can be used to further separate keys within same domain.
   * Example: user ID or session ID
   */
  context: string;

  /**
   * Size of derived key in bytes.
   * - For SHA-256: Minimum and default 32 bytes (256 bits) for the derived key
   * - For SHA-512: Minimum and default 64 bytes (512 bits) for the derived key
   * - For SHA-1 (though not recommended for new applications): Minimum and default 20 bytes (160 bits) for the derived key
   * - Maximum size 64 bytes (512 bits) for any algorithms.
   */
  keySize?: number;
}

/**
 * Functions for deriving cryptographic keys
 */
export const keyDerivation = {
  /**
   * Derives a new key using HKDF from a master key with domain separation.
   * @param params - Key derivation parameters
   * @returns Promise resolving to derived key as base64 string
   * @throws {Error}
   * - INVALID_PARAMS: Invalid master key or parameters
   * - DERIVATION_ERROR: Key derivation failed
   *
   * @example
   * const derivedKey = await keyDerivation.deriveKey({
   *   masterKey: "base64MasterKey...",
   *   domain: "encryption",
   *   context: "user123",
   *   algorithm: "SHA-256", // optional
   *   keySize: 32 // optional
   * });
   */
  deriveKey: async (params: DeriveKeyParams): Promise<string> => {
    return Securecrypto.deriveKey(params);
  },
};
