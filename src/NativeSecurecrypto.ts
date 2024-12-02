import type { TurboModule } from 'react-native';
import { TurboModuleRegistry } from 'react-native';

interface CipherParams {
  algorithm: string; // AES-GCM currently supported
  key: string; // base64 string, 32 bytes (256 bits)
}

/**
 * Parameters for key derivation.
 * For SHA-256: Minimum master key is 32 bytes (256 bits)
 * For SHA-512: Minimum master key is 64 bytes (512 bits)
 * For SHA-1: Minimum master key is 20 bytes (160 bits)
 *
 * Size of derived key in bytes.
 * - For SHA-256: Minimum and default 32 bytes (256 bits) for the derived key
 * - For SHA-512: Minimum and default 64 bytes (512 bits) for the derived key
 * - For SHA-1 (though not recommended for new applications): Minimum and default 20 bytes (160 bits) for the derived key
 * - Maximum size 64 bytes (512 bits) for any algorithms.
 */
interface DeriveKeyParams {
  algorithm?: string; // SHA-256 | SHA-512 | SHA-1
  masterKey: string; // base64 string
  domain: string;
  context: string;
  keySize?: number;
}

export interface Spec extends TurboModule {
  // Random module methods
  generateRandomBytes(length: number): Promise<Uint8Array>;
  generateRandomBytesAsHex(length: number): Promise<string>;
  generateRandomBytesAsBase64(length: number): Promise<string>;

  // Cipher module methods
  encryptString(params: CipherParams, data: string): Promise<string>;
  decryptString(params: CipherParams, data: string): Promise<string>;
  encryptBytes(params: CipherParams, data: string): Promise<string>; // data and result are in base64
  decryptBytes(params: CipherParams, data: string): Promise<string>; // data and result are in base64

  // sourcePath and destPath are paths to files on the device. Both are string to ensure smooth type conversion to native.
  encryptFile(
    params: CipherParams,
    sourcePath: string,
    destPath: string
  ): Promise<boolean>;
  decryptFile(
    params: CipherParams,
    sourcePath: string,
    destPath: string
  ): Promise<boolean>;

  deriveKey(params: DeriveKeyParams): Promise<string>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('Securecrypto');
