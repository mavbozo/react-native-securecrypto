import { cipher } from '../index';

jest.mock('../NativeSecurecrypto', () => ({
  default: {
    encryptString: jest.fn((params, data) => {
      if (!params.key || params.algorithm !== 'AES-GCM') {
        return Promise.reject(new Error('INVALID_PARAMS'));
      }
      // Return mock encrypted string
      return Promise.resolve('encrypted_' + data);
    }),

    decryptString: jest.fn((params, data) => {
      if (!params.key || params.algorithm !== 'AES-GCM') {
        return Promise.reject(new Error('INVALID_PARAMS'));
      }
      if (!data.startsWith('encrypted_')) {
        return Promise.reject(new Error('DECRYPTION_ERROR'));
      }
      // Return mock decrypted string
      return Promise.resolve(data.substring(10));
    }),

    encryptBytes: jest.fn((params, base64Data) => {
      if (!params.key || params.algorithm !== 'AES-GCM') {
        return Promise.reject(new Error('INVALID_PARAMS'));
      }
      // Return mock encrypted base64 with prefix to identify it as encrypted
      return Promise.resolve(
        Buffer.from('encrypted_' + base64Data).toString('base64')
      );
    }),

    decryptBytes: jest.fn((params, base64Data) => {
      if (!params.key || params.algorithm !== 'AES-GCM') {
        return Promise.reject(new Error('INVALID_PARAMS'));
      }
      const decoded = Buffer.from(base64Data, 'base64').toString();
      if (!decoded.startsWith('encrypted_')) {
        return Promise.reject(new Error('DECRYPTION_ERROR'));
      }
      // Return mock decrypted base64
      return Promise.resolve(decoded.substring(10));
    }),

    encryptFile: jest.fn((params, sourcePath, _) => {
      if (!params.key || params.algorithm !== 'AES-GCM') {
        return Promise.reject(new Error('INVALID_PARAMS'));
      }
      if (!sourcePath) {
        return Promise.reject(new Error('FILE_NOT_FOUND'));
      }
      return Promise.resolve(true);
    }),

    decryptFile: jest.fn((params, sourcePath, _) => {
      if (!params.key || params.algorithm !== 'AES-GCM') {
        return Promise.reject(new Error('INVALID_PARAMS'));
      }
      if (!sourcePath) {
        return Promise.reject(new Error('FILE_NOT_FOUND'));
      }
      return Promise.resolve(true);
    }),
  },
}));

describe('cipher', () => {
  const validParams = {
    algorithm: 'AES-GCM' as const,
    key: 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY=', // 32 bytes base64
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('string encryption/decryption', () => {
    it('should encrypt string successfully', async () => {
      const data = 'Hello, World!';
      const result = await cipher.encryptString(validParams, data);
      expect(result).toBe('encrypted_Hello, World!');
      expect(
        require('../NativeSecurecrypto').default.encryptString
      ).toHaveBeenCalledWith(validParams, data);
    });

    it('should decrypt string successfully', async () => {
      const encryptedData = 'encrypted_Hello, World!';
      const result = await cipher.decryptString(validParams, encryptedData);
      expect(result).toBe('Hello, World!');
      expect(
        require('../NativeSecurecrypto').default.decryptString
      ).toHaveBeenCalledWith(validParams, encryptedData);
    });

    it('should reject invalid params', async () => {
      const invalidParams = {
        algorithm: 'invalid' as const,
        key: 'invalid',
      } as any;
      await expect(cipher.encryptString(invalidParams, 'test')).rejects.toThrow(
        'INVALID_PARAMS'
      );
      await expect(cipher.decryptString(invalidParams, 'test')).rejects.toThrow(
        'INVALID_PARAMS'
      );
    });

    it('should handle decryption errors', async () => {
      await expect(
        cipher.decryptString(validParams, 'invalid_data')
      ).rejects.toThrow('DECRYPTION_ERROR');
    });
  });

  describe('byte encryption/decryption', () => {
    it('should encrypt bytes successfully', async () => {
      const data = new Uint8Array([1, 2, 3, 4]);
      const result = await cipher.encryptBytes(validParams, data);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(
        require('../NativeSecurecrypto').default.encryptBytes
      ).toHaveBeenCalledWith(validParams, expect.any(String));
    });

    it('should decrypt bytes successfully', async () => {
      // First encrypt the data to get valid encrypted format
      const originalData = new Uint8Array([1, 2, 3, 4]);
      const encryptedData = await cipher.encryptBytes(
        validParams,
        originalData
      );

      // Then decrypt it
      const result = await cipher.decryptBytes(validParams, encryptedData);
      expect(result).toBeInstanceOf(Uint8Array);
    });

    it('should reject invalid params for bytes', async () => {
      const invalidParams = {
        algorithm: 'invalid' as const,
        key: 'invalid',
      } as any;
      const data = new Uint8Array([1, 2, 3, 4]);
      await expect(cipher.encryptBytes(invalidParams, data)).rejects.toThrow(
        'INVALID_PARAMS'
      );
      await expect(cipher.decryptBytes(invalidParams, data)).rejects.toThrow(
        'INVALID_PARAMS'
      );
    });
  });

  describe('file encryption/decryption', () => {
    it('should encrypt file successfully', async () => {
      const result = await cipher.encryptFile(
        validParams,
        'source.txt',
        'dest.enc'
      );
      expect(result).toBe(true);
      expect(
        require('../NativeSecurecrypto').default.encryptFile
      ).toHaveBeenCalledWith(validParams, 'source.txt', 'dest.enc');
    });

    it('should decrypt file successfully', async () => {
      const result = await cipher.decryptFile(
        validParams,
        'source.enc',
        'dest.txt'
      );
      expect(result).toBe(true);
      expect(
        require('../NativeSecurecrypto').default.decryptFile
      ).toHaveBeenCalledWith(validParams, 'source.enc', 'dest.txt');
    });

    it('should handle file not found', async () => {
      await expect(
        cipher.encryptFile(validParams, '', 'dest.enc')
      ).rejects.toThrow('FILE_NOT_FOUND');
      await expect(
        cipher.decryptFile(validParams, '', 'dest.txt')
      ).rejects.toThrow('FILE_NOT_FOUND');
    });

    it('should reject invalid params for files', async () => {
      const invalidParams = {
        algorithm: 'invalid' as const,
        key: 'invalid',
      } as any;
      await expect(
        cipher.encryptFile(invalidParams, 'source.txt', 'dest.enc')
      ).rejects.toThrow('INVALID_PARAMS');
      await expect(
        cipher.decryptFile(invalidParams, 'source.enc', 'dest.txt')
      ).rejects.toThrow('INVALID_PARAMS');
    });
  });
});
