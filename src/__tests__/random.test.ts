import { random } from '../index';

// Mock the native module
jest.mock('../NativeSecurecrypto', () => ({
  default: {
    generateRandomBytes: jest.fn((length: number) => {
      if (length <= 0 || length > 1024 * 1024) {
        return Promise.reject(new Error('INVALID_SIZE'));
      }
      // Return mock Uint8Array of specified length
      return Promise.resolve(new Uint8Array(length).fill(0x42));
    }),
    generateRandomBytesAsHex: jest.fn((length: number) => {
      if (length <= 0 || length > 1024 * 1024) {
        return Promise.reject(new Error('INVALID_SIZE'));
      }
      // Return mock hex string
      return Promise.resolve('42'.repeat(length));
    }),
    generateRandomBytesAsBase64: jest.fn((length: number) => {
      if (length <= 0 || length > 1024 * 1024) {
        return Promise.reject(new Error('INVALID_SIZE'));
      }
      // Create a more realistic base64 string without internal padding
      const mockBytes = Buffer.from(new Uint8Array(length).fill(0x42));
      return Promise.resolve(mockBytes.toString('base64'));
    }),
  },
}));

describe('random', () => {
  beforeEach(() => {
    // Clear mock calls before each test
    jest.clearAllMocks();
  });

  describe('generateRandomBytes', () => {
    it('should call native module with correct length', async () => {
      const length = 32;
      const result = await random.generateRandomBytes(length);
      expect(
        require('../NativeSecurecrypto').default.generateRandomBytes
      ).toHaveBeenCalledWith(length);
      expect(result).toBeInstanceOf(Uint8Array);
      expect(result.length).toBe(length);
    });

    it('should throw error for zero length', async () => {
      await expect(random.generateRandomBytes(0)).rejects.toThrow(
        'INVALID_SIZE'
      );
      expect(
        require('../NativeSecurecrypto').default.generateRandomBytes
      ).toHaveBeenCalledWith(0);
    });

    it('should throw error for negative length', async () => {
      await expect(random.generateRandomBytes(-1)).rejects.toThrow(
        'INVALID_SIZE'
      );
      expect(
        require('../NativeSecurecrypto').default.generateRandomBytes
      ).toHaveBeenCalledWith(-1);
    });

    it('should throw error for length exceeding 1024 * 1024', async () => {
      await expect(random.generateRandomBytes(1024 * 1024 + 1)).rejects.toThrow(
        'INVALID_SIZE'
      );
      expect(
        require('../NativeSecurecrypto').default.generateRandomBytes
      ).toHaveBeenCalledWith(1024 * 1024 + 1);
    });
  });

  describe('generateRandomBytesAsHex', () => {
    it('should call native module with correct length', async () => {
      const byteLength = 32;
      const result = await random.generateRandomBytesAsHex(byteLength);
      expect(
        require('../NativeSecurecrypto').default.generateRandomBytesAsHex
      ).toHaveBeenCalledWith(byteLength);
      expect(typeof result).toBe('string');
      expect(result.length).toBe(byteLength * 2); // hex string is twice the length of bytes
    });

    it('should throw error for invalid lengths', async () => {
      await expect(random.generateRandomBytesAsHex(0)).rejects.toThrow(
        'INVALID_SIZE'
      );
      await expect(random.generateRandomBytesAsHex(-1)).rejects.toThrow(
        'INVALID_SIZE'
      );
      await expect(
        random.generateRandomBytesAsHex(1024 * 1024 + 1)
      ).rejects.toThrow('INVALID_SIZE');
    });
  });

  describe('generateRandomBytesAsBase64', () => {
    it('should call native module with correct length', async () => {
      const byteLength = 32;
      const result = await random.generateRandomBytesAsBase64(byteLength);
      expect(
        require('../NativeSecurecrypto').default.generateRandomBytesAsBase64
      ).toHaveBeenCalledWith(byteLength);
      expect(typeof result).toBe('string');
      // Verify it's a valid base64 string
      expect(/^[A-Za-z0-9+/]+={0,2}$/.test(result)).toBe(true);
    });

    it('should throw error for invalid lengths', async () => {
      await expect(random.generateRandomBytesAsBase64(0)).rejects.toThrow(
        'INVALID_SIZE'
      );
      await expect(random.generateRandomBytesAsBase64(-1)).rejects.toThrow(
        'INVALID_SIZE'
      );
      await expect(
        random.generateRandomBytesAsBase64(1024 * 1024 + 1)
      ).rejects.toThrow('INVALID_SIZE');
    });
  });

  describe('error handling', () => {
    it('should handle native module errors', async () => {
      const mockError = new Error('RANDOM_GENERATION_ERROR');
      require('../NativeSecurecrypto').default.generateRandomBytes.mockRejectedValueOnce(
        mockError
      );

      await expect(random.generateRandomBytes(32)).rejects.toThrow(
        'RANDOM_GENERATION_ERROR'
      );
    });
  });
});
