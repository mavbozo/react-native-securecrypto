import { keyDerivation } from '../index';

// Mock the entire NativeSecurecrypto module
jest.mock('../NativeSecurecrypto', () => ({
  __esModule: true,
  default: {
    deriveKey: jest.fn(),
  },
}));

// Get the mocked module
const mockNativeModule = jest.requireMock('../NativeSecurecrypto').default;

describe('keyDerivation', () => {
  beforeEach(() => {
    // Clear mock state before each test
    jest.clearAllMocks();
  });

  it('should derive key with default parameters', async () => {
    // Arrange
    const mockDerivedKey = 'derivedKeyBase64...';
    mockNativeModule.deriveKey.mockResolvedValue(mockDerivedKey);

    const params = {
      masterKey: 'masterKeyBase64...',
      domain: 'encryption',
      context: 'user123',
    };

    // Act
    const result = await keyDerivation.deriveKey(params);

    // Assert
    expect(result).toBe(mockDerivedKey);
    expect(mockNativeModule.deriveKey).toHaveBeenCalledWith(params);
  });

  it('should derive key with SHA-512 algorithm', async () => {
    // Arrange
    const mockDerivedKey = 'derivedKeyBase64...';
    mockNativeModule.deriveKey.mockResolvedValue(mockDerivedKey);

    const params = {
      masterKey: 'masterKeyBase64...',
      domain: 'authentication',
      context: 'session456',
      algorithm: 'SHA-512' as const,
      keySize: 64,
    };

    // Act
    const result = await keyDerivation.deriveKey(params);

    // Assert
    expect(result).toBe(mockDerivedKey);
    expect(mockNativeModule.deriveKey).toHaveBeenCalledWith(params);
  });

  it('should handle INVALID_PARAMS error', async () => {
    // Arrange
    mockNativeModule.deriveKey.mockRejectedValue(new Error('INVALID_PARAMS'));

    const params = {
      masterKey: 'invalidKey',
      domain: 'encryption',
      context: 'user123',
    };

    // Act & Assert
    await expect(keyDerivation.deriveKey(params)).rejects.toThrow(
      'INVALID_PARAMS'
    );
  });

  it('should handle DERIVATION_ERROR', async () => {
    // Arrange
    mockNativeModule.deriveKey.mockRejectedValue(new Error('DERIVATION_ERROR'));

    const params = {
      masterKey: 'masterKeyBase64...',
      domain: 'encryption',
      context: 'user123',
    };

    // Act & Assert
    await expect(keyDerivation.deriveKey(params)).rejects.toThrow(
      'DERIVATION_ERROR'
    );
  });

  it('should derive key with custom key size', async () => {
    // Arrange
    const mockDerivedKey = 'derivedKeyBase64...';
    mockNativeModule.deriveKey.mockResolvedValue(mockDerivedKey);

    const params = {
      masterKey: 'masterKeyBase64...',
      domain: 'encryption',
      context: 'user123',
      keySize: 16, // 128-bit key
    };

    // Act
    const result = await keyDerivation.deriveKey(params);

    // Assert
    expect(result).toBe(mockDerivedKey);
    expect(mockNativeModule.deriveKey).toHaveBeenCalledWith(params);
  });

  it('should handle all hash algorithms', async () => {
    const algorithms = ['SHA-256', 'SHA-512', 'SHA-1'] as const;
    const mockDerivedKey = 'derivedKeyBase64...';

    for (const algorithm of algorithms) {
      mockNativeModule.deriveKey.mockResolvedValue(mockDerivedKey);

      // Arrange
      const params = {
        masterKey: 'masterKeyBase64...',
        domain: 'encryption',
        context: 'user123',
        algorithm,
      };

      // Act
      const result = await keyDerivation.deriveKey(params);

      // Assert
      expect(result).toBe(mockDerivedKey);
      expect(mockNativeModule.deriveKey).toHaveBeenCalledWith(params);
    }
  });
});
