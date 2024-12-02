#import "Securecrypto.h"
#import <MbSecureCrypto/MbSecureCrypto.h>

@implementation Securecrypto
RCT_EXPORT_MODULE()

// Don't compile this code when we build for the old architecture.
#ifdef RCT_NEW_ARCH_ENABLED

- (void)rejectWithError:(NSError *)error reject:(RCTPromiseRejectBlock)reject {
  NSString *errorCode;

  if ([error.domain isEqualToString:MBSErrorDomain]) {
    switch (error.code) {
    // Existing random generation errors
    case MBSRandomErrorInvalidByteCount:
      errorCode = @"INVALID_SIZE";
      break;
    case MBSRandomErrorGenerationFailed:
    case MBSRandomErrorBufferAllocation:
      errorCode = @"RANDOM_GENERATION_ERROR";
      break;

    // Input validation errors
    case MBSCipherErrorInvalidKey:
    case MBSCipherErrorInvalidIV:
    case MBSCipherErrorInvalidInput:
    case MBSCipherErrorUnsupportedAlgorithm:
    case MBSCipherErrorUnsupportedFormat:
    case MBSCipherErrorFormatDetectionFailed:
    case MBSCipherErrorFormatMismatch:
      errorCode = @"INVALID_PARAMS";
      break;

    // Operation errors
    case MBSCipherErrorEncryptionFailed:
      errorCode = @"ENCRYPTION_ERROR";
      break;
    case MBSCipherErrorDecryptionFailed:
    case MBSCipherErrorAuthenticationFailed:
      errorCode = @"DECRYPTION_ERROR";
      break;
    case MBSCipherErrorKeyDerivationFailed:
      errorCode = @"DERIVATION_ERROR";
      break;

    // File operation errors
    case MBSCipherErrorIOFailure:
    case MBSCipherErrorFilePermission:
      errorCode = @"FILE_NOT_FOUND";
      break;
    case MBSCipherErrorFileTooLarge:
      errorCode = @"INVALID_SIZE";
      break;

    default:
      errorCode = @"UNEXPECTED_ERROR";
    }
  } else {
    errorCode = @"UNEXPECTED_ERROR";
  }

  reject(errorCode, error.localizedDescription, error);
}

- (void)rejectWithUnknownError:(RCTPromiseRejectBlock)reject {
  reject(@"UNKNOWN_ERROR",
         @"Failed to generate random bytes with no error details", nil);
}

- (void)generateRandomBytes:(double)length
                    resolve:(RCTPromiseResolveBlock)resolve
                     reject:(RCTPromiseRejectBlock)reject {
  dispatch_async(
      dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError *error = nil;
        NSInteger lengthInt = (NSInteger)length;

        NSData *randomData = [MBSRandom generateBytes:lengthInt error:&error];

        dispatch_async(dispatch_get_main_queue(), ^{
          if (error) {
            [self rejectWithError:error reject:reject];
          } else if (randomData) {
            NSMutableArray *byteArray =
                [NSMutableArray arrayWithCapacity:randomData.length];
            const uint8_t *bytes = (const uint8_t *)randomData.bytes;
            for (NSInteger i = 0; i < randomData.length; i++) {
              [byteArray addObject:@(bytes[i])];
            }
            resolve(byteArray);
          } else {
            [self rejectWithUnknownError:reject];
          }
        });
      });
}

- (void)generateRandomBytesAsHex:(double)length
                         resolve:(RCTPromiseResolveBlock)resolve
                          reject:(RCTPromiseRejectBlock)reject {
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0),
                 ^{
                   NSError *error = nil;
                   NSInteger lengthInt = (NSInteger)length;

                   NSString *hexString = [MBSRandom generateBytesAsHex:lengthInt
                                                                 error:&error];

                   dispatch_async(dispatch_get_main_queue(), ^{
                     if (error) {
                       [self rejectWithError:error reject:reject];
                     } else if (hexString) {
                       resolve(hexString);
                     } else {
                       [self rejectWithUnknownError:reject];
                     }
                   });
                 });
}

- (void)generateRandomBytesAsBase64:(double)length
                            resolve:(RCTPromiseResolveBlock)resolve
                             reject:(RCTPromiseRejectBlock)reject {
  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0),
                 ^{
                   NSError *error = nil;
                   NSInteger lengthInt = (NSInteger)length;

                   NSString *base64String =
                       [MBSRandom generateBytesAsBase64:lengthInt error:&error];

                   dispatch_async(dispatch_get_main_queue(), ^{
                     if (error) {
                       [self rejectWithError:error reject:reject];
                     } else if (base64String) {
                       resolve(base64String);
                     } else {
                       [self rejectWithUnknownError:reject];
                     }
                   });
                 });
}

// for encryption, we use TurboModule CipherParams
// iOS: TurboModule parameters must be accessed on main thread only

- (void)encryptString:(JS::NativeSecurecrypto::CipherParams &)params
                 data:(NSString *)data
              resolve:(RCTPromiseResolveBlock)resolve
               reject:(RCTPromiseRejectBlock)reject {

  // Check data size first
  if (data.length <= 0 || data.length > 1048576) {
    reject(@"INVALID_SIZE",
           @"Size must be positive and less than 1MB (1,048,576 bytes)", nil);
    return;
  }

  // Extract all parameters on main thread
  NSString *algorithm = params.algorithm();
  NSString *keyString = params.key();
  // Make a copy of data
  NSString *dataCopy = [data copy];

  if (![algorithm isEqualToString:@"AES-GCM"]) {
    reject(@"INVALID_PARAMS", @"Only AES-GCM algorithm is supported", nil);
    return;
  }

  NSData *keyData = [[NSData alloc] initWithBase64EncodedString:keyString
                                                        options:0];
  if (!keyData) {
    reject(@"INVALID_PARAMS", @"Invalid base64 key", nil);
    return;
  }

  if (keyData.length != 32) {
    reject(@"INVALID_PARAMS", @"AES-GCM key must be 32 bytes (256 bits)", nil);
    return;
  }

  dispatch_async(
      dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError *error = nil;

        // Encrypt using MBSCipher
        NSString *encrypted = [MBSCipher encryptString:dataCopy
                                         withAlgorithm:MBSCipherAlgorithmAESGCM
                                            withFormat:@(MBSCipherFormatV1)
                                               withKey:keyData
                                                 error:&error];

        dispatch_async(dispatch_get_main_queue(), ^{
          if (error) {
            [self rejectWithError:error reject:reject];
          } else if (encrypted) {
            resolve(encrypted);
          } else {
            reject(@"ENCRYPTION_ERROR",
                   @"Failed to encrypt with no error details", nil);
          }
        });
      });
}

- (void)decryptString:(JS::NativeSecurecrypto::CipherParams &)params
                 data:(NSString *)data
              resolve:(RCTPromiseResolveBlock)resolve
               reject:(RCTPromiseRejectBlock)reject {

  // Extract all parameters on main thread
  NSString *algorithm = params.algorithm();
  NSString *keyString = params.key();
  // Make a copy of data
  NSString *dataCopy = [data copy];

  if (![algorithm isEqualToString:@"AES-GCM"]) {
    reject(@"INVALID_PARAMS", @"Only AES-GCM algorithm is supported", nil);
    return;
  }

  NSData *keyData = [[NSData alloc] initWithBase64EncodedString:keyString
                                                        options:0];
  if (!keyData) {
    reject(@"INVALID_PARAMS", @"Invalid base64 key", nil);
    return;
  }

  if (keyData.length != 32) {
    reject(@"INVALID_PARAMS", @"AES-GCM key must be 32 bytes (256 bits)", nil);
    return;
  }

  dispatch_async(
      dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError *error = nil;

        // Decrypt using MBSCipher
        NSString *decrypted = [MBSCipher decryptString:dataCopy
                                         withAlgorithm:MBSCipherAlgorithmAESGCM
                                            withFormat:@(MBSCipherFormatV1)
                                               withKey:keyData
                                                 error:&error];

        dispatch_async(dispatch_get_main_queue(), ^{
          if (error) {
            [self rejectWithError:error reject:reject];
          } else {
            resolve(decrypted);
          }
        });
      });
}

- (void)encryptBytes:(JS::NativeSecurecrypto::CipherParams &)params
                data:(NSString *)base64Data
             resolve:(RCTPromiseResolveBlock)resolve
              reject:(RCTPromiseRejectBlock)reject {

  // Extract params on main thread
  NSString *algorithm = params.algorithm();
  NSString *keyString = params.key();
  NSString *base64DataCopy = [base64Data copy];

  // Validate algorithm
  if (![algorithm isEqualToString:@"AES-GCM"]) {
    reject(@"INVALID_PARAMS", @"Only AES-GCM algorithm is supported", nil);
    return;
  }

  // Convert and validate key
  NSData *keyData = [[NSData alloc] initWithBase64EncodedString:keyString
                                                        options:0];
  if (!keyData) {
    reject(@"INVALID_PARAMS", @"Invalid base64 key", nil);
    return;
  }

  if (keyData.length != 32) {
    reject(@"INVALID_PARAMS", @"AES-GCM key must be 32 bytes (256 bits)", nil);
    return;
  }

  dispatch_async(
      dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError *error = nil;

        // Decode input base64
        NSData *inputData =
            [[NSData alloc] initWithBase64EncodedString:base64DataCopy
                                                options:0];
        if (!inputData) {
          dispatch_async(dispatch_get_main_queue(), ^{
            reject(@"INVALID_PARAMS", @"Invalid base64 input data", nil);
          });
          return;
        }

        // Check size limit
        if (inputData.length > 1048576) { // 1MB limit
          dispatch_async(dispatch_get_main_queue(), ^{
            reject(@"INVALID_SIZE", @"Input data exceeds 1MB limit", nil);
          });
          return;
        }

        // Encrypt the data
        NSData *encryptedData = [MBSCipher encryptData:inputData
                                         withAlgorithm:MBSCipherAlgorithmAESGCM
                                            withFormat:@(MBSCipherFormatV1)
                                               withKey:keyData
                                                 error:&error];

        dispatch_async(dispatch_get_main_queue(), ^{
          if (error) {
            [self rejectWithError:error reject:reject];
          } else if (encryptedData) {
            // Convert result back to base64
            NSString *encryptedBase64 =
                [encryptedData base64EncodedStringWithOptions:0];
            resolve(encryptedBase64);
          } else {
            reject(@"ENCRYPTION_ERROR",
                   @"Failed to encrypt data with no error details", nil);
          }
        });
      });
}

- (void)decryptBytes:(JS::NativeSecurecrypto::CipherParams &)params
                data:(NSString *)base64Data
             resolve:(RCTPromiseResolveBlock)resolve
              reject:(RCTPromiseRejectBlock)reject {

  // Extract params on main thread
  NSString *algorithm = params.algorithm();
  NSString *keyString = params.key();
  NSString *base64DataCopy = [base64Data copy];

  // Validate algorithm
  if (![algorithm isEqualToString:@"AES-GCM"]) {
    reject(@"INVALID_PARAMS", @"Only AES-GCM algorithm is supported", nil);
    return;
  }

  // Convert and validate key
  NSData *keyData = [[NSData alloc] initWithBase64EncodedString:keyString
                                                        options:0];
  if (!keyData) {
    reject(@"INVALID_PARAMS", @"Invalid base64 key", nil);
    return;
  }

  dispatch_async(
      dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError *error = nil;

        // Decode input base64
        NSData *inputData =
            [[NSData alloc] initWithBase64EncodedString:base64DataCopy
                                                options:0];
        if (!inputData) {
          dispatch_async(dispatch_get_main_queue(), ^{
            reject(@"INVALID_PARAMS", @"Invalid base64 input data", nil);
          });
          return;
        }

        // Decrypt the data
        NSData *decryptedData = [MBSCipher decryptData:inputData
                                         withAlgorithm:MBSCipherAlgorithmAESGCM
                                            withFormat:@(MBSCipherFormatV1)
                                               withKey:keyData
                                                 error:&error];

        dispatch_async(dispatch_get_main_queue(), ^{
          if (error) {
            [self rejectWithError:error reject:reject];
          } else if (decryptedData) {
            // Convert result back to base64
            NSString *decryptedBase64 =
                [decryptedData base64EncodedStringWithOptions:0];
            resolve(decryptedBase64);
          } else {
            reject(@"DECRYPTION_ERROR",
                   @"Failed to decrypt data with no error details", nil);
          }
        });
      });
}


- (void)encryptFile:(JS::NativeSecurecrypto::CipherParams &)params
         sourcePath:(NSString *)sourcePath
          destPath:(NSString *)destPath
           resolve:(RCTPromiseResolveBlock)resolve
            reject:(RCTPromiseRejectBlock)reject {
    // Extract params on main thread
    NSString *algorithm = params.algorithm();
    NSString *keyString = params.key();
    NSString *sourcePathCopy = [sourcePath copy];
    NSString *destPathCopy = [destPath copy];
    
    // Validate algorithm
    if (![algorithm isEqualToString:@"AES-GCM"]) {
        reject(@"INVALID_PARAMS", @"Only AES-GCM algorithm is supported", nil);
        return;
    }
    
    // Convert and validate key
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:keyString options:0];
    if (!keyData) {
        reject(@"INVALID_PARAMS", @"Invalid base64 key", nil);
        return;
    }
    
    if (keyData.length != 32) {
        reject(@"INVALID_PARAMS", @"AES-GCM key must be 32 bytes (256 bits)", nil);
        return;
    }
    
    // Create URLs from paths
    NSURL *sourceURL = [NSURL fileURLWithPath:sourcePathCopy];
    NSURL *destURL = [NSURL fileURLWithPath:destPathCopy];
    
    // Check if source file exists
    if (![[NSFileManager defaultManager] fileExistsAtPath:sourcePathCopy]) {
        reject(@"FILE_NOT_FOUND", @"Source file not found", nil);
        return;
    }
    
    // Check file size (10MB limit)
    NSError *attributesError = nil;
    NSDictionary *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:sourcePathCopy error:&attributesError];
    if (attributesError) {
        reject(@"FILE_NOT_FOUND", @"Could not access source file", attributesError);
        return;
    }
    
    unsigned long long fileSize = [attributes fileSize];
    if (fileSize > 10 * 1024 * 1024) { // 10MB
        reject(@"INVALID_SIZE", @"Source file exceeds 10MB limit", nil);
        return;
    }
    
    // Dispatch to background queue for encryption
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError *error = nil;
        
        BOOL success = [MBSCipher encryptFile:sourceURL
                                   toOutput:destURL
                              withAlgorithm:MBSCipherAlgorithmAESGCM
                                 withFormat:@(MBSCipherFormatV1)
                                    withKey:keyData
                                      error:&error];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error) {
                [self rejectWithError:error reject:reject];
            } else if (success) {
                resolve(@YES);
            } else {
                reject(@"ENCRYPTION_ERROR", @"Failed to encrypt file with no error details", nil);
            }
        });
    });
}

- (void)decryptFile:(JS::NativeSecurecrypto::CipherParams &)params
         sourcePath:(NSString *)sourcePath
          destPath:(NSString *)destPath
           resolve:(RCTPromiseResolveBlock)resolve
            reject:(RCTPromiseRejectBlock)reject {
    // Extract params on main thread
    NSString *algorithm = params.algorithm();
    NSString *keyString = params.key();
    NSString *sourcePathCopy = [sourcePath copy];
    NSString *destPathCopy = [destPath copy];
    
    // Validate algorithm
    if (![algorithm isEqualToString:@"AES-GCM"]) {
        reject(@"INVALID_PARAMS", @"Only AES-GCM algorithm is supported", nil);
        return;
    }
    
    // Convert and validate key
    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:keyString options:0];
    if (!keyData) {
        reject(@"INVALID_PARAMS", @"Invalid base64 key", nil);
        return;
    }
    
    if (keyData.length != 32) {
        reject(@"INVALID_PARAMS", @"AES-GCM key must be 32 bytes (256 bits)", nil);
        return;
    }
    
    // Create URLs from paths
    NSURL *sourceURL = [NSURL fileURLWithPath:sourcePathCopy];
    NSURL *destURL = [NSURL fileURLWithPath:destPathCopy];
    
    // Check if source file exists
    if (![[NSFileManager defaultManager] fileExistsAtPath:sourcePathCopy]) {
        reject(@"FILE_NOT_FOUND", @"Source file not found", nil);
        return;
    }
    
    // Dispatch to background queue for decryption
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError *error = nil;
        
        BOOL success = [MBSCipher decryptFile:sourceURL
                                   toOutput:destURL
                              withAlgorithm:MBSCipherAlgorithmAESGCM
                                 withFormat:@(MBSCipherFormatV1)
                                    withKey:keyData
                                      error:&error];
        
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error) {
                [self rejectWithError:error reject:reject];
            } else if (success) {
                resolve(@YES);
            } else {
                reject(@"DECRYPTION_ERROR", @"Failed to decrypt file with no error details", nil);
            }
        });
    });
}


- (void)deriveKey:(JS::NativeSecurecrypto::DeriveKeyParams &)params
          resolve:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject {
    // Extract all parameters on main thread
    NSString *algorithm = params.algorithm();
    NSString *masterKeyBase64 = params.masterKey();
    NSString *domain = params.domain();
    NSString *context = params.context();
    std::optional<double> keySizeOpt = params.keySize();
    
    // Validate required parameters
    if (!masterKeyBase64 || !domain || !context) {
        reject(@"INVALID_PARAMS", @"Missing required parameters. masterKey, domain, and context are required.", nil);
        return;
    }
    
    // Convert base64 master key to NSData
    NSData *masterKey = [[NSData alloc] initWithBase64EncodedString:masterKeyBase64 options:0];
    if (!masterKey) {
        reject(@"INVALID_PARAMS", @"Invalid base64 master key. Please provide a valid base64 encoded string.", nil);
        return;
    }
    
    // Determine HKDF algorithm and validate master key length
    MBSHkdfAlgorithm hkdfAlgorithm;
    NSInteger minKeySize;
    NSInteger defaultKeySize;
    NSString *algorithmName;
    
    if (!algorithm || [algorithm isEqualToString:@"SHA-256"]) {
        hkdfAlgorithm = MBSHkdfAlgorithmSHA256;
        minKeySize = 32; // 256 bits
        defaultKeySize = 32;
        algorithmName = @"SHA-256";
    } else if ([algorithm isEqualToString:@"SHA-512"]) {
        hkdfAlgorithm = MBSHkdfAlgorithmSHA512;
        minKeySize = 64; // 512 bits
        defaultKeySize = 64;
        algorithmName = @"SHA-512";
    } else if ([algorithm isEqualToString:@"SHA-1"]) {
        hkdfAlgorithm = MBSHkdfAlgorithmSHA1;
        minKeySize = 20; // 160 bits
        defaultKeySize = 20;
        algorithmName = @"SHA-1";
    } else {
        reject(@"INVALID_PARAMS", 
               @"Unsupported hash algorithm. Supported algorithms are: SHA-256 (default), SHA-512, and SHA-1.", 
               nil);
        return;
    }
    
    // Validate master key length
    if (masterKey.length < minKeySize) {
        NSString *errorMsg = [NSString stringWithFormat:
            @"Master key must be at least %ld bytes (%ld bits) for %@. Provided key is %ld bytes (%ld bits).", 
            (long)minKeySize, (long)minKeySize * 8, 
            algorithmName, (long)masterKey.length, (long)masterKey.length * 8];
        reject(@"INVALID_PARAMS", errorMsg, nil);
        return;
    }
    
    // Get and validate key size
    NSInteger keySize = keySizeOpt.has_value() ? (NSInteger)keySizeOpt.value() : defaultKeySize;
    
    // Validate minimum key size
    if (keySize < minKeySize) {
        NSString *errorMsg = [NSString stringWithFormat:
            @"Derived key size must be at least %ld bytes (%ld bits) for %@. Requested size was %ld bytes.", 
            (long)minKeySize, (long)minKeySize * 8, 
            algorithmName, (long)keySize];
        reject(@"INVALID_PARAMS", errorMsg, nil);
        return;
    }
    
    // Validate maximum key size (512 bits = 64 bytes)
    static const NSInteger maxKeySize = 64;
    if (keySize > maxKeySize) {
        NSString *errorMsg = [NSString stringWithFormat:
            @"Derived key size must not exceed %ld bytes (%ld bits). Requested size was %ld bytes.", 
            (long)maxKeySize, (long)maxKeySize * 8, (long)keySize];
        reject(@"INVALID_PARAMS", errorMsg, nil);
        return;
    }
    
    // Validate domain and context length
    static const NSInteger maxStringLength = 1024; // 1KB limit for domain and context
    if (domain.length > maxStringLength || context.length > maxStringLength) {
        reject(@"INVALID_PARAMS", 
               @"Domain and context strings must not exceed 1024 characters.", 
               nil);
        return;
    }
    
    // Make copies for background thread
    NSData *masterKeyCopy = [masterKey copy];
    NSString *domainCopy = [domain copy];
    NSString *contextCopy = [context copy];
    
    // Dispatch to background queue
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSError *error = nil;
        
        NSData *derivedKey = [MBSKeyDerivation deriveKey:masterKeyCopy
                                                 domain:domainCopy
                                                context:contextCopy
                                                keySize:keySize
                                              algorithm:hkdfAlgorithm
                                                 error:&error];
        
        // Dispatch back to main queue
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error) {
                [self rejectWithError:error reject:reject];
            } else if (derivedKey) {
                // Convert derived key to base64
                NSString *derivedKeyBase64 = [derivedKey base64EncodedStringWithOptions:0];
                resolve(derivedKeyBase64);
            } else {
                reject(@"DERIVATION_ERROR", 
                       @"Failed to derive key. The operation completed but produced no key data.", 
                       nil);
            }
        });
    });
}

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params {
  return std::make_shared<facebook::react::NativeSecurecryptoSpecJSI>(params);
}
#endif

@end
