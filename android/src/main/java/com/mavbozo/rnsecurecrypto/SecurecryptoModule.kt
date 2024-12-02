package com.mavbozo.rnsecurecrypto

import java.io.File
import android.util.Base64
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.WritableArray
import com.facebook.react.module.annotations.ReactModule
import com.mavbozo.rnsecurecrypto.internal.Cipher
import com.mavbozo.rnsecurecrypto.internal.CipherParams.Companion.fromReadableMap
import com.mavbozo.rnsecurecrypto.internal.Random
import com.mavbozo.rnsecurecrypto.internal.KeyDerivation
import com.mavbozo.rnsecurecrypto.internal.KeyDerivationParams.Companion.fromReadableMap as fromReadableMapKeyDerivation
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.launch

@ReactModule(name = SecurecryptoModule.NAME)
class SecurecryptoModule(reactContext: ReactApplicationContext) :
        NativeSecurecryptoSpec(reactContext) {

  private val job = SupervisorJob()

  // Create a coroutine scope for async operations
  private val scope = CoroutineScope(job + Dispatchers.Default)

  private val random = Random()

  private fun ByteArray.toWritableArray(): WritableArray {
    return Arguments.createArray().apply {
      // Convert signed bytes to unsigned
      this@toWritableArray.forEach { byte -> pushInt(byte.toInt() and 0xFF) }
    }
  }

  override fun getName(): String {
    return NAME
  }

  override fun generateRandomBytes(length: Double, promise: Promise) {
    if (length <= 0 || length > 1_048_576) {
      promise.reject(
              "INVALID_SIZE",
              IllegalArgumentException(
                      "Size must be positive and less than 1MB (1,048,576 bytes), got: $length"
              )
      )
      return
    }

    scope.launch(Dispatchers.IO) {
      try {
        val lengthInt = length.toInt()
        val bytes = random.generateRandomBytes(lengthInt)
        promise.resolve(bytes.toWritableArray())
      } catch (e: SecurityException) {
        promise.reject(
                "RANDOM_GENERATION_ERROR",
                "Failed to generate random bytes: ${e.message}",
                e
        )
      } catch (e: Exception) {
        promise.reject("UNEXPECTED_ERROR", "An unexpected error occurred: ${e.message}", e)
      }
    }
  }

  override fun generateRandomBytesAsHex(length: Double, promise: Promise) {
    if (length <= 0 || length > 1_048_576) {
      promise.reject(
              "INVALID_SIZE",
              IllegalArgumentException(
                      "Size must be positive and less than 1MB (1,048,576 bytes), got: $length"
              )
      )
      return
    }

    scope.launch(Dispatchers.IO) {
      try {
        val lengthInt = length.toInt()
        val hexString = random.generateRandomBytesAsHex(lengthInt)
        promise.resolve(hexString)
      } catch (e: SecurityException) {
        promise.reject(
                "RANDOM_GENERATION_ERROR",
                "Failed to generate random hex string: ${e.message}",
                e
        )
      } catch (e: Exception) {
        promise.reject("UNEXPECTED_ERROR", "An unexpected error occurred: ${e.message}", e)
      }
    }
  }

  override fun generateRandomBytesAsBase64(length: Double, promise: Promise) {
    if (length <= 0 || length > 1_048_576) {
      promise.reject(
              "INVALID_SIZE",
              IllegalArgumentException(
                      "Size must be positive and less than 1MB (1,048,576 bytes), got: $length"
              )
      )
      return
    }

    scope.launch(Dispatchers.IO) {
      try {
        val lengthInt = length.toInt()
        val base64String = random.generateRandomBytesAsBase64(lengthInt)
        promise.resolve(base64String)
      } catch (e: SecurityException) {
        promise.reject(
                "RANDOM_GENERATION_ERROR",
                "Failed to generate base64 string: ${e.message}",
                e
        )
      } catch (e: Exception) {
        promise.reject("UNEXPECTED_ERROR", "An unexpected error occurred: ${e.message}", e)
      }
    }
  }

  // for encryption/ keyderivation we use ReadbleMap
  // Android: ReadableMap is thread-safe, can be accessed from any thread

  override fun encryptString(params: ReadableMap, data: String, promise: Promise) {
    if (data.length <= 0 || data.length > 1_048_576) {
      promise.reject(
              "INVALID_SIZE",
              IllegalArgumentException(
                      "Size must be positive and less than 1MB (1,048,576 bytes), got: ${data.length}"
              )
      )
      return
    }

    scope.launch(Dispatchers.IO) {
      try {
        val encrypted = Cipher.encryptString(fromReadableMap(params), data)
        promise.resolve(encrypted)
      } catch (e: Exception) {
        when (e) {
          is IllegalArgumentException ->
                  promise.reject(
                          "INVALID_PARAMS",
                          "Check your params object, it might be missing required fields or have invalid values: ${e.message}"
                  )
          else -> promise.reject("ENCRYPTION_ERROR", "Failed to encrypt data: ${e.message}")
        }
      }
    }
  }

  override fun decryptString(params: ReadableMap, data: String, promise: Promise) {
    scope.launch(Dispatchers.IO) {
      try {
        val decrypted = Cipher.decryptString(fromReadableMap(params), data)
        promise.resolve(decrypted)
      } catch (e: Exception) {
        when (e) {
          is IllegalArgumentException ->
                  promise.reject(
                          "INVALID_PARAMS",
                          "Check your params object, it might be missing required fields or have invalid values: ${e.message}"
                  )
          else -> promise.reject("DECRYPTION_ERROR", "Failed to decrypt data: ${e.message}")
        }
      }
    }
  }

  // data is a base64 string,
  // return a base64 string
  // we use base64 encoding to avoid issues with codegen turbo module types conversion
  override fun encryptBytes(params: ReadableMap, data: String, promise: Promise) {
    scope.launch(Dispatchers.IO) {
      try {
        // Decode incoming base64 string to byte array
        val inputBytes = Base64.decode(data, Base64.DEFAULT)

        // Encrypt the bytes
        val encryptedBytes = Cipher.encryptBytes(fromReadableMap(params), inputBytes)

        // Encode the result back to base64
        val encryptedBase64 = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP)

        promise.resolve(encryptedBase64)
      } catch (e: IllegalArgumentException) {
        promise.reject("INVALID_PARAMS", "Invalid base64 input or params: ${e.message}")
      } catch (e: Exception) {
        promise.reject("ENCRYPTION_ERROR", "Failed to encrypt data: ${e.message}")
      }
    }
  }

  override fun decryptBytes(params: ReadableMap, data: String, promise: Promise) {
    scope.launch(Dispatchers.IO) {
      try {
        // Decode incoming base64 string to byte array
        val inputBytes = Base64.decode(data, Base64.DEFAULT)

        // Decrypt the bytes
        val decryptedBytes = Cipher.decryptBytes(fromReadableMap(params), inputBytes)

        // Encode the result back to base64
        val decryptedBase64 = Base64.encodeToString(decryptedBytes, Base64.NO_WRAP)

        promise.resolve(decryptedBase64)
      } catch (e: IllegalArgumentException) {
        promise.reject("INVALID_PARAMS", "Invalid base64 input or params: ${e.message}")
      } catch (e: Exception) {
        promise.reject("DECRYPTION_ERROR", "Failed to decrypt data: ${e.message}", e)
      }
    }
  }

  override fun encryptFile(params: ReadableMap, sourcePath: String, destPath: String, promise: Promise) {
    // Convert sourcePath and destPath to File objects
    val sourceFile = File(sourcePath)
    val destFile = File(destPath)
    
    // Check sourceFile exists
    if (!sourceFile.exists()) {
      promise.reject("FILE_NOT_FOUND", "Source file not found: $sourcePath")
      return
    }

    scope.launch(Dispatchers.IO) {
      try {
        Cipher.encryptFile(fromReadableMap(params), sourceFile, destFile)
        promise.resolve(true)
      } catch (e: Exception) {
        when (e) {
          is IllegalArgumentException ->
            promise.reject(
              "INVALID_PARAMS",
              "Check your params object, it might be missing required fields or have invalid values: ${e.message}"
            )
          else -> promise.reject("ENCRYPTION_ERROR", "Failed to encrypt file: ${e.message}", e)
        }
      }
    }
  }

  override fun decryptFile(params: ReadableMap, sourcePath: String, destPath: String, promise: Promise) {
    // Convert sourcePath and destPath to File objects
    val sourceFile = File(sourcePath)
    val destFile = File(destPath)
    
    // Check sourceFile exists
    if (!sourceFile.exists()) {
      promise.reject("FILE_NOT_FOUND", "Source file not found: $sourcePath")
      return
    }

    scope.launch(Dispatchers.IO) {
      try {
        Cipher.decryptFile(fromReadableMap(params), sourceFile, destFile)
        promise.resolve(true)
      } catch (e: Exception) {
        when (e) {
          is IllegalArgumentException ->
            promise.reject(
              "INVALID_PARAMS",
              "Check your params object, it might be missing required fields or have invalid values: ${e.message}"
            )
          else -> promise.reject("DECRYPTION_ERROR", "Failed to decrypt file: ${e.message}", e)
        }
      }
    }
  }

  override fun deriveKey(params: ReadableMap, promise: Promise) {
    scope.launch(Dispatchers.IO) {
      try {
        val derivedKey = KeyDerivation.deriveKey(fromReadableMapKeyDerivation(params))
        promise.resolve(derivedKey)
      } catch (e: Exception) {
        when (e) {
          is IllegalArgumentException -> promise.reject("INVALID_PARAMS", "Invalid params: ${e.message}")
          else -> promise.reject("DERIVATION_ERROR", "Failed to derive key: ${e.message}", e)
        }
      }
    }
  }

  companion object {
    const val NAME = "Securecrypto"
  }

  override fun onCatalystInstanceDestroy() {
    job.cancelChildren() // Cancel all child coroutines
    random.cleanup()
    super.invalidate()
  }
}
