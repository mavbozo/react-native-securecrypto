package com.mavbozo.rnsecurecrypto.internal

import java.io.File
import com.mavbozo.androidsecurecrypto.Cipher as NativeCipher
import android.util.Base64


sealed interface CipherParams {
    val algorithm: String

    data class AesGcm(
        override val algorithm: String = "AES-GCM",
        val key: String
    ) : CipherParams

    companion object {
        fun fromReadableMap(params: com.facebook.react.bridge.ReadableMap): CipherParams {
            return when (val algorithm = params.getString("algorithm")) {
                "AES-GCM" -> AesGcm(
                    key = params.getString("key") 
                        ?: throw IllegalArgumentException("key is required")
                )
                null -> throw IllegalArgumentException("algorithm is required")
                else -> throw IllegalArgumentException("Unsupported algorithm: $algorithm")
            }
        }
    }
}

class Cipher {
    companion object {
        /**
         * Current supported cipher parameters. Constants defined here for future extensibility when
         * more options are supported.
         */
        private const val SUPPORTED_KEY_SIZE = 256
        private const val SUPPORTED_TAG_LENGTH = 128

        suspend fun encryptString(params: CipherParams, data: String): String {
            return when (params) {
                is CipherParams.AesGcm -> {
                    val keyBytes = Base64.decode(params.key, Base64.NO_WRAP)
                    NativeCipher.encryptString(keyBytes, data).getOrThrow()
                }
            }
        }

        suspend fun decryptString(params: CipherParams, data: String): String {
            return when (params) {
                is CipherParams.AesGcm -> {
                    val keyBytes = Base64.decode(params.key, Base64.NO_WRAP)
                    NativeCipher.decryptString(keyBytes, data).getOrThrow()
                }
            }
        }

        suspend fun encryptBytes(params: CipherParams, data: ByteArray): ByteArray {
            return when (params) {
                is CipherParams.AesGcm -> {
                    val keyBytes = Base64.decode(params.key, Base64.NO_WRAP)
                    NativeCipher.encryptBytes(keyBytes, data).getOrThrow()
                }
            }
        }

        suspend fun decryptBytes(params: CipherParams, data: ByteArray): ByteArray {
            return when (params) {
                is CipherParams.AesGcm -> {
                    val keyBytes = Base64.decode(params.key, Base64.NO_WRAP)
                    NativeCipher.decryptBytes(keyBytes, data).getOrThrow()
                }
            }
        }

        suspend fun encryptFile(params: CipherParams, sourceFile: File, destFile: File) {
            return when(params) {
                is CipherParams.AesGcm -> {
                    val keyBytes = Base64.decode(params.key, Base64.NO_WRAP)
                    NativeCipher.encryptFile(keyBytes, sourceFile, destFile).getOrThrow()
                }
            }
        }

        suspend fun decryptFile(params: CipherParams, sourceFile: File, destFile: File) {
            return when(params) {
                is CipherParams.AesGcm -> {
                    val keyBytes = Base64.decode(params.key, Base64.NO_WRAP)
                    NativeCipher.decryptFile(keyBytes, sourceFile, destFile).getOrThrow()
                }
            }
        }
    }
}
