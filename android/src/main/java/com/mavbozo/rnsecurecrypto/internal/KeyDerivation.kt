package com.mavbozo.rnsecurecrypto.internal

import com.mavbozo.androidsecurecrypto.KeyDerivation as NativeKeyDerivation
import com.mavbozo.androidsecurecrypto.HkdfAlgorithm
import android.util.Base64
import com.facebook.react.bridge.ReadableMap

sealed interface KeyDerivationParams {
    val algorithm: HkdfAlgorithm?
    val masterKey: ByteArray
    val domain: String
    val context: String
    val keySize: Int?

    companion object {
        private const val MAX_STRING_LENGTH = 1024 // 1KB limit for domain and context

        fun fromReadableMap(params: ReadableMap): KeyDerivationParams {
            // Parse and validate algorithm
            val algorithmStr = params.getString("algorithm")
            val algorithm = when (algorithmStr) {
                null -> null
                "SHA-256" -> HkdfAlgorithm.SHA256
                "SHA-512" -> HkdfAlgorithm.SHA512
                "SHA-1" -> HkdfAlgorithm.SHA1
                else -> throw IllegalArgumentException(
                    "Unsupported algorithm: $algorithmStr. Supported algorithms are: SHA-256 (default), SHA-512, and SHA-1."
                )
            }

            // Validate and decode master key
            val masterKeyStr = params.getString("masterKey") 
                ?: throw IllegalArgumentException("masterKey is required")
            
            val masterKey = try {
                Base64.decode(masterKeyStr, Base64.NO_WRAP)
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException("Invalid base64 master key. Please provide a valid base64 encoded string.")
            }

            // Validate master key length based on algorithm
            val minMasterKeySize = when (algorithm ?: HkdfAlgorithm.SHA256) {
                HkdfAlgorithm.SHA256 -> 32 // 256 bits
                HkdfAlgorithm.SHA512 -> 64 // 512 bits
                HkdfAlgorithm.SHA1 -> 20   // 160 bits
            }

            if (masterKey.size < minMasterKeySize) {
                throw IllegalArgumentException(
                    "Master key must be at least ${minMasterKeySize} bytes (${minMasterKeySize * 8} bits) for " +
                    "${algorithmStr ?: "SHA-256"}. Provided key is ${masterKey.size} bytes (${masterKey.size * 8} bits)."
                )
            }

            // Validate domain and context
            val domain = params.getString("domain") 
                ?: throw IllegalArgumentException("domain is required")
            val context = params.getString("context") 
                ?: throw IllegalArgumentException("context is required")

            if (domain.length > MAX_STRING_LENGTH || context.length > MAX_STRING_LENGTH) {
                throw IllegalArgumentException("Domain and context strings must not exceed $MAX_STRING_LENGTH characters.")
            }

            // Validate key size
            val keySize = if (params.hasKey("keySize")) params.getDouble("keySize").toInt() else null
            
            if (keySize != null) {
                val minKeySize = when (algorithm ?: HkdfAlgorithm.SHA256) {
                    HkdfAlgorithm.SHA256 -> 32 // 256 bits
                    HkdfAlgorithm.SHA512 -> 64 // 512 bits
                    HkdfAlgorithm.SHA1 -> 20   // 160 bits
                }

                if (keySize < minKeySize) {
                    throw IllegalArgumentException(
                        "Derived key size must be at least $minKeySize bytes (${minKeySize * 8} bits) for " +
                        "${algorithmStr ?: "SHA-256"}. Requested size was $keySize bytes."
                    )
                }

                val maxKeySize = 64 // 512 bits max
                if (keySize > maxKeySize) {
                    throw IllegalArgumentException(
                        "Derived key size must not exceed $maxKeySize bytes (${maxKeySize * 8} bits). " +
                        "Requested size was $keySize bytes."
                    )
                }
            }

            return DefaultKeyDerivationParams(algorithm, masterKey, domain, context, keySize)
        }
    }
}

private data class DefaultKeyDerivationParams(
    override val algorithm: HkdfAlgorithm?,
    override val masterKey: ByteArray,
    override val domain: String,
    override val context: String,
    override val keySize: Int?
) : KeyDerivationParams {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DefaultKeyDerivationParams) return false
        return algorithm == other.algorithm &&
                masterKey.contentEquals(other.masterKey) &&
                domain == other.domain &&
                context == other.context &&
                keySize == other.keySize
    }

    override fun hashCode(): Int {
        var result = algorithm?.hashCode() ?: 0
        result = 31 * result + masterKey.contentHashCode()
        result = 31 * result + domain.hashCode()
        result = 31 * result + context.hashCode()
        result = 31 * result + (keySize ?: 0)
        return result
    }
}

class KeyDerivation {
    companion object {
        suspend fun deriveKey(params: KeyDerivationParams): String {
            return when (params) {
                is DefaultKeyDerivationParams -> {
                    val algorithm = params.algorithm ?: HkdfAlgorithm.SHA256
                    val keySize = params.keySize ?: when (algorithm) {
                        HkdfAlgorithm.SHA256 -> 32
                        HkdfAlgorithm.SHA512 -> 64
                        HkdfAlgorithm.SHA1 -> 20
                    }

                    try {
                        val derivedKey = NativeKeyDerivation.deriveKey(
                            masterKey = params.masterKey,
                            algorithm = algorithm,
                            domain = params.domain,
                            context = params.context,
                            keySize = keySize
                        ).getOrThrow()

                        derivedKey.use { bytes ->
                            Base64.encodeToString(bytes, Base64.NO_WRAP)
                        }
                    } catch (e: Exception) {
                        throw RuntimeException("Key derivation failed: ${e.message}", e)
                    }
                }
            }
        }
    }
}