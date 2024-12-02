package com.mavbozo.rnsecurecrypto.internal

import com.mavbozo.androidsecurecrypto.Random as NativeRandom

class Random {
    private var nativeRandom: NativeRandom? = null
    
    private suspend fun getNativeRandom(): NativeRandom {
        return nativeRandom ?: NativeRandom.create().getOrThrow().also { 
            nativeRandom = it 
        }
    }

    @Throws(Exception::class)
    suspend fun generateRandomBytes(length: Int): ByteArray {
        return getNativeRandom().nextSecureBytes(length).getOrThrow().use { bytes ->
            bytes.clone() // Clone before the bytes get zeroed
        }
    }

    @Throws(Exception::class)
    suspend fun generateRandomBytesAsHex(length: Int): String {
        // Use the companion object's static method directly for efficiency
        return NativeRandom.generateBytesAsHex(length).getOrThrow()
    }

    @Throws(Exception::class)
    suspend fun generateRandomBytesAsBase64(length: Int): String {
        // Use the companion object's static method directly for efficiency
        return NativeRandom.generateBytesAsBase64(length).getOrThrow()
    }

    fun cleanup() {
        nativeRandom = null
    }
}