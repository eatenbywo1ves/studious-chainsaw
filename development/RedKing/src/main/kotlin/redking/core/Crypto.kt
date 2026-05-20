package redking.core

import java.security.*
import java.util.Base64

/**
 * Cryptographic utilities for message signing and verification.
 * Uses RSA with SHA512 for secure message authentication.
 */
object Crypto {
    private const val ALGORITHM = "RSA"
    private const val SIGNATURE_ALGORITHM = "SHA512withRSA"
    private const val KEY_SIZE = 2048

    /**
     * Generate a new RSA key pair.
     */
    fun generateKeyPair(): KeyPair {
        val keyGen = KeyPairGenerator.getInstance(ALGORITHM)
        keyGen.initialize(KEY_SIZE, SecureRandom())
        return keyGen.generateKeyPair()
    }

    /**
     * Sign a message using a private key.
     * @param privateKey The private key to sign with
     * @param message The message to sign
     * @return Base64 encoded signature
     */
    fun signMessage(privateKey: PrivateKey, message: String): String {
        val sig = Signature.getInstance(SIGNATURE_ALGORITHM)
        sig.initSign(privateKey)

        val base64Encoder = Base64.getEncoder()
        sig.update(base64Encoder.encode(message.toByteArray()))

        return base64Encoder.encodeToString(sig.sign())
    }

    /**
     * Verify a message signature using a public key.
     * @param publicKey The public key to verify with
     * @param message The original message
     * @param signature The Base64 encoded signature
     * @return true if signature is valid, false otherwise
     */
    fun verifyMessage(publicKey: PublicKey, message: String, signature: String): Boolean {
        return try {
            val sig = Signature.getInstance(SIGNATURE_ALGORITHM)
            sig.initVerify(publicKey)

            val base64Encoder = Base64.getEncoder()
            val base64Decoder = Base64.getDecoder()

            sig.update(base64Encoder.encode(message.toByteArray()))
            sig.verify(base64Decoder.decode(signature))
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Export a public key to Base64 string.
     */
    fun exportPublicKey(publicKey: PublicKey): String {
        return Base64.getEncoder().encodeToString(publicKey.encoded)
    }

    /**
     * Export a private key to Base64 string.
     */
    fun exportPrivateKey(privateKey: PrivateKey): String {
        return Base64.getEncoder().encodeToString(privateKey.encoded)
    }

    /**
     * Import a public key from Base64 string.
     */
    fun importPublicKey(base64Key: String): PublicKey {
        val keyBytes = Base64.getDecoder().decode(base64Key)
        val keySpec = java.security.spec.X509EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance(ALGORITHM)
        return keyFactory.generatePublic(keySpec)
    }

    /**
     * Import a private key from Base64 string.
     */
    fun importPrivateKey(base64Key: String): PrivateKey {
        val keyBytes = Base64.getDecoder().decode(base64Key)
        val keySpec = java.security.spec.PKCS8EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance(ALGORITHM)
        return keyFactory.generatePrivate(keySpec)
    }

    /**
     * Generate a secure random ID.
     */
    fun generateSecureId(): String {
        val bytes = ByteArray(16)
        SecureRandom().nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}
