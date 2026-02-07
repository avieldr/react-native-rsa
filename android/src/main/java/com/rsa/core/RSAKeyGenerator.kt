package com.rsa.core

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.RSAPublicKeySpec
import java.util.Base64

/**
 * Result of RSA key pair generation, containing both keys as PEM strings.
 */
data class RSAKeyPairResult(
    val publicKey: String,
    val privateKey: String
)

/**
 * RSA key generation and conversion operations.
 *
 * Thread-safe singleton that provides:
 *   - Key pair generation (PKCS#1 or PKCS#8 private key format)
 *   - Public key extraction from a private key
 *   - Private key format conversion between PKCS#1 and PKCS#8
 *
 * Delegates ASN.1 encoding to [ASN1Utils] and PEM/key-loading to [KeyUtils].
 */
class RSAKeyGenerator {

    companion object {
        private const val DEFAULT_KEY_SIZE = 2048

        @Volatile
        private var INSTANCE: RSAKeyGenerator? = null

        fun getInstance(): RSAKeyGenerator {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: RSAKeyGenerator().also { INSTANCE = it }
            }
        }
    }

    /**
     * Generate an RSA key pair.
     *
     * @param keySize RSA key size in bits (default: 2048). Supported: 1024, 2048, 4096.
     * @param format  "pkcs1" or "pkcs8" — controls the private key output format.
     *                Public key is always SPKI/X.509 ("BEGIN PUBLIC KEY").
     * @return RSAKeyPairResult with public and private keys in PEM format
     */
    fun generateKeyPair(keySize: Int = DEFAULT_KEY_SIZE, format: String = "pkcs1"): RSAKeyPairResult {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(keySize)
        val keyPair: KeyPair = keyPairGenerator.generateKeyPair()

        val privateKey = keyPair.private as RSAPrivateCrtKey
        val publicKey = keyPair.public as RSAPublicKey

        // Encode private key in the requested format
        val privateKeyPEM = when (format) {
            "pkcs8" -> KeyUtils.toPEM(privateKey.encoded, "PRIVATE KEY")
            else -> {
                // Manually encode PKCS#1 since Java only gives us PKCS#8 natively
                val pkcs1Bytes = ASN1Utils.encodePkcs1RsaPrivateKey(privateKey)
                KeyUtils.toPEM(pkcs1Bytes, "RSA PRIVATE KEY")
            }
        }

        // Public key: Java's key.encoded returns SPKI/X.509 DER directly
        val publicKeyPEM = KeyUtils.toPEM(publicKey.encoded, "PUBLIC KEY")

        return RSAKeyPairResult(publicKey = publicKeyPEM, privateKey = privateKeyPEM)
    }

    /**
     * Extract the public key from an RSA private key PEM string.
     *
     * Works with both PKCS#1 and PKCS#8 input formats.
     * The returned public key is always in SPKI/X.509 PEM format.
     */
    fun getPublicKeyFromPrivate(privateKeyPEM: String): String {
        val keyFactory = KeyFactory.getInstance("RSA")

        // Load the private key (handles both PKCS#1 and PKCS#8 automatically)
        val privateKey = KeyUtils.loadPrivateKey(privateKeyPEM)

        // Build public key from the private key's modulus and public exponent
        val publicSpec = RSAPublicKeySpec(privateKey.modulus, privateKey.publicExponent)
        val publicKey = keyFactory.generatePublic(publicSpec) as RSAPublicKey

        return KeyUtils.toPEM(publicKey.encoded, "PUBLIC KEY")
    }

    /**
     * Convert a private key PEM between PKCS#1 and PKCS#8 formats.
     *
     * @param pem          The private key in PEM format
     * @param targetFormat "pkcs1" or "pkcs8"
     * @return The private key re-encoded in the target format
     * @throws IllegalArgumentException if the PEM format is unrecognized
     */
    fun convertPrivateKey(pem: String, targetFormat: String): String {
        return when {
            // PKCS#1 → PKCS#8: wrap the raw bytes in a PKCS#8 structure
            pem.contains("BEGIN RSA PRIVATE KEY") && targetFormat == "pkcs8" -> {
                val base64 = KeyUtils.extractBase64(pem)
                val pkcs1Bytes = Base64.getDecoder().decode(base64)
                val pkcs8Bytes = ASN1Utils.wrapPkcs1InPkcs8(pkcs1Bytes)
                KeyUtils.toPEM(pkcs8Bytes, "PRIVATE KEY")
            }
            // PKCS#8 → PKCS#1: extract the inner PKCS#1 bytes
            pem.contains("BEGIN PRIVATE KEY") && targetFormat == "pkcs1" -> {
                val base64 = KeyUtils.extractBase64(pem)
                val pkcs8Bytes = Base64.getDecoder().decode(base64)
                val pkcs1Bytes = ASN1Utils.extractPkcs1FromPkcs8(pkcs8Bytes)
                KeyUtils.toPEM(pkcs1Bytes, "RSA PRIVATE KEY")
            }
            // Already in the target format — return unchanged
            pem.contains("BEGIN RSA PRIVATE KEY") && targetFormat == "pkcs1" -> pem
            pem.contains("BEGIN PRIVATE KEY") && targetFormat == "pkcs8" -> pem
            else -> throw IllegalArgumentException("Unrecognized PEM format or unsupported target format")
        }
    }
}
