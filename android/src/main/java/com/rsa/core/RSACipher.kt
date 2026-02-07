package com.rsa.core

import java.util.Base64
import javax.crypto.Cipher

/**
 * RSA encryption and decryption operations for Android.
 *
 * Uses `javax.crypto.Cipher` with algorithm configurations from [Algorithms].
 * All data crosses the bridge as base64 strings to avoid binary encoding issues.
 *
 * Supported padding modes:
 *   - "oaep"  — OAEP (Optimal Asymmetric Encryption Padding) with configurable hash.
 *               Uses explicit OAEPParameterSpec to ensure the correct hash is used
 *               for both the message digest and MGF1 mask generation.
 *   - "pkcs1" — PKCS#1 v1.5 padding (legacy, not recommended for new applications)
 */
object RSACipher {

    /**
     * Encrypt data with an RSA public key.
     *
     * @param dataBase64    The plaintext data encoded as base64
     * @param publicKeyPEM  The public key in SPKI PEM format ("BEGIN PUBLIC KEY")
     * @param padding       "oaep" or "pkcs1"
     * @param hash          "sha256", "sha1", "sha384", or "sha512" (used with OAEP)
     * @return The ciphertext encoded as base64
     */
    fun encrypt(dataBase64: String, publicKeyPEM: String, padding: String, hash: String): String {
        val publicKey = KeyUtils.loadPublicKey(publicKeyPEM)
        val data = Base64.getDecoder().decode(dataBase64)
        val algorithm = Algorithms.getCipherAlgorithm(padding, hash)

        val cipher = Cipher.getInstance(algorithm.transformation)
        if (algorithm.params != null) {
            // OAEP requires explicit parameter spec for correct hash configuration
            cipher.init(Cipher.ENCRYPT_MODE, publicKey, algorithm.params)
        } else {
            // PKCS#1 v1.5 — no additional params needed
            cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        }

        val encrypted = cipher.doFinal(data)
        return Base64.getEncoder().encodeToString(encrypted)
    }

    /**
     * Decrypt data with an RSA private key.
     *
     * @param dataBase64     The ciphertext encoded as base64
     * @param privateKeyPEM  The private key in PEM format (PKCS#1 or PKCS#8)
     * @param padding        "oaep" or "pkcs1" — must match the padding used during encryption
     * @param hash           "sha256", "sha1", "sha384", or "sha512" — must match encryption hash
     * @return The decrypted plaintext encoded as base64
     */
    fun decrypt(dataBase64: String, privateKeyPEM: String, padding: String, hash: String): String {
        val privateKey = KeyUtils.loadPrivateKey(privateKeyPEM)
        val data = Base64.getDecoder().decode(dataBase64)
        val algorithm = Algorithms.getCipherAlgorithm(padding, hash)

        val cipher = Cipher.getInstance(algorithm.transformation)
        if (algorithm.params != null) {
            cipher.init(Cipher.DECRYPT_MODE, privateKey, algorithm.params)
        } else {
            cipher.init(Cipher.DECRYPT_MODE, privateKey)
        }

        val decrypted = cipher.doFinal(data)
        return Base64.getEncoder().encodeToString(decrypted)
    }
}
