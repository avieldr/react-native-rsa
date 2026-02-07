package com.rsa.core

import java.security.Signature
import java.util.Base64

/**
 * RSA signing and verification operations for Android.
 *
 * Uses `java.security.Signature` with algorithm configurations from [Algorithms].
 * All data crosses the bridge as base64 strings to avoid binary encoding issues.
 *
 * Supported padding modes:
 *   - "pss"   — PSS (Probabilistic Signature Scheme) with configurable hash.
 *               Salt length equals the hash output length. Available on API 24+.
 *   - "pkcs1" — PKCS#1 v1.5 deterministic signatures
 */
object RSASigner {

    /**
     * Sign data with an RSA private key.
     *
     * @param dataBase64    The data to sign, encoded as base64
     * @param privateKeyPEM The private key in PEM format (PKCS#1 or PKCS#8)
     * @param padding       "pss" or "pkcs1"
     * @param hash          "sha256", "sha1", "sha384", or "sha512"
     * @return The signature encoded as base64
     */
    fun sign(dataBase64: String, privateKeyPEM: String, padding: String, hash: String): String {
        val privateKey = KeyUtils.loadPrivateKey(privateKeyPEM)
        val data = Base64.getDecoder().decode(dataBase64)
        val algorithm = Algorithms.getSignatureAlgorithm(padding, hash)

        val sig = Signature.getInstance(algorithm.name)
        // PSS requires explicit parameter spec; PKCS#1 v1.5 has no params
        if (algorithm.params != null) {
            sig.setParameter(algorithm.params)
        }
        sig.initSign(privateKey)
        sig.update(data)

        val signature = sig.sign()
        return Base64.getEncoder().encodeToString(signature)
    }

    /**
     * Verify a signature against data using an RSA public key.
     *
     * @param dataBase64      The original data that was signed, encoded as base64
     * @param signatureBase64 The signature to verify, encoded as base64
     * @param publicKeyPEM    The public key in SPKI PEM format ("BEGIN PUBLIC KEY")
     * @param padding         "pss" or "pkcs1" — must match the padding used during signing
     * @param hash            "sha256", "sha1", "sha384", or "sha512" — must match signing hash
     * @return true if the signature is valid, false otherwise
     */
    fun verify(dataBase64: String, signatureBase64: String, publicKeyPEM: String, padding: String, hash: String): Boolean {
        val publicKey = KeyUtils.loadPublicKey(publicKeyPEM)
        val data = Base64.getDecoder().decode(dataBase64)
        val signatureBytes = Base64.getDecoder().decode(signatureBase64)
        val algorithm = Algorithms.getSignatureAlgorithm(padding, hash)

        val sig = Signature.getInstance(algorithm.name)
        if (algorithm.params != null) {
            sig.setParameter(algorithm.params)
        }
        sig.initVerify(publicKey)
        sig.update(data)

        return sig.verify(signatureBytes)
    }
}
