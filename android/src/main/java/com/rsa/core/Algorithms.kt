package com.rsa.core

import java.security.spec.AlgorithmParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

/**
 * Maps (padding, hash) option strings to Java Security / Cipher algorithm configurations.
 *
 * This provides a single lookup point so that RSACipher and RSASigner don't
 * need to duplicate algorithm selection logic.
 *
 * Supported combinations:
 *   Cipher (encrypt/decrypt):
 *     - "pkcs1"  → RSA/ECB/PKCS1Padding (hash is ignored)
 *     - "oaep"   → RSA/ECB/OAEPPadding with explicit OAEPParameterSpec
 *
 *   Signature (sign/verify):
 *     - "pkcs1"  → SHA{N}withRSA
 *     - "pss"    → SHA{N}withRSA/PSS with explicit PSSParameterSpec
 */
object Algorithms {

    /**
     * Resolved cipher algorithm: the Java transformation string plus optional params.
     */
    data class CipherAlgorithm(
        val transformation: String,
        val params: AlgorithmParameterSpec?
    )

    /**
     * Resolved signature algorithm: the Java algorithm name plus optional params.
     */
    data class SignatureAlgorithm(
        val name: String,
        val params: AlgorithmParameterSpec?
    )

    /**
     * Look up the Java Cipher transformation and parameters for an encrypt/decrypt operation.
     *
     * @param padding "pkcs1" or "oaep"
     * @param hash    "sha1", "sha256", "sha384", or "sha512" (only used with OAEP)
     */
    fun getCipherAlgorithm(padding: String, hash: String): CipherAlgorithm {
        return when (padding) {
            "pkcs1" -> CipherAlgorithm("RSA/ECB/PKCS1Padding", null)
            "oaep" -> {
                val (hashName, mgf1Spec) = getHashParams(hash)
                // Explicit OAEPParameterSpec is needed to support all hash algorithms.
                // The default "RSA/ECB/OAEPWithSHA-256AndMGF1Padding" always uses SHA-1 for MGF1.
                CipherAlgorithm(
                    "RSA/ECB/OAEPPadding",
                    OAEPParameterSpec(hashName, "MGF1", mgf1Spec, PSource.PSpecified.DEFAULT)
                )
            }
            else -> throw IllegalArgumentException("Unsupported encryption padding: $padding")
        }
    }

    /**
     * Look up the Java Signature algorithm name and parameters for a sign/verify operation.
     *
     * @param padding "pkcs1" or "pss"
     * @param hash    "sha1", "sha256", "sha384", or "sha512"
     */
    fun getSignatureAlgorithm(padding: String, hash: String): SignatureAlgorithm {
        return when (padding) {
            "pkcs1" -> {
                // Deterministic PKCS#1 v1.5 signatures — no additional params needed
                val algName = when (hash) {
                    "sha1" -> "SHA1withRSA"
                    "sha256" -> "SHA256withRSA"
                    "sha384" -> "SHA384withRSA"
                    "sha512" -> "SHA512withRSA"
                    else -> throw IllegalArgumentException("Unsupported hash: $hash")
                }
                SignatureAlgorithm(algName, null)
            }
            "pss" -> {
                // PSS signatures require explicit parameter spec (salt length = hash output length)
                val (hashName, mgf1Spec, saltLen) = getHashParamsWithSalt(hash)
                val algName = when (hash) {
                    "sha1" -> "SHA1withRSA/PSS"
                    "sha256" -> "SHA256withRSA/PSS"
                    "sha384" -> "SHA384withRSA/PSS"
                    "sha512" -> "SHA512withRSA/PSS"
                    else -> throw IllegalArgumentException("Unsupported hash: $hash")
                }
                SignatureAlgorithm(
                    algName,
                    PSSParameterSpec(hashName, "MGF1", mgf1Spec, saltLen, 1)
                )
            }
            else -> throw IllegalArgumentException("Unsupported signature padding: $padding")
        }
    }

    // --- Internal helpers ---

    /** Hash name and MGF1 parameter spec for a given hash algorithm. */
    private fun getHashParams(hash: String): Pair<String, MGF1ParameterSpec> {
        return when (hash) {
            "sha1" -> Pair("SHA-1", MGF1ParameterSpec.SHA1)
            "sha256" -> Pair("SHA-256", MGF1ParameterSpec.SHA256)
            "sha384" -> Pair("SHA-384", MGF1ParameterSpec.SHA384)
            "sha512" -> Pair("SHA-512", MGF1ParameterSpec.SHA512)
            else -> throw IllegalArgumentException("Unsupported hash: $hash")
        }
    }

    /** Hash name, MGF1 spec, and salt length (= hash output size in bytes) for PSS. */
    private data class HashParamsWithSalt(val hashName: String, val mgf1Spec: MGF1ParameterSpec, val saltLen: Int)
    private fun getHashParamsWithSalt(hash: String): HashParamsWithSalt {
        return when (hash) {
            "sha1" -> HashParamsWithSalt("SHA-1", MGF1ParameterSpec.SHA1, 20)
            "sha256" -> HashParamsWithSalt("SHA-256", MGF1ParameterSpec.SHA256, 32)
            "sha384" -> HashParamsWithSalt("SHA-384", MGF1ParameterSpec.SHA384, 48)
            "sha512" -> HashParamsWithSalt("SHA-512", MGF1ParameterSpec.SHA512, 64)
            else -> throw IllegalArgumentException("Unsupported hash: $hash")
        }
    }
}
