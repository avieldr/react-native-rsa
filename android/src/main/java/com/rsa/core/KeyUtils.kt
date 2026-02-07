package com.rsa.core

import java.security.KeyFactory
import java.security.PublicKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * PEM parsing and key loading utilities for Android.
 *
 * Handles conversion between PEM-encoded key strings and Java security key objects.
 * Supports both PKCS#1 ("BEGIN RSA PRIVATE KEY") and PKCS#8 ("BEGIN PRIVATE KEY")
 * private key formats, and SPKI ("BEGIN PUBLIC KEY") public key format.
 */
object KeyUtils {

    /**
     * Extract the base64-encoded content from a PEM string,
     * stripping the header/footer lines and all whitespace.
     */
    fun extractBase64(pem: String): String {
        return pem.lines()
            .filter { !it.startsWith("-----") }
            .joinToString("")
            .replace("\\s".toRegex(), "")
    }

    /**
     * Format raw DER bytes as a PEM string with the given header.
     *
     * @param derBytes The raw DER-encoded key bytes
     * @param header   The PEM header label (e.g. "RSA PRIVATE KEY", "PRIVATE KEY", "PUBLIC KEY")
     * @return A properly formatted PEM string with 64-char line wrapping
     */
    fun toPEM(derBytes: ByteArray, header: String): String {
        val base64Key = Base64.getEncoder().encodeToString(derBytes)
        return "-----BEGIN $header-----\n" +
                base64Key.chunked(64).joinToString("\n") +
                "\n-----END $header-----"
    }

    /**
     * Load an RSA private key from a PEM string.
     *
     * Accepts both PKCS#1 and PKCS#8 formats:
     *   - PKCS#1 ("BEGIN RSA PRIVATE KEY"): wraps in PKCS#8 first, since Java's
     *     KeyFactory only accepts PKCS#8 (PKCS8EncodedKeySpec)
     *   - PKCS#8 ("BEGIN PRIVATE KEY"): used directly
     *
     * @return The private key as RSAPrivateCrtKey (gives access to CRT components)
     */
    fun loadPrivateKey(pem: String): RSAPrivateCrtKey {
        val keyFactory = KeyFactory.getInstance("RSA")
        val base64 = extractBase64(pem)
        val derBytes = Base64.getDecoder().decode(base64)

        // Java only accepts PKCS#8, so wrap PKCS#1 if needed
        val pkcs8Bytes = if (pem.contains("BEGIN RSA PRIVATE KEY")) {
            ASN1Utils.wrapPkcs1InPkcs8(derBytes)
        } else {
            derBytes
        }

        val spec = PKCS8EncodedKeySpec(pkcs8Bytes)
        return keyFactory.generatePrivate(spec) as RSAPrivateCrtKey
    }

    /**
     * Load an RSA public key from a PEM string (SPKI/X.509 format).
     *
     * Expects "BEGIN PUBLIC KEY" (SPKI) format, which is what Java's
     * X509EncodedKeySpec accepts directly.
     */
    fun loadPublicKey(pem: String): PublicKey {
        val keyFactory = KeyFactory.getInstance("RSA")
        val base64 = extractBase64(pem)
        val derBytes = Base64.getDecoder().decode(base64)
        val spec = X509EncodedKeySpec(derBytes)
        return keyFactory.generatePublic(spec)
    }
}
