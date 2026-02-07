package com.rsa.core

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.interfaces.RSAPrivateCrtKey

/**
 * ASN.1 DER encoding/decoding utilities for RSA key format conversions.
 *
 * Handles the low-level binary encoding needed to convert between
 * PKCS#1 and PKCS#8 key formats without external dependencies.
 *
 * ASN.1 (Abstract Syntax Notation One) uses TLV (Tag-Length-Value) encoding:
 *   - Tag:    identifies the data type (e.g. 0x02 = INTEGER, 0x30 = SEQUENCE)
 *   - Length: number of bytes in the value
 *   - Value:  the actual data bytes
 */
object ASN1Utils {

    // RSA algorithm OID: 1.2.840.113549.1.1.1
    // This identifies the key as RSA in AlgorithmIdentifier structures
    val RSA_OID = byteArrayOf(
        0x06, 0x09, 0x2A.toByte(), 0x86.toByte(), 0x48, 0x86.toByte(),
        0xF7.toByte(), 0x0D, 0x01, 0x01, 0x01
    )

    // ASN.1 NULL value — used as the parameter in AlgorithmIdentifier (RSA has no params)
    val ASN1_NULL = byteArrayOf(0x05, 0x00)

    /**
     * Encode a BigInteger as an ASN.1 INTEGER (tag 0x02 + length + value).
     * BigInteger.toByteArray() returns a two's-complement representation,
     * which is exactly what DER INTEGER expects.
     */
    fun encodeAsn1Integer(value: BigInteger): ByteArray {
        val output = ByteArrayOutputStream()
        val bytes = value.toByteArray()
        output.write(0x02)  // INTEGER tag
        output.write(encodeAsn1Length(bytes.size))
        output.write(bytes)
        return output.toByteArray()
    }

    /**
     * Encode a length value in ASN.1 DER format.
     *
     * DER length encoding:
     *   - 0–127:    single byte (short form)
     *   - 128–255:  0x81 followed by one byte
     *   - 256–65535: 0x82 followed by two bytes (big-endian)
     */
    fun encodeAsn1Length(length: Int): ByteArray {
        return when {
            length < 128 -> byteArrayOf(length.toByte())
            length < 256 -> byteArrayOf(0x81.toByte(), length.toByte())
            length < 65536 -> byteArrayOf(
                0x82.toByte(),
                (length shr 8).toByte(),
                (length and 0xFF).toByte()
            )
            else -> throw IllegalArgumentException("Length too large: $length")
        }
    }

    /**
     * Decode an ASN.1 DER length field starting at [offset] in [bytes].
     *
     * @return Pair of (decoded length or null on error, number of bytes consumed)
     */
    fun decodeAsn1Length(bytes: ByteArray, offset: Int): Pair<Int?, Int> {
        if (offset >= bytes.size) return Pair(null, 0)
        val first = bytes[offset].toInt() and 0xFF
        if (first < 128) {
            return Pair(first, 1)
        }
        val numBytes = first and 0x7F
        if (numBytes == 0 || offset + numBytes >= bytes.size) return Pair(null, 0)
        var length = 0
        for (i in 0 until numBytes) {
            length = (length shl 8) or (bytes[offset + 1 + i].toInt() and 0xFF)
        }
        return Pair(length, 1 + numBytes)
    }

    /**
     * Encode an RSA private key as PKCS#1 DER.
     *
     * PKCS#1 RSAPrivateKey layout:
     *   SEQUENCE {
     *     version   INTEGER (0),
     *     modulus   INTEGER,  -- n
     *     publicExp INTEGER,  -- e
     *     privateExp INTEGER, -- d
     *     prime1    INTEGER,  -- p
     *     prime2    INTEGER,  -- q
     *     exp1      INTEGER,  -- d mod (p-1)
     *     exp2      INTEGER,  -- d mod (q-1)
     *     coeff     INTEGER   -- (inverse of q) mod p
     *   }
     */
    fun encodePkcs1RsaPrivateKey(key: RSAPrivateCrtKey): ByteArray {
        val output = ByteArrayOutputStream()
        val sequenceContent = ByteArrayOutputStream()

        sequenceContent.write(encodeAsn1Integer(BigInteger.ZERO))      // version = 0
        sequenceContent.write(encodeAsn1Integer(key.modulus))          // n
        sequenceContent.write(encodeAsn1Integer(key.publicExponent))   // e
        sequenceContent.write(encodeAsn1Integer(key.privateExponent))  // d
        sequenceContent.write(encodeAsn1Integer(key.primeP))           // p
        sequenceContent.write(encodeAsn1Integer(key.primeQ))           // q
        sequenceContent.write(encodeAsn1Integer(key.primeExponentP))   // d mod (p-1)
        sequenceContent.write(encodeAsn1Integer(key.primeExponentQ))   // d mod (q-1)
        sequenceContent.write(encodeAsn1Integer(key.crtCoefficient))   // (inverse of q) mod p

        val contentBytes = sequenceContent.toByteArray()
        output.write(0x30)  // SEQUENCE tag
        output.write(encodeAsn1Length(contentBytes.size))
        output.write(contentBytes)

        return output.toByteArray()
    }

    /**
     * Wrap PKCS#1 private key bytes inside a PKCS#8 PrivateKeyInfo structure.
     *
     * PKCS#8 PrivateKeyInfo layout:
     *   SEQUENCE {
     *     version            INTEGER (0),
     *     algorithm          AlgorithmIdentifier { OID, NULL },
     *     privateKey         OCTET STRING containing PKCS#1 bytes
     *   }
     */
    fun wrapPkcs1InPkcs8(pkcs1Bytes: ByteArray): ByteArray {
        val output = ByteArrayOutputStream()
        val sequenceContent = ByteArrayOutputStream()

        // version INTEGER 0
        sequenceContent.write(encodeAsn1Integer(BigInteger.ZERO))

        // AlgorithmIdentifier SEQUENCE { rsaOID, NULL }
        val algIdContent = ByteArrayOutputStream()
        algIdContent.write(RSA_OID)
        algIdContent.write(ASN1_NULL)
        val algIdBytes = algIdContent.toByteArray()
        sequenceContent.write(0x30) // SEQUENCE tag
        sequenceContent.write(encodeAsn1Length(algIdBytes.size))
        sequenceContent.write(algIdBytes)

        // privateKey OCTET STRING wrapping the raw PKCS#1 bytes
        sequenceContent.write(0x04) // OCTET STRING tag
        sequenceContent.write(encodeAsn1Length(pkcs1Bytes.size))
        sequenceContent.write(pkcs1Bytes)

        val contentBytes = sequenceContent.toByteArray()
        output.write(0x30) // outer SEQUENCE tag
        output.write(encodeAsn1Length(contentBytes.size))
        output.write(contentBytes)

        return output.toByteArray()
    }

    /**
     * Extract the inner PKCS#1 private key bytes from a PKCS#8 wrapper.
     *
     * Walks the PKCS#8 structure:
     *   SEQUENCE → skip version INTEGER → skip AlgorithmIdentifier SEQUENCE → read OCTET STRING
     *
     * Returns the original bytes unchanged if parsing fails.
     */
    fun extractPkcs1FromPkcs8(pkcs8Bytes: ByteArray): ByteArray {
        var offset = 0

        // Outer SEQUENCE
        if (offset >= pkcs8Bytes.size || pkcs8Bytes[offset] != 0x30.toByte()) return pkcs8Bytes
        offset++
        val (_, seqLenBytes) = decodeAsn1Length(pkcs8Bytes, offset)
        offset += seqLenBytes

        // version INTEGER — skip over it
        if (offset >= pkcs8Bytes.size || pkcs8Bytes[offset] != 0x02.toByte()) return pkcs8Bytes
        offset++
        val (verLen, verLenBytes) = decodeAsn1Length(pkcs8Bytes, offset)
        offset += verLenBytes + (verLen ?: 0)

        // AlgorithmIdentifier SEQUENCE — skip over it
        if (offset >= pkcs8Bytes.size || pkcs8Bytes[offset] != 0x30.toByte()) return pkcs8Bytes
        offset++
        val (algLen, algLenBytes) = decodeAsn1Length(pkcs8Bytes, offset)
        offset += algLenBytes + (algLen ?: 0)

        // OCTET STRING containing the PKCS#1 private key
        if (offset >= pkcs8Bytes.size || pkcs8Bytes[offset] != 0x04.toByte()) return pkcs8Bytes
        offset++
        val (octetLen, octetLenBytes) = decodeAsn1Length(pkcs8Bytes, offset)
        offset += octetLenBytes

        val len = octetLen ?: return pkcs8Bytes
        if (offset + len > pkcs8Bytes.size) return pkcs8Bytes
        return pkcs8Bytes.copyOfRange(offset, offset + len)
    }
}
