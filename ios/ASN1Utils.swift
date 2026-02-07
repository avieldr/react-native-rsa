import Foundation

/**
 * ASN.1 DER encoding/decoding utilities for RSA key format conversions.
 *
 * Handles the low-level binary encoding needed to convert between
 * PKCS#1 and PKCS#8 key formats, and to wrap raw public keys in SPKI.
 *
 * ASN.1 (Abstract Syntax Notation One) uses TLV (Tag-Length-Value) encoding:
 *   - Tag:    identifies the data type (e.g. 0x02 = INTEGER, 0x30 = SEQUENCE)
 *   - Length: number of bytes in the value
 *   - Value:  the actual data bytes
 */
enum ASN1Utils {

    // RSA algorithm OID: 1.2.840.113549.1.1.1
    // This identifies the key as RSA in AlgorithmIdentifier structures
    static let rsaOID: [UInt8] = [
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
    ]

    // ASN.1 NULL value — used as the parameter in AlgorithmIdentifier (RSA has no params)
    static let asn1Null: [UInt8] = [0x05, 0x00]

    // MARK: - Length Encoding / Decoding

    /**
     * Encode a length value in ASN.1 DER format.
     *
     * DER length encoding:
     *   - 0–127:     single byte (short form)
     *   - 128–255:   0x81 followed by one byte
     *   - 256–65535:  0x82 followed by two bytes (big-endian)
     *   - 65536+:     0x83 followed by three bytes
     */
    static func encodeASN1Length(_ length: Int) -> Data {
        if length < 128 {
            return Data([UInt8(length)])
        } else if length < 256 {
            return Data([0x81, UInt8(length)])
        } else if length < 65536 {
            return Data([0x82, UInt8(length >> 8), UInt8(length & 0xFF)])
        } else {
            return Data([0x83, UInt8(length >> 16), UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)])
        }
    }

    /**
     * Decode an ASN.1 DER length field starting at `offset` in `bytes`.
     *
     * - Returns: Tuple of (decoded length or nil on error, number of bytes consumed)
     */
    static func decodeASN1Length(_ bytes: [UInt8], _ offset: Int) -> (Int?, Int) {
        guard offset < bytes.count else { return (nil, 0) }
        let first = bytes[offset]
        if first < 128 {
            return (Int(first), 1)
        }
        let numBytes = Int(first & 0x7F)
        guard numBytes > 0, offset + numBytes < bytes.count else { return (nil, 0) }
        var length = 0
        for i in 0..<numBytes {
            length = (length << 8) | Int(bytes[offset + 1 + i])
        }
        return (length, 1 + numBytes)
    }

    // MARK: - Structure Builders

    /// Wrap arbitrary data in an ASN.1 SEQUENCE (tag 0x30 + length + data).
    static func wrapInSequence(_ data: Data) -> Data {
        var result = Data([0x30])
        result.append(encodeASN1Length(data.count))
        result.append(data)
        return result
    }

    /**
     * Wrap a raw PKCS#1 public key in an SPKI (SubjectPublicKeyInfo) structure.
     *
     * iOS `SecKeyCopyExternalRepresentation` returns raw PKCS#1 for RSA public keys,
     * but the standard PEM "PUBLIC KEY" format expects SPKI wrapping.
     *
     * SPKI layout:
     *   SEQUENCE {
     *     algorithm  AlgorithmIdentifier { OID, NULL },
     *     publicKey  BIT STRING (0x00 unused-bits prefix + raw key bytes)
     *   }
     */
    static func wrapPublicKeyInSPKI(rawKeyData: Data) -> Data {
        // AlgorithmIdentifier SEQUENCE { rsaOID, NULL }
        var algId = Data()
        algId.append(contentsOf: rsaOID)
        algId.append(contentsOf: asn1Null)
        let algIdSeq = wrapInSequence(algId)

        // BIT STRING: tag + length + 0x00 (zero unused bits) + raw key data
        var bitStringContent = Data([0x00])
        bitStringContent.append(rawKeyData)

        var bitString = Data([0x03]) // BIT STRING tag
        bitString.append(encodeASN1Length(bitStringContent.count))
        bitString.append(bitStringContent)

        // Combine into outer SEQUENCE
        var spkiContent = Data()
        spkiContent.append(algIdSeq)
        spkiContent.append(bitString)

        return wrapInSequence(spkiContent)
    }

    /**
     * Wrap PKCS#1 private key data inside a PKCS#8 PrivateKeyInfo structure.
     *
     * PKCS#8 PrivateKeyInfo layout:
     *   SEQUENCE {
     *     version    INTEGER (0),
     *     algorithm  AlgorithmIdentifier { OID, NULL },
     *     privateKey OCTET STRING containing PKCS#1 bytes
     *   }
     */
    static func wrapPkcs1InPkcs8(pkcs1Data: Data) -> Data {
        var content = Data()

        // version INTEGER 0
        content.append(contentsOf: [0x02, 0x01, 0x00] as [UInt8])

        // AlgorithmIdentifier SEQUENCE { rsaOID, NULL }
        var algId = Data()
        algId.append(contentsOf: rsaOID)
        algId.append(contentsOf: asn1Null)
        content.append(wrapInSequence(algId))

        // OCTET STRING wrapping the raw PKCS#1 bytes
        content.append(Data([0x04]))
        content.append(encodeASN1Length(pkcs1Data.count))
        content.append(pkcs1Data)

        return wrapInSequence(content)
    }

    /**
     * Extract the inner PKCS#1 private key data from a PKCS#8 wrapper.
     *
     * Walks the PKCS#8 structure:
     *   SEQUENCE → skip version INTEGER → skip AlgorithmIdentifier → read OCTET STRING
     *
     * Returns the original data unchanged if parsing fails.
     */
    static func extractPkcs1FromPkcs8(pkcs8Data: Data) -> Data {
        let bytes = [UInt8](pkcs8Data)
        var offset = 0

        // Outer SEQUENCE tag + length
        guard offset < bytes.count, bytes[offset] == 0x30 else { return pkcs8Data }
        offset += 1
        let (_, seqLenBytes) = decodeASN1Length(bytes, offset)
        offset += seqLenBytes

        // version INTEGER — skip over it
        guard offset < bytes.count, bytes[offset] == 0x02 else { return pkcs8Data }
        offset += 1
        let (verLen, verLenBytes) = decodeASN1Length(bytes, offset)
        offset += verLenBytes + (verLen ?? 0)

        // AlgorithmIdentifier SEQUENCE — skip over it
        guard offset < bytes.count, bytes[offset] == 0x30 else { return pkcs8Data }
        offset += 1
        let (algLen, algLenBytes) = decodeASN1Length(bytes, offset)
        offset += algLenBytes + (algLen ?? 0)

        // OCTET STRING containing the PKCS#1 private key
        guard offset < bytes.count, bytes[offset] == 0x04 else { return pkcs8Data }
        offset += 1
        let (octetLen, octetLenBytes) = decodeASN1Length(bytes, offset)
        offset += octetLenBytes

        guard let len = octetLen, offset + len <= bytes.count else { return pkcs8Data }
        return Data(bytes[offset..<(offset + len)])
    }

    /**
     * Strip the SPKI (SubjectPublicKeyInfo) wrapper to get the raw PKCS#1 public key.
     *
     * iOS `SecKeyCreateWithData` expects raw PKCS#1 public key data, not SPKI.
     * Standard PEM "PUBLIC KEY" files contain SPKI, so we need to unwrap.
     *
     * SPKI layout:
     *   SEQUENCE {
     *     AlgorithmIdentifier SEQUENCE { ... },
     *     BIT STRING (0x00 prefix + raw key bytes)
     *   }
     */
    static func stripSPKIHeader(spkiData: Data) -> Data {
        let bytes = [UInt8](spkiData)
        var offset = 0

        // Outer SEQUENCE
        guard offset < bytes.count, bytes[offset] == 0x30 else { return spkiData }
        offset += 1
        let (_, seqLenBytes) = decodeASN1Length(bytes, offset)
        offset += seqLenBytes

        // AlgorithmIdentifier SEQUENCE — skip over it
        guard offset < bytes.count, bytes[offset] == 0x30 else { return spkiData }
        offset += 1
        let (algLen, algLenBytes) = decodeASN1Length(bytes, offset)
        offset += algLenBytes + (algLen ?? 0)

        // BIT STRING
        guard offset < bytes.count, bytes[offset] == 0x03 else { return spkiData }
        offset += 1
        let (bitLen, bitLenBytes) = decodeASN1Length(bytes, offset)
        offset += bitLenBytes

        // Skip the "unused bits" byte (always 0x00 for RSA keys)
        guard offset < bytes.count, bytes[offset] == 0x00 else { return spkiData }
        offset += 1

        // The remaining bytes are the raw PKCS#1 public key
        guard let len = bitLen, offset + len - 1 <= bytes.count else { return spkiData }
        return Data(bytes[offset..<(offset + len - 1)])
    }
}
