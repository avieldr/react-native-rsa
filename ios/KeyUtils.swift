import Foundation
import Security

/**
 * PEM parsing and key loading utilities for iOS.
 *
 * Handles conversion between PEM-encoded key strings and SecKey objects.
 * Supports both PKCS#1 ("BEGIN RSA PRIVATE KEY") and PKCS#8 ("BEGIN PRIVATE KEY")
 * private key formats, and SPKI ("BEGIN PUBLIC KEY") public key format.
 */
enum KeyUtils {

    /**
     * Extract the base64-encoded content from a PEM string,
     * stripping the header/footer lines.
     */
    static func extractBase64(from pem: String) -> String {
        return pem.components(separatedBy: "\n")
            .filter { !$0.hasPrefix("-----") }
            .joined()
    }

    /**
     * Format raw DER data as a PEM string with the given header.
     *
     * - Parameters:
     *   - data:   The raw DER-encoded key data
     *   - header: The PEM header label (e.g. "RSA PRIVATE KEY", "PRIVATE KEY", "PUBLIC KEY")
     * - Returns: A properly formatted PEM string with 64-char line wrapping
     */
    static func toPEM(data: Data, header: String) -> String {
        let base64 = data.base64EncodedString()
        let lines = base64.chunked(into: 64).joined(separator: "\n")
        return "-----BEGIN \(header)-----\n\(lines)\n-----END \(header)-----"
    }

    /**
     * Load an RSA private key from a PEM string as a SecKey.
     *
     * Accepts both PKCS#1 and PKCS#8 formats:
     *   - PKCS#1 ("BEGIN RSA PRIVATE KEY"): used directly, since SecKeyCreateWithData
     *     expects raw PKCS#1 for RSA private keys
     *   - PKCS#8 ("BEGIN PRIVATE KEY"): extracts the inner PKCS#1 data first
     *
     * - Throws: If base64 decoding fails or the key cannot be imported
     */
    static func loadPrivateKey(pem: String) throws -> SecKey {
        let base64 = extractBase64(from: pem)
        guard let derData = Data(base64Encoded: base64) else {
            throw NSError(domain: "KeyUtils", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "Invalid base64 encoding in private key PEM"])
        }

        // SecKeyCreateWithData expects raw PKCS#1 for RSA keys
        let pkcs1Data: Data
        if pem.contains("BEGIN RSA PRIVATE KEY") {
            pkcs1Data = derData
        } else if pem.contains("BEGIN PRIVATE KEY") {
            // PKCS#8 wraps PKCS#1 — extract the inner key
            pkcs1Data = ASN1Utils.extractPkcs1FromPkcs8(pkcs8Data: derData)
        } else {
            throw NSError(domain: "KeyUtils", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "Unrecognized private key PEM format"])
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(pkcs1Data as CFData, attributes as CFDictionary, &error) else {
            let errorMessage = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw NSError(domain: "KeyUtils", code: 3,
                          userInfo: [NSLocalizedDescriptionKey: "Failed to import private key: \(errorMessage)"])
        }
        return key
    }

    /**
     * Load an RSA public key from a PEM string as a SecKey.
     *
     * Expects SPKI ("BEGIN PUBLIC KEY") format. Since SecKeyCreateWithData
     * expects raw PKCS#1 public key data (not SPKI), the SPKI header is
     * stripped automatically.
     *
     * - Throws: If base64 decoding fails or the key cannot be imported
     */
    static func loadPublicKey(pem: String) throws -> SecKey {
        let base64 = extractBase64(from: pem)
        guard let derData = Data(base64Encoded: base64) else {
            throw NSError(domain: "KeyUtils", code: 4,
                          userInfo: [NSLocalizedDescriptionKey: "Invalid base64 encoding in public key PEM"])
        }

        // SecKeyCreateWithData expects raw PKCS#1 public key, not SPKI
        let rawKeyData = ASN1Utils.stripSPKIHeader(spkiData: derData)

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
        ]

        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(rawKeyData as CFData, attributes as CFDictionary, &error) else {
            let errorMessage = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw NSError(domain: "KeyUtils", code: 5,
                          userInfo: [NSLocalizedDescriptionKey: "Failed to import public key: \(errorMessage)"])
        }
        return key
    }
}

// MARK: - String Extension for PEM Line Wrapping

extension String {
    /// Split a string into chunks of the given size (used for 64-char PEM line wrapping).
    func chunked(into size: Int) -> [String] {
        return stride(from: 0, to: count, by: size).map {
            let start = index(startIndex, offsetBy: $0)
            let end = index(start, offsetBy: min(size, count - $0))
            return String(self[start..<end])
        }
    }
}
