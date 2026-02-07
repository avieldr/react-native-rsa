import Foundation
import Security

/**
 * Result of RSA key pair generation, containing both keys as PEM strings.
 * Exposed to Objective-C for bridge compatibility.
 */
@objc public class RSAKeyPairResult: NSObject {
    @objc public let publicKey: String
    @objc public let privateKey: String

    init(publicKey: String, privateKey: String) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
}

/**
 * RSA key generation and conversion operations.
 *
 * Thread-safe singleton that provides:
 *   - Key pair generation (PKCS#1 or PKCS#8 private key format)
 *   - Public key extraction from a private key
 *   - Private key format conversion between PKCS#1 and PKCS#8
 *
 * Uses the iOS Security framework (`SecKey` APIs) for key generation and import.
 * Delegates ASN.1 encoding to `ASN1Utils` and PEM/key-loading to `KeyUtils`.
 */
@objc public final class RSAKeyGenerator: NSObject {

    @objc public static let shared = RSAKeyGenerator()
    private override init() { super.init() }

    // MARK: - Key Pair Generation

    /**
     * Generate an RSA key pair using the iOS Security framework.
     *
     * - Parameters:
     *   - keySize: RSA key size in bits (e.g. 1024, 2048, 4096)
     *   - format:  "pkcs1" or "pkcs8" — controls the private key output format.
     *              Public key is always SPKI ("BEGIN PUBLIC KEY").
     * - Throws: If key generation or export fails
     * - Returns: RSAKeyPairResult with public and private keys in PEM format
     */
    @objc public func generateKeyPair(keySize: Int, format: String) throws -> RSAKeyPairResult {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: keySize,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false
            ]
        ]

        var error: Unmanaged<CFError>?
        guard let privateSecKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let errorMessage = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw NSError(domain: "RSAKeyGenerator", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "Failed to generate RSA key: \(errorMessage)"])
        }

        // SecKeyCopyExternalRepresentation returns PKCS#1 DER for RSA private keys
        guard let privateKeyData = SecKeyCopyExternalRepresentation(privateSecKey, &error) as Data? else {
            let errorMessage = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw NSError(domain: "RSAKeyGenerator", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "Failed to export RSA key: \(errorMessage)"])
        }

        // Encode private key in the requested format
        let privateKeyPEM: String
        if format == "pkcs8" {
            let pkcs8Data = ASN1Utils.wrapPkcs1InPkcs8(pkcs1Data: privateKeyData)
            privateKeyPEM = KeyUtils.toPEM(data: pkcs8Data, header: "PRIVATE KEY")
        } else {
            privateKeyPEM = KeyUtils.toPEM(data: privateKeyData, header: "RSA PRIVATE KEY")
        }

        // Extract and export public key
        guard let publicSecKey = SecKeyCopyPublicKey(privateSecKey) else {
            throw NSError(domain: "RSAKeyGenerator", code: 3,
                          userInfo: [NSLocalizedDescriptionKey: "Could not extract public key"])
        }

        guard let publicKeyRawData = SecKeyCopyExternalRepresentation(publicSecKey, &error) as Data? else {
            let errorMessage = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw NSError(domain: "RSAKeyGenerator", code: 4,
                          userInfo: [NSLocalizedDescriptionKey: "Failed to export public key: \(errorMessage)"])
        }

        // Wrap raw PKCS#1 public key in SPKI for standard PEM format
        let spkiData = ASN1Utils.wrapPublicKeyInSPKI(rawKeyData: publicKeyRawData)
        let publicKeyPEM = KeyUtils.toPEM(data: spkiData, header: "PUBLIC KEY")

        return RSAKeyPairResult(publicKey: publicKeyPEM, privateKey: privateKeyPEM)
    }

    // MARK: - Public Key Extraction

    /**
     * Extract the public key from an RSA private key PEM string.
     *
     * Works with both PKCS#1 and PKCS#8 input formats.
     * The returned public key is always in SPKI PEM format ("BEGIN PUBLIC KEY").
     */
    @objc public func getPublicKeyFromPrivate(privateKeyPEM: String) throws -> String {
        // Load private key (handles both PKCS#1 and PKCS#8 automatically)
        let privateSecKey = try KeyUtils.loadPrivateKey(pem: privateKeyPEM)

        guard let publicSecKey = SecKeyCopyPublicKey(privateSecKey) else {
            throw NSError(domain: "RSAKeyGenerator", code: 8,
                          userInfo: [NSLocalizedDescriptionKey: "Could not extract public key"])
        }

        var error: Unmanaged<CFError>?
        guard let publicKeyRawData = SecKeyCopyExternalRepresentation(publicSecKey, &error) as Data? else {
            let errorMessage = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw NSError(domain: "RSAKeyGenerator", code: 9,
                          userInfo: [NSLocalizedDescriptionKey: "Failed to export public key: \(errorMessage)"])
        }

        let spkiData = ASN1Utils.wrapPublicKeyInSPKI(rawKeyData: publicKeyRawData)
        return KeyUtils.toPEM(data: spkiData, header: "PUBLIC KEY")
    }

    // MARK: - Key Format Conversion

    /**
     * Convert a private key PEM between PKCS#1 and PKCS#8 formats.
     *
     * - Parameters:
     *   - pem:          The private key in PEM format
     *   - targetFormat: "pkcs1" or "pkcs8"
     * - Throws: If the PEM format is unrecognized or base64 decoding fails
     * - Returns: The private key re-encoded in the target format
     */
    @objc public func convertPrivateKey(pem: String, targetFormat: String) throws -> String {
        if pem.contains("BEGIN RSA PRIVATE KEY") && targetFormat == "pkcs8" {
            // PKCS#1 → PKCS#8: wrap the raw bytes in a PKCS#8 structure
            let base64 = KeyUtils.extractBase64(from: pem)
            guard let derData = Data(base64Encoded: base64) else {
                throw NSError(domain: "RSAKeyGenerator", code: 10,
                              userInfo: [NSLocalizedDescriptionKey: "Invalid base64 encoding"])
            }
            let pkcs8Data = ASN1Utils.wrapPkcs1InPkcs8(pkcs1Data: derData)
            return KeyUtils.toPEM(data: pkcs8Data, header: "PRIVATE KEY")
        } else if pem.contains("BEGIN PRIVATE KEY") && targetFormat == "pkcs1" {
            // PKCS#8 → PKCS#1: extract the inner PKCS#1 bytes
            let base64 = KeyUtils.extractBase64(from: pem)
            guard let derData = Data(base64Encoded: base64) else {
                throw NSError(domain: "RSAKeyGenerator", code: 11,
                              userInfo: [NSLocalizedDescriptionKey: "Invalid base64 encoding"])
            }
            let pkcs1Data = ASN1Utils.extractPkcs1FromPkcs8(pkcs8Data: derData)
            return KeyUtils.toPEM(data: pkcs1Data, header: "RSA PRIVATE KEY")
        } else if (pem.contains("BEGIN RSA PRIVATE KEY") && targetFormat == "pkcs1") ||
                  (pem.contains("BEGIN PRIVATE KEY") && targetFormat == "pkcs8") {
            // Already in the target format — return unchanged
            return pem
        } else {
            throw NSError(domain: "RSAKeyGenerator", code: 12,
                          userInfo: [NSLocalizedDescriptionKey: "Unrecognized PEM format or unsupported target format"])
        }
    }
}
