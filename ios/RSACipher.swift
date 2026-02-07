import Foundation
import Security

/**
 * RSA encryption and decryption operations for iOS.
 *
 * Uses the Security framework's `SecKeyCreateEncryptedData` / `SecKeyCreateDecryptedData`.
 * All data crosses the bridge as base64 strings to avoid binary encoding issues.
 *
 * Supported padding modes:
 *   - "oaep"  — OAEP (Optimal Asymmetric Encryption Padding) with configurable hash
 *   - "pkcs1" — PKCS#1 v1.5 padding (legacy, not recommended for new applications)
 *
 * Exposed to Objective-C via `@objc` for the React Native bridge.
 */
@objc public class RSACipher: NSObject {

    /**
     * Encrypt data with an RSA public key.
     *
     * - Parameters:
     *   - dataBase64:   The plaintext data encoded as base64
     *   - publicKeyPEM: The public key in SPKI PEM format ("BEGIN PUBLIC KEY")
     *   - padding:      "oaep" or "pkcs1"
     *   - hash:         "sha256", "sha1", "sha384", or "sha512" (used with OAEP)
     * - Throws: If the input is invalid, key loading fails, or encryption fails
     * - Returns: The ciphertext encoded as base64
     */
    @objc public static func encrypt(dataBase64: String, publicKeyPEM: String, padding: String, hash: String) throws -> String {
        guard let data = Data(base64Encoded: dataBase64) else {
            throw NSError(domain: "RSACipher", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "Invalid base64 input data"])
        }

        let publicKey = try KeyUtils.loadPublicKey(pem: publicKeyPEM)
        let algorithm = try Algorithms.encryptionAlgorithm(padding: padding, hash: hash)

        var error: Unmanaged<CFError>?
        guard let encryptedData = SecKeyCreateEncryptedData(publicKey, algorithm, data as CFData, &error) as Data? else {
            let errorMessage = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw NSError(domain: "RSACipher", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "Encryption failed: \(errorMessage)"])
        }

        return encryptedData.base64EncodedString()
    }

    /**
     * Decrypt data with an RSA private key.
     *
     * - Parameters:
     *   - dataBase64:    The ciphertext encoded as base64
     *   - privateKeyPEM: The private key in PEM format (PKCS#1 or PKCS#8)
     *   - padding:       "oaep" or "pkcs1" — must match the padding used during encryption
     *   - hash:          "sha256", "sha1", "sha384", or "sha512" — must match encryption hash
     * - Throws: If the input is invalid, key loading fails, or decryption fails
     * - Returns: The decrypted plaintext encoded as base64
     */
    @objc public static func decrypt(dataBase64: String, privateKeyPEM: String, padding: String, hash: String) throws -> String {
        guard let data = Data(base64Encoded: dataBase64) else {
            throw NSError(domain: "RSACipher", code: 3,
                          userInfo: [NSLocalizedDescriptionKey: "Invalid base64 input data"])
        }

        let privateKey = try KeyUtils.loadPrivateKey(pem: privateKeyPEM)
        let algorithm = try Algorithms.encryptionAlgorithm(padding: padding, hash: hash)

        var error: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(privateKey, algorithm, data as CFData, &error) as Data? else {
            let errorMessage = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw NSError(domain: "RSACipher", code: 4,
                          userInfo: [NSLocalizedDescriptionKey: "Decryption failed: \(errorMessage)"])
        }

        return decryptedData.base64EncodedString()
    }
}
