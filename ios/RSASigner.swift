import Foundation
import Security

/**
 * RSA signing and verification operations for iOS.
 *
 * Uses the Security framework's `SecKeyCreateSignature` / `SecKeyVerifySignature`.
 * All data crosses the bridge as base64 strings to avoid binary encoding issues.
 *
 * Supported padding modes:
 *   - "pss"   — PSS (Probabilistic Signature Scheme) with configurable hash
 *   - "pkcs1" — PKCS#1 v1.5 deterministic signatures
 *
 * The "Message" algorithm variants are used (e.g. `rsaSignatureMessagePSSSHA256`),
 * meaning the Security framework hashes the input internally — callers pass the raw message.
 *
 * Exposed to Objective-C via `@objc` for the React Native bridge.
 */
@objc public class RSASigner: NSObject {

    /**
     * Sign data with an RSA private key.
     *
     * - Parameters:
     *   - dataBase64:    The data to sign, encoded as base64
     *   - privateKeyPEM: The private key in PEM format (PKCS#1 or PKCS#8)
     *   - padding:       "pss" or "pkcs1"
     *   - hash:          "sha256", "sha1", "sha384", or "sha512"
     * - Throws: If the input is invalid, key loading fails, or signing fails
     * - Returns: The signature encoded as base64
     */
    @objc public static func sign(dataBase64: String, privateKeyPEM: String, padding: String, hash: String) throws -> String {
        guard let data = Data(base64Encoded: dataBase64) else {
            throw NSError(domain: "RSASigner", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "Invalid base64 input data"])
        }

        let privateKey = try KeyUtils.loadPrivateKey(pem: privateKeyPEM)
        let algorithm = try Algorithms.signatureAlgorithm(padding: padding, hash: hash)

        var error: Unmanaged<CFError>?
        guard let signatureData = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) as Data? else {
            let errorMessage = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            throw NSError(domain: "RSASigner", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "Signing failed: \(errorMessage)"])
        }

        return signatureData.base64EncodedString()
    }

    /**
     * Verify a signature against data using an RSA public key.
     *
     * - Parameters:
     *   - dataBase64:      The original data that was signed, encoded as base64
     *   - signatureBase64: The signature to verify, encoded as base64
     *   - publicKeyPEM:    The public key in SPKI PEM format ("BEGIN PUBLIC KEY")
     *   - padding:         "pss" or "pkcs1" — must match the padding used during signing
     *   - hash:            "sha256", "sha1", "sha384", or "sha512" — must match signing hash
     * - Throws: If the input is invalid or key loading fails
     * - Returns: true if the signature is valid, false otherwise
     *
     * Returns NSNumber (not Bool) because Swift `@objc throws -> Bool` is not
     * allowed — throwing methods must return Void or an Objective-C class type.
     */
    @objc public static func verify(dataBase64: String, signatureBase64: String, publicKeyPEM: String, padding: String, hash: String) throws -> NSNumber {
        guard let data = Data(base64Encoded: dataBase64) else {
            throw NSError(domain: "RSASigner", code: 3,
                          userInfo: [NSLocalizedDescriptionKey: "Invalid base64 input data"])
        }
        guard let signatureData = Data(base64Encoded: signatureBase64) else {
            throw NSError(domain: "RSASigner", code: 4,
                          userInfo: [NSLocalizedDescriptionKey: "Invalid base64 signature"])
        }

        let publicKey = try KeyUtils.loadPublicKey(pem: publicKeyPEM)
        let algorithm = try Algorithms.signatureAlgorithm(padding: padding, hash: hash)

        // SecKeyVerifySignature returns true for valid signatures, false otherwise.
        // IMPORTANT: On iOS, it also sets *error for invalid signatures (errSecVerifyFailed = -67808).
        // We must distinguish between "invalid signature" (return false) and "actual error"
        // (bad key type, unsupported algorithm, etc.) by checking the error code.
        var error: Unmanaged<CFError>?
        let result = SecKeyVerifySignature(publicKey, algorithm, data as CFData, signatureData as CFData, &error)

        if !result, let cfError = error?.takeRetainedValue() {
            let nsError = cfError as Error as NSError
            // errSecVerifyFailed (-67808) means "signature doesn't match" — not an actual error.
            // Return false for this case; only throw for unexpected failures.
            if nsError.domain == NSOSStatusErrorDomain && nsError.code == Int(errSecVerifyFailed) {
                return NSNumber(value: false)
            }
            throw NSError(domain: "RSASigner", code: 5,
                          userInfo: [NSLocalizedDescriptionKey: "Verification error: \(cfError.localizedDescription)"])
        }

        return NSNumber(value: result)
    }
}
