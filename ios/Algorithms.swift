import Foundation
import Security

/**
 * Maps (padding, hash) option strings to `SecKeyAlgorithm` values.
 *
 * This provides a single lookup point so that RSACipher and RSASigner don't
 * need to duplicate algorithm selection logic.
 *
 * Supported combinations:
 *   Encryption (encrypt/decrypt):
 *     - "pkcs1"  → rsaEncryptionPKCS1
 *     - "oaep"   → rsaEncryptionOAEPSHA{N}
 *
 *   Signature (sign/verify):
 *     - "pkcs1"  → rsaSignatureMessagePKCS1v15SHA{N}
 *     - "pss"    → rsaSignatureMessagePSSSHA{N}
 *
 * The "Message" variants (rsaSignatureMessage…) hash the input data internally,
 * so callers pass the raw message — not a pre-computed digest.
 */
enum Algorithms {

    /**
     * Look up the SecKeyAlgorithm for an encrypt/decrypt operation.
     *
     * - Parameters:
     *   - padding: "pkcs1" or "oaep"
     *   - hash:    "sha1", "sha256", "sha384", or "sha512" (only used with OAEP)
     * - Throws: If the padding or hash is unsupported
     */
    static func encryptionAlgorithm(padding: String, hash: String) throws -> SecKeyAlgorithm {
        switch padding {
        case "pkcs1":
            return .rsaEncryptionPKCS1
        case "oaep":
            switch hash {
            case "sha1":   return .rsaEncryptionOAEPSHA1
            case "sha256": return .rsaEncryptionOAEPSHA256
            case "sha384": return .rsaEncryptionOAEPSHA384
            case "sha512": return .rsaEncryptionOAEPSHA512
            default:
                throw NSError(domain: "Algorithms", code: 1,
                              userInfo: [NSLocalizedDescriptionKey: "Unsupported hash for OAEP: \(hash)"])
            }
        default:
            throw NSError(domain: "Algorithms", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "Unsupported encryption padding: \(padding)"])
        }
    }

    /**
     * Look up the SecKeyAlgorithm for a sign/verify operation.
     *
     * - Parameters:
     *   - padding: "pkcs1" or "pss"
     *   - hash:    "sha1", "sha256", "sha384", or "sha512"
     * - Throws: If the padding or hash is unsupported
     */
    static func signatureAlgorithm(padding: String, hash: String) throws -> SecKeyAlgorithm {
        switch padding {
        case "pkcs1":
            // PKCS#1 v1.5 deterministic signatures
            switch hash {
            case "sha1":   return .rsaSignatureMessagePKCS1v15SHA1
            case "sha256": return .rsaSignatureMessagePKCS1v15SHA256
            case "sha384": return .rsaSignatureMessagePKCS1v15SHA384
            case "sha512": return .rsaSignatureMessagePKCS1v15SHA512
            default:
                throw NSError(domain: "Algorithms", code: 3,
                              userInfo: [NSLocalizedDescriptionKey: "Unsupported hash for PKCS#1 signature: \(hash)"])
            }
        case "pss":
            // PSS probabilistic signatures
            switch hash {
            case "sha1":   return .rsaSignatureMessagePSSSHA1
            case "sha256": return .rsaSignatureMessagePSSSHA256
            case "sha384": return .rsaSignatureMessagePSSSHA384
            case "sha512": return .rsaSignatureMessagePSSSHA512
            default:
                throw NSError(domain: "Algorithms", code: 4,
                              userInfo: [NSLocalizedDescriptionKey: "Unsupported hash for PSS signature: \(hash)"])
            }
        default:
            throw NSError(domain: "Algorithms", code: 5,
                          userInfo: [NSLocalizedDescriptionKey: "Unsupported signature padding: \(padding)"])
        }
    }
}
