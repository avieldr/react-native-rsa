/**
 * Default values for all RSA operation options.
 *
 * These are applied in `index.ts` when the caller omits an option.
 * Keeping them in one place ensures consistency across encrypt, decrypt, sign, verify.
 */
export const DEFAULTS = {
  /** Default padding for encrypt/decrypt — OAEP is recommended over PKCS#1 */
  ENCRYPTION_PADDING: 'oaep' as const,

  /** Default padding for sign/verify — PSS is recommended over PKCS#1 */
  SIGNATURE_PADDING: 'pss' as const,

  /** Default hash algorithm */
  HASH: 'sha256' as const,

  /** Default input string encoding — UTF-8 text is the common case */
  ENCODING: 'utf8' as const,

  /** Default private key format for key generation */
  KEY_FORMAT: 'pkcs1' as const,
};

/** Supported RSA key sizes in bits */
export const VALID_KEY_SIZES = [1024, 2048, 4096] as const;
