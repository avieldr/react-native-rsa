// --- Key Format Types ---

/** Private key encoding format */
export type KeyFormat = 'pkcs1' | 'pkcs8';

// --- Crypto Option Types ---

/** Padding mode for encrypt/decrypt operations */
export type EncryptionPadding = 'oaep' | 'pkcs1';

/** Padding mode for sign/verify operations */
export type SignaturePadding = 'pss' | 'pkcs1';

/** Hash algorithm used for padding schemes */
export type HashAlgorithm = 'sha256' | 'sha1' | 'sha384' | 'sha512';

/**
 * Controls how the JS input string is interpreted before sending to native.
 *   - 'utf8':   the string is UTF-8 text (will be encoded to base64 before bridging)
 *   - 'base64': the string is already base64-encoded binary data
 */
export type InputEncoding = 'utf8' | 'base64';

// --- Key Generation Types ---

export interface GenerateKeyPairOptions {
  /** Output format for the private key. Default: 'pkcs1' */
  format?: KeyFormat;
}

export interface RSAKeyPair {
  /** Public key in PEM format (SPKI/X.509) */
  publicKey: string;
  /** Private key in PEM format (PKCS#1 or PKCS#8 depending on options) */
  privateKey: string;
}

// --- Key Info Types ---

export interface RSAKeyInfo {
  isValid: boolean;
  format: 'pkcs1' | 'pkcs8' | 'public' | 'unknown';
  keyType: 'private' | 'public' | 'unknown';
  pemLineCount: number;
  derByteLength: number;
  errors: string[];
}

// --- Encrypt / Decrypt Options ---

export interface EncryptOptions {
  /** Padding mode. Default: 'oaep' */
  padding?: EncryptionPadding;
  /** Hash algorithm (used with OAEP). Default: 'sha256' */
  hash?: HashAlgorithm;
  /** How to interpret the input string. Default: 'utf8' */
  encoding?: InputEncoding;
}

export interface DecryptOptions {
  /** Padding mode — must match encryption. Default: 'oaep' */
  padding?: EncryptionPadding;
  /** Hash algorithm — must match encryption. Default: 'sha256' */
  hash?: HashAlgorithm;
}

// --- Sign / Verify Options ---

export interface SignOptions {
  /** Padding mode. Default: 'pss' */
  padding?: SignaturePadding;
  /** Hash algorithm. Default: 'sha256' */
  hash?: HashAlgorithm;
  /** How to interpret the input string. Default: 'utf8' */
  encoding?: InputEncoding;
}

export interface VerifyOptions {
  /** Padding mode — must match signing. Default: 'pss' */
  padding?: SignaturePadding;
  /** Hash algorithm — must match signing. Default: 'sha256' */
  hash?: HashAlgorithm;
  /** How to interpret the input string. Default: 'utf8' */
  encoding?: InputEncoding;
}
