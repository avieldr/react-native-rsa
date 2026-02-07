import NativeRsa from './NativeRsa';
import { getKeyInfo } from './keyInfo';
import { utf8ToBase64 } from './encoding';
import { DEFAULTS } from './constants';
import {
  requireString,
  requirePrivateKey,
  requirePublicKey,
  validateKeySize,
  validateEncryptionPadding,
  validateSignaturePadding,
  validateHash,
  validateKeyFormat,
  validateEncoding,
  wrapNativeError,
} from './errors';
import type {
  RSAKeyPair,
  GenerateKeyPairOptions,
  KeyFormat,
  EncryptOptions,
  DecryptOptions,
  SignOptions,
  VerifyOptions,
} from './types';

// Re-export all public types
export type {
  RSAKeyPair,
  GenerateKeyPairOptions,
  RSAKeyInfo,
  KeyFormat,
  EncryptOptions,
  DecryptOptions,
  SignOptions,
  VerifyOptions,
  EncryptionPadding,
  SignaturePadding,
  HashAlgorithm,
  InputEncoding,
} from './types';

// Re-export error class, error code type, and utilities that consumers may need
export { RsaError, type RsaErrorCode } from './errors';
export { getKeyInfo } from './keyInfo';
export { utf8ToBase64, base64ToUtf8 } from './encoding';

// --- Key Generation ---

/**
 * Generate an RSA key pair (public + private) using native platform crypto.
 *
 * @param keySize RSA key size in bits. Default: 2048. Supported: 1024, 2048, 4096.
 * @param options Optional configuration (format: 'pkcs1' | 'pkcs8')
 * @returns Object with publicKey and privateKey in PEM format
 * @throws {RsaError} INVALID_KEY_SIZE if keySize is not 1024, 2048, or 4096
 * @throws {RsaError} INVALID_FORMAT if options.format is not 'pkcs1' or 'pkcs8'
 * @throws {RsaError} KEY_GENERATION_FAILED if native key generation fails
 */
async function generateKeyPair(
  keySize: number = 2048,
  options?: GenerateKeyPairOptions
): Promise<RSAKeyPair> {
  validateKeySize(keySize);
  const format = options?.format ?? DEFAULTS.KEY_FORMAT;
  validateKeyFormat(format);

  try {
    return await NativeRsa.generateKeyPair(keySize, format);
  } catch (error) {
    throw wrapNativeError(error, 'KEY_GENERATION_FAILED');
  }
}

/**
 * Extract the public key from an RSA private key PEM string.
 *
 * @param privateKeyPEM RSA private key in PEM format (PKCS#1 or PKCS#8)
 * @returns Public key in PEM format (SPKI/X.509)
 * @throws {RsaError} INVALID_INPUT if privateKeyPEM is empty
 * @throws {RsaError} INVALID_KEY if privateKeyPEM is not a valid private key
 * @throws {RsaError} KEY_EXTRACTION_FAILED if native operation fails
 */
async function getPublicKeyFromPrivate(
  privateKeyPEM: string
): Promise<string> {
  requirePrivateKey(privateKeyPEM);

  try {
    return await NativeRsa.getPublicKeyFromPrivate(privateKeyPEM);
  } catch (error) {
    throw wrapNativeError(error, 'KEY_EXTRACTION_FAILED');
  }
}

// --- Encrypt / Decrypt ---

/**
 * Encrypt plaintext with an RSA public key.
 *
 * The input string is UTF-8 encoded to base64 by default before sending to native.
 * Set `options.encoding = 'base64'` if the input is already base64-encoded binary.
 *
 * @param data         The plaintext to encrypt (UTF-8 string or base64, depending on encoding option)
 * @param publicKeyPEM The public key in SPKI PEM format
 * @param options      Padding, hash, and encoding options (defaults: oaep, sha256, utf8)
 * @returns Base64-encoded ciphertext
 * @throws {RsaError} INVALID_INPUT if data or publicKeyPEM is empty
 * @throws {RsaError} INVALID_KEY if publicKeyPEM is not a valid public key
 * @throws {RsaError} INVALID_PADDING if options.padding is invalid
 * @throws {RsaError} INVALID_HASH if options.hash is invalid
 * @throws {RsaError} INVALID_ENCODING if options.encoding is invalid
 * @throws {RsaError} ENCRYPTION_FAILED if native encryption fails
 */
async function encrypt(
  data: string,
  publicKeyPEM: string,
  options?: EncryptOptions
): Promise<string> {
  requireString(data, 'data');
  requirePublicKey(publicKeyPEM);

  const padding = options?.padding ?? DEFAULTS.ENCRYPTION_PADDING;
  const hash = options?.hash ?? DEFAULTS.HASH;
  const encoding = options?.encoding ?? DEFAULTS.ENCODING;

  validateEncryptionPadding(padding);
  validateHash(hash);
  validateEncoding(encoding);

  // Convert UTF-8 text to base64 for the native bridge; pass through if already base64
  const dataBase64 = encoding === 'utf8' ? utf8ToBase64(data) : data;

  try {
    return await NativeRsa.encrypt(dataBase64, publicKeyPEM, padding, hash);
  } catch (error) {
    throw wrapNativeError(error, 'ENCRYPTION_FAILED');
  }
}

/**
 * Decrypt ciphertext with an RSA private key.
 *
 * Always returns base64-encoded plaintext. If the original data was UTF-8 text,
 * use `base64ToUtf8()` to decode the result.
 *
 * @param encrypted    Base64-encoded ciphertext (from encrypt())
 * @param privateKeyPEM The private key in PEM format (PKCS#1 or PKCS#8)
 * @param options      Padding and hash options — must match what was used for encryption
 * @returns Base64-encoded decrypted plaintext
 * @throws {RsaError} INVALID_INPUT if encrypted or privateKeyPEM is empty
 * @throws {RsaError} INVALID_KEY if privateKeyPEM is not a valid private key
 * @throws {RsaError} INVALID_PADDING if options.padding is invalid
 * @throws {RsaError} INVALID_HASH if options.hash is invalid
 * @throws {RsaError} DECRYPTION_FAILED if native decryption fails
 */
async function decrypt(
  encrypted: string,
  privateKeyPEM: string,
  options?: DecryptOptions
): Promise<string> {
  requireString(encrypted, 'encrypted');
  requirePrivateKey(privateKeyPEM);

  const padding = options?.padding ?? DEFAULTS.ENCRYPTION_PADDING;
  const hash = options?.hash ?? DEFAULTS.HASH;

  validateEncryptionPadding(padding);
  validateHash(hash);

  try {
    return await NativeRsa.decrypt(encrypted, privateKeyPEM, padding, hash);
  } catch (error) {
    throw wrapNativeError(error, 'DECRYPTION_FAILED');
  }
}

// --- Sign / Verify ---

/**
 * Sign data with an RSA private key.
 *
 * The input string is UTF-8 encoded to base64 by default before sending to native.
 * Set `options.encoding = 'base64'` if the input is already base64-encoded binary.
 *
 * @param data         The data to sign (UTF-8 string or base64, depending on encoding option)
 * @param privateKeyPEM The private key in PEM format (PKCS#1 or PKCS#8)
 * @param options      Padding, hash, and encoding options (defaults: pss, sha256, utf8)
 * @returns Base64-encoded signature
 * @throws {RsaError} INVALID_INPUT if data or privateKeyPEM is empty
 * @throws {RsaError} INVALID_KEY if privateKeyPEM is not a valid private key
 * @throws {RsaError} INVALID_PADDING if options.padding is invalid
 * @throws {RsaError} INVALID_HASH if options.hash is invalid
 * @throws {RsaError} INVALID_ENCODING if options.encoding is invalid
 * @throws {RsaError} SIGNING_FAILED if native signing fails
 */
async function sign(
  data: string,
  privateKeyPEM: string,
  options?: SignOptions
): Promise<string> {
  requireString(data, 'data');
  requirePrivateKey(privateKeyPEM);

  const padding = options?.padding ?? DEFAULTS.SIGNATURE_PADDING;
  const hash = options?.hash ?? DEFAULTS.HASH;
  const encoding = options?.encoding ?? DEFAULTS.ENCODING;

  validateSignaturePadding(padding);
  validateHash(hash);
  validateEncoding(encoding);

  const dataBase64 = encoding === 'utf8' ? utf8ToBase64(data) : data;

  try {
    return await NativeRsa.sign(dataBase64, privateKeyPEM, padding, hash);
  } catch (error) {
    throw wrapNativeError(error, 'SIGNING_FAILED');
  }
}

/**
 * Verify a signature against data using an RSA public key.
 *
 * The input string encoding must match what was used during signing.
 *
 * @param data         The original data that was signed
 * @param signature    Base64-encoded signature (from sign())
 * @param publicKeyPEM The public key in SPKI PEM format
 * @param options      Padding, hash, and encoding options — must match signing options
 * @returns true if the signature is valid, false otherwise
 * @throws {RsaError} INVALID_INPUT if data, signature, or publicKeyPEM is empty
 * @throws {RsaError} INVALID_KEY if publicKeyPEM is not a valid public key
 * @throws {RsaError} INVALID_PADDING if options.padding is invalid
 * @throws {RsaError} INVALID_HASH if options.hash is invalid
 * @throws {RsaError} INVALID_ENCODING if options.encoding is invalid
 * @throws {RsaError} VERIFICATION_FAILED if native verification fails
 */
async function verify(
  data: string,
  signature: string,
  publicKeyPEM: string,
  options?: VerifyOptions
): Promise<boolean> {
  requireString(data, 'data');
  requireString(signature, 'signature');
  requirePublicKey(publicKeyPEM);

  const padding = options?.padding ?? DEFAULTS.SIGNATURE_PADDING;
  const hash = options?.hash ?? DEFAULTS.HASH;
  const encoding = options?.encoding ?? DEFAULTS.ENCODING;

  validateSignaturePadding(padding);
  validateHash(hash);
  validateEncoding(encoding);

  const dataBase64 = encoding === 'utf8' ? utf8ToBase64(data) : data;

  try {
    return await NativeRsa.verify(dataBase64, signature, publicKeyPEM, padding, hash);
  } catch (error) {
    throw wrapNativeError(error, 'VERIFICATION_FAILED');
  }
}

// --- Key Format Conversion ---

/**
 * Convert a private key PEM between PKCS#1 and PKCS#8 formats.
 *
 * @param pem          The private key in PEM format
 * @param targetFormat 'pkcs1' or 'pkcs8'
 * @returns The private key re-encoded in the target format
 * @throws {RsaError} INVALID_INPUT if pem is empty
 * @throws {RsaError} INVALID_KEY if pem is not a valid private key
 * @throws {RsaError} INVALID_FORMAT if targetFormat is invalid
 * @throws {RsaError} KEY_CONVERSION_FAILED if native conversion fails
 */
async function convertPrivateKey(
  pem: string,
  targetFormat: KeyFormat
): Promise<string> {
  requirePrivateKey(pem);
  validateKeyFormat(targetFormat);

  try {
    return await NativeRsa.convertPrivateKey(pem, targetFormat);
  } catch (error) {
    throw wrapNativeError(error, 'KEY_CONVERSION_FAILED');
  }
}

// --- Default Export ---

const RSA = {
  generateKeyPair,
  getPublicKeyFromPrivate,
  getKeyInfo,
  encrypt,
  decrypt,
  sign,
  verify,
  convertPrivateKey,
};
export default RSA;
