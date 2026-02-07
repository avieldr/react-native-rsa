import { VALID_KEY_SIZES } from './constants';

/**
 * Error codes thrown by @avieldr/react-native-rsa.
 *
 * Validation errors (thrown before native call):
 *   - INVALID_INPUT: Required parameter is missing or empty
 *   - INVALID_KEY: Key format is wrong or key type mismatch
 *   - INVALID_KEY_SIZE: Unsupported key size
 *   - INVALID_PADDING: Unknown padding mode
 *   - INVALID_HASH: Unknown hash algorithm
 *   - INVALID_FORMAT: Unknown key format
 *   - INVALID_ENCODING: Unknown encoding type
 *
 * Native operation errors (thrown by platform crypto):
 *   - KEY_GENERATION_FAILED: Native key generation failed
 *   - KEY_EXTRACTION_FAILED: Failed to extract public key from private
 *   - KEY_CONVERSION_FAILED: Failed to convert key format
 *   - ENCRYPTION_FAILED: Native encryption operation failed
 *   - DECRYPTION_FAILED: Native decryption operation failed
 *   - SIGNING_FAILED: Native signing operation failed
 *   - VERIFICATION_FAILED: Native signature verification failed
 */
export type RsaErrorCode =
  // Validation errors
  | 'INVALID_INPUT'
  | 'INVALID_KEY'
  | 'INVALID_KEY_SIZE'
  | 'INVALID_PADDING'
  | 'INVALID_HASH'
  | 'INVALID_FORMAT'
  | 'INVALID_ENCODING'
  // Native operation errors
  | 'KEY_GENERATION_FAILED'
  | 'KEY_EXTRACTION_FAILED'
  | 'KEY_CONVERSION_FAILED'
  | 'ENCRYPTION_FAILED'
  | 'DECRYPTION_FAILED'
  | 'SIGNING_FAILED'
  | 'VERIFICATION_FAILED';

/**
 * Error thrown by @avieldr/react-native-rsa for invalid inputs or native failures.
 * Extends Error with a `code` property for programmatic handling.
 */
export class RsaError extends Error {
  readonly code: RsaErrorCode;
  /** The original error from the native layer, if any */
  readonly cause?: Error;

  constructor(code: RsaErrorCode, message: string, cause?: Error) {
    super(message);
    this.name = 'RsaError';
    this.code = code;
    this.cause = cause;
  }
}

/**
 * Map of native error codes to RsaErrorCode.
 * Native modules reject with codes like "RSAEncryptError" — we normalize them.
 */
const NATIVE_ERROR_CODE_MAP: Record<string, RsaErrorCode> = {
  RSAKeyGenerationError: 'KEY_GENERATION_FAILED',
  RSAKeyExtractionError: 'KEY_EXTRACTION_FAILED',
  RSAConvertKeyError: 'KEY_CONVERSION_FAILED',
  RSAEncryptError: 'ENCRYPTION_FAILED',
  RSADecryptError: 'DECRYPTION_FAILED',
  RSASignError: 'SIGNING_FAILED',
  RSAVerifyError: 'VERIFICATION_FAILED',
};

/**
 * Wrap a native error into an RsaError with a normalized code.
 * If the error is already an RsaError, returns it unchanged.
 */
export function wrapNativeError(error: unknown, fallbackCode: RsaErrorCode): RsaError {
  if (error instanceof RsaError) {
    return error;
  }

  if (error instanceof Error) {
    // React Native errors from native modules have a `code` property
    const nativeCode = (error as { code?: string }).code;
    const code = (nativeCode && NATIVE_ERROR_CODE_MAP[nativeCode]) || fallbackCode;
    return new RsaError(code, error.message, error);
  }

  // Unknown error type
  return new RsaError(fallbackCode, String(error));
}

// --- Validation helpers ---

export function requireString(
  value: unknown,
  name: string
): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new RsaError('INVALID_INPUT', `'${name}' must be a non-empty string`);
  }
}

export function requirePrivateKey(pem: string): void {
  requireString(pem, 'privateKey');
  if (
    pem.includes('BEGIN PUBLIC KEY')
  ) {
    throw new RsaError(
      'INVALID_KEY',
      'Expected a private key (BEGIN RSA PRIVATE KEY or BEGIN PRIVATE KEY), but received a public key'
    );
  }
  if (
    !pem.includes('BEGIN RSA PRIVATE KEY') &&
    !pem.includes('BEGIN PRIVATE KEY')
  ) {
    throw new RsaError(
      'INVALID_KEY',
      'Expected a private key (BEGIN RSA PRIVATE KEY or BEGIN PRIVATE KEY)'
    );
  }
}

export function requirePublicKey(pem: string): void {
  requireString(pem, 'publicKey');
  if (
    pem.includes('BEGIN RSA PRIVATE KEY') ||
    pem.includes('BEGIN PRIVATE KEY')
  ) {
    throw new RsaError(
      'INVALID_KEY',
      'Expected a public key (BEGIN PUBLIC KEY), but received a private key'
    );
  }
  if (!pem.includes('BEGIN PUBLIC KEY')) {
    throw new RsaError(
      'INVALID_KEY',
      'Expected a public key (BEGIN PUBLIC KEY)'
    );
  }
}

export function validateKeySize(keySize: number): void {
  if (!(VALID_KEY_SIZES as readonly number[]).includes(keySize)) {
    throw new RsaError(
      'INVALID_KEY_SIZE',
      `Invalid key size ${keySize}. Supported sizes: ${VALID_KEY_SIZES.join(', ')}`
    );
  }
}

const VALID_ENCRYPTION_PADDINGS = ['oaep', 'pkcs1'];

export function validateEncryptionPadding(padding: string): void {
  if (!VALID_ENCRYPTION_PADDINGS.includes(padding)) {
    throw new RsaError(
      'INVALID_PADDING',
      `Invalid encryption padding '${padding}'. Must be 'oaep' or 'pkcs1'`
    );
  }
}

const VALID_SIGNATURE_PADDINGS = ['pss', 'pkcs1'];

export function validateSignaturePadding(padding: string): void {
  if (!VALID_SIGNATURE_PADDINGS.includes(padding)) {
    throw new RsaError(
      'INVALID_PADDING',
      `Invalid signature padding '${padding}'. Must be 'pss' or 'pkcs1'`
    );
  }
}

const VALID_HASHES = ['sha1', 'sha256', 'sha384', 'sha512'];

export function validateHash(hash: string): void {
  if (!VALID_HASHES.includes(hash)) {
    throw new RsaError(
      'INVALID_HASH',
      `Invalid hash '${hash}'. Must be 'sha1', 'sha256', 'sha384', or 'sha512'`
    );
  }
}

const VALID_KEY_FORMATS = ['pkcs1', 'pkcs8'];

export function validateKeyFormat(format: string): void {
  if (!VALID_KEY_FORMATS.includes(format)) {
    throw new RsaError(
      'INVALID_FORMAT',
      `Invalid key format '${format}'. Must be 'pkcs1' or 'pkcs8'`
    );
  }
}

const VALID_ENCODINGS = ['utf8', 'base64'];

export function validateEncoding(encoding: string): void {
  if (!VALID_ENCODINGS.includes(encoding)) {
    throw new RsaError(
      'INVALID_ENCODING',
      `Invalid encoding '${encoding}'. Must be 'utf8' or 'base64'`
    );
  }
}
