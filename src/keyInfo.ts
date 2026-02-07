import type { RSAKeyInfo } from './types';

const PEM_HEADERS = {
  pkcs1Private: '-----BEGIN RSA PRIVATE KEY-----',
  pkcs1PrivateEnd: '-----END RSA PRIVATE KEY-----',
  pkcs8Private: '-----BEGIN PRIVATE KEY-----',
  pkcs8PrivateEnd: '-----END PRIVATE KEY-----',
  public: '-----BEGIN PUBLIC KEY-----',
  publicEnd: '-----END PUBLIC KEY-----',
};

function parseASN1Length(
  bytes: Uint8Array,
  offset: number
): { length: number | null; bytesRead: number } {
  if (offset >= bytes.length) {
    return { length: null, bytesRead: 0 };
  }
  const firstByte = bytes[offset]!;
  if (firstByte < 128) {
    return { length: firstByte, bytesRead: 1 };
  }
  const numLengthBytes = firstByte & 0x7f;
  if (numLengthBytes === 0 || offset + numLengthBytes >= bytes.length) {
    return { length: null, bytesRead: 0 };
  }
  let length = 0;
  for (let i = 0; i < numLengthBytes; i++) {
    length = (length << 8) | bytes[offset + 1 + i]!;
  }
  return { length, bytesRead: 1 + numLengthBytes };
}

function validatePKCS1Structure(derBytes: Uint8Array): string[] {
  const errors: string[] = [];
  let offset = 0;

  if (derBytes[offset] !== 0x30) {
    errors.push(
      `Expected SEQUENCE tag (0x30), got 0x${derBytes[offset]?.toString(16)}`
    );
    return errors;
  }
  offset++;

  const { length: seqLength, bytesRead } = parseASN1Length(derBytes, offset);
  offset += bytesRead;

  if (seqLength === null) {
    errors.push('Invalid SEQUENCE length encoding');
    return errors;
  }

  let integerCount = 0;
  let tempOffset = offset;
  const endOffset = offset + seqLength;

  while (tempOffset < endOffset && tempOffset < derBytes.length) {
    if (derBytes[tempOffset] !== 0x02) {
      errors.push(
        `Expected INTEGER tag (0x02) at position ${tempOffset}, got 0x${derBytes[tempOffset]?.toString(16)}`
      );
      break;
    }
    tempOffset++;
    const { length: intLength, bytesRead: intBytesRead } = parseASN1Length(
      derBytes,
      tempOffset
    );
    if (intLength === null) {
      errors.push('Invalid INTEGER length encoding');
      break;
    }
    tempOffset += intBytesRead + intLength;
    integerCount++;
  }

  if (integerCount !== 9) {
    errors.push(
      `Expected 9 INTEGER fields for PKCS#1, found ${integerCount}`
    );
  }
  return errors;
}

function validatePKCS8Structure(derBytes: Uint8Array): string[] {
  const errors: string[] = [];
  let offset = 0;

  // Outer SEQUENCE
  if (derBytes[offset] !== 0x30) {
    errors.push(
      `Expected SEQUENCE tag (0x30), got 0x${derBytes[offset]?.toString(16)}`
    );
    return errors;
  }
  offset++;
  const { length: seqLength, bytesRead } = parseASN1Length(derBytes, offset);
  offset += bytesRead;
  if (seqLength === null) {
    errors.push('Invalid SEQUENCE length encoding');
    return errors;
  }

  const endOffset = offset + seqLength;

  // version INTEGER (should be 0)
  if (offset >= endOffset || derBytes[offset] !== 0x02) {
    errors.push(
      `Expected INTEGER tag (0x02) for version, got 0x${derBytes[offset]?.toString(16)}`
    );
    return errors;
  }
  offset++;
  const { length: verLen, bytesRead: verBytesRead } = parseASN1Length(
    derBytes,
    offset
  );
  if (verLen === null) {
    errors.push('Invalid version INTEGER length');
    return errors;
  }
  offset += verBytesRead + verLen;

  // AlgorithmIdentifier SEQUENCE
  if (offset >= endOffset || derBytes[offset] !== 0x30) {
    errors.push(
      `Expected SEQUENCE tag (0x30) for AlgorithmIdentifier, got 0x${derBytes[offset]?.toString(16)}`
    );
    return errors;
  }
  offset++;
  const { length: algLen, bytesRead: algBytesRead } = parseASN1Length(
    derBytes,
    offset
  );
  if (algLen === null) {
    errors.push('Invalid AlgorithmIdentifier length');
    return errors;
  }
  offset += algBytesRead + algLen;

  // privateKey OCTET STRING
  if (offset >= endOffset || derBytes[offset] !== 0x04) {
    errors.push(
      `Expected OCTET STRING tag (0x04) for privateKey, got 0x${derBytes[offset]?.toString(16)}`
    );
    return errors;
  }

  return errors;
}

function validateSPKIStructure(derBytes: Uint8Array): string[] {
  const errors: string[] = [];
  let offset = 0;

  // Outer SEQUENCE
  if (derBytes[offset] !== 0x30) {
    errors.push(
      `Expected SEQUENCE tag (0x30), got 0x${derBytes[offset]?.toString(16)}`
    );
    return errors;
  }
  offset++;
  const { length: seqLength, bytesRead } = parseASN1Length(derBytes, offset);
  offset += bytesRead;
  if (seqLength === null) {
    errors.push('Invalid SEQUENCE length encoding');
    return errors;
  }

  const endOffset = offset + seqLength;

  // AlgorithmIdentifier SEQUENCE
  if (offset >= endOffset || derBytes[offset] !== 0x30) {
    errors.push(
      `Expected SEQUENCE tag (0x30) for AlgorithmIdentifier, got 0x${derBytes[offset]?.toString(16)}`
    );
    return errors;
  }
  offset++;
  const { length: algLen, bytesRead: algBytesRead } = parseASN1Length(
    derBytes,
    offset
  );
  if (algLen === null) {
    errors.push('Invalid AlgorithmIdentifier length');
    return errors;
  }
  offset += algBytesRead + algLen;

  // subjectPublicKey BIT STRING
  if (offset >= endOffset || derBytes[offset] !== 0x03) {
    errors.push(
      `Expected BIT STRING tag (0x03) for subjectPublicKey, got 0x${derBytes[offset]?.toString(16)}`
    );
    return errors;
  }

  return errors;
}

// Minimal base64 decoder (no external deps)
const BASE64_CHARS =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

function base64Decode(input: string): Uint8Array {
  const cleaned = input.replace(/[^A-Za-z0-9+/=]/g, '');
  const len = cleaned.length;
  const byteLen = (len * 3) / 4 - (cleaned.endsWith('==') ? 2 : cleaned.endsWith('=') ? 1 : 0);
  const bytes = new Uint8Array(byteLen);
  let p = 0;

  for (let i = 0; i < len; i += 4) {
    const a = BASE64_CHARS.indexOf(cleaned[i]!);
    const b = BASE64_CHARS.indexOf(cleaned[i + 1]!);
    const c = cleaned[i + 2] === '=' ? 0 : BASE64_CHARS.indexOf(cleaned[i + 2]!);
    const d = cleaned[i + 3] === '=' ? 0 : BASE64_CHARS.indexOf(cleaned[i + 3]!);

    const bits = (a << 18) | (b << 12) | (c << 6) | d;

    if (p < byteLen) bytes[p++] = (bits >> 16) & 0xff;
    if (p < byteLen) bytes[p++] = (bits >> 8) & 0xff;
    if (p < byteLen) bytes[p++] = bits & 0xff;
  }
  return bytes;
}

/**
 * Analyze an RSA key PEM string and return metadata about it.
 * Runs entirely in JS — no native bridge call needed.
 */
export function getKeyInfo(keyString: string): RSAKeyInfo {
  const errors: string[] = [];
  let format: RSAKeyInfo['format'] = 'unknown';
  let keyType: RSAKeyInfo['keyType'] = 'unknown';
  let base64Content = '';
  let base64Lines: string[] = [];

  if (
    keyString.includes(PEM_HEADERS.pkcs1Private) &&
    keyString.includes(PEM_HEADERS.pkcs1PrivateEnd)
  ) {
    format = 'pkcs1';
    keyType = 'private';
    const start =
      keyString.indexOf(PEM_HEADERS.pkcs1Private) +
      PEM_HEADERS.pkcs1Private.length;
    const end = keyString.indexOf(PEM_HEADERS.pkcs1PrivateEnd);
    const raw = keyString.substring(start, end).trim();
    base64Lines = raw
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    base64Content = raw.replace(/\s/g, '');
  } else if (
    keyString.includes(PEM_HEADERS.pkcs8Private) &&
    keyString.includes(PEM_HEADERS.pkcs8PrivateEnd)
  ) {
    format = 'pkcs8';
    keyType = 'private';
    const start =
      keyString.indexOf(PEM_HEADERS.pkcs8Private) +
      PEM_HEADERS.pkcs8Private.length;
    const end = keyString.indexOf(PEM_HEADERS.pkcs8PrivateEnd);
    const raw = keyString.substring(start, end).trim();
    base64Lines = raw
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    base64Content = raw.replace(/\s/g, '');
  } else if (
    keyString.includes(PEM_HEADERS.public) &&
    keyString.includes(PEM_HEADERS.publicEnd)
  ) {
    format = 'public';
    keyType = 'public';
    const start =
      keyString.indexOf(PEM_HEADERS.public) + PEM_HEADERS.public.length;
    const end = keyString.indexOf(PEM_HEADERS.publicEnd);
    const raw = keyString.substring(start, end).trim();
    base64Lines = raw
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l.length > 0);
    base64Content = raw.replace(/\s/g, '');
  } else {
    errors.push('Missing or invalid PEM headers');
  }

  // Validate line formatting (PEM standard: 64 chars per line)
  if (base64Lines.length > 0) {
    for (let i = 0; i < base64Lines.length - 1; i++) {
      if (base64Lines[i]!.length !== 64) {
        errors.push(
          `Line ${i + 1} has ${base64Lines[i]!.length} chars, expected 64`
        );
        break;
      }
    }
    const lastLine = base64Lines[base64Lines.length - 1]!;
    if (lastLine.length > 64) {
      errors.push(`Last line has ${lastLine.length} chars, expected <= 64`);
    }
  }

  // Decode and validate structure
  let derBytes: Uint8Array | null = null;
  if (base64Content.length > 0) {
    try {
      derBytes = base64Decode(base64Content);
    } catch {
      errors.push('Invalid base64 encoding');
    }
  }

  if (derBytes && format === 'pkcs1') {
    errors.push(...validatePKCS1Structure(derBytes));
  } else if (derBytes && format === 'pkcs8') {
    errors.push(...validatePKCS8Structure(derBytes));
  } else if (derBytes && format === 'public') {
    errors.push(...validateSPKIStructure(derBytes));
  }

  return {
    isValid: errors.length === 0,
    format,
    keyType,
    pemLineCount: base64Lines.length,
    derByteLength: derBytes?.length ?? 0,
    errors,
  };
}
