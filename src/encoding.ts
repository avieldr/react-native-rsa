/**
 * Pure-JS UTF-8 ↔ Base64 encoding utilities.
 *
 * These work in all React Native JS engines (Hermes, JSC) without
 * external dependencies. They handle full Unicode including surrogate pairs.
 *
 * Used by the public API to convert UTF-8 input strings to base64
 * before sending them across the native bridge.
 */

const BASE64_CHARS =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * Encode a UTF-8 string to base64.
 *
 * Steps:
 *   1. Convert the JS string (UTF-16) to UTF-8 byte values
 *   2. Encode those bytes as base64
 *
 * Handles multi-byte characters and surrogate pairs correctly.
 */
export function utf8ToBase64(str: string): string {
  // Step 1: UTF-16 string → UTF-8 byte array
  const bytes: number[] = [];
  for (let i = 0; i < str.length; i++) {
    let codePoint = str.codePointAt(i)!;
    // Skip the low surrogate of a surrogate pair (codePointAt already decoded it)
    if (codePoint > 0xffff) {
      i++;
    }

    if (codePoint < 0x80) {
      // 1-byte: ASCII (0xxxxxxx)
      bytes.push(codePoint);
    } else if (codePoint < 0x800) {
      // 2-byte: (110xxxxx 10xxxxxx)
      bytes.push(0xc0 | (codePoint >> 6), 0x80 | (codePoint & 0x3f));
    } else if (codePoint < 0x10000) {
      // 3-byte: (1110xxxx 10xxxxxx 10xxxxxx)
      bytes.push(
        0xe0 | (codePoint >> 12),
        0x80 | ((codePoint >> 6) & 0x3f),
        0x80 | (codePoint & 0x3f)
      );
    } else {
      // 4-byte: (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx) — for emoji, etc.
      bytes.push(
        0xf0 | (codePoint >> 18),
        0x80 | ((codePoint >> 12) & 0x3f),
        0x80 | ((codePoint >> 6) & 0x3f),
        0x80 | (codePoint & 0x3f)
      );
    }
  }

  // Step 2: Byte array → Base64 string (3 bytes per group → 4 base64 chars)
  let result = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i]!;
    const b = i + 1 < bytes.length ? bytes[i + 1]! : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2]! : 0;

    result += BASE64_CHARS[a >> 2];
    result += BASE64_CHARS[((a & 3) << 4) | (b >> 4)];
    result +=
      i + 1 < bytes.length ? BASE64_CHARS[((b & 0xf) << 2) | (c >> 6)] : '=';
    result += i + 2 < bytes.length ? BASE64_CHARS[c & 0x3f] : '=';
  }
  return result;
}

/**
 * Decode a base64 string to a UTF-8 string.
 *
 * Steps:
 *   1. Decode base64 → raw byte values
 *   2. Interpret those bytes as UTF-8 and build a JS string
 *
 * Useful for reading decrypted plaintext that was originally UTF-8 text.
 */
export function base64ToUtf8(base64: string): string {
  // Step 1: Base64 string → byte array
  const cleaned = base64.replace(/[^A-Za-z0-9+/=]/g, '');
  const bytes: number[] = [];
  for (let i = 0; i < cleaned.length; i += 4) {
    const a = BASE64_CHARS.indexOf(cleaned[i]!);
    const b = BASE64_CHARS.indexOf(cleaned[i + 1]!);
    const c =
      cleaned[i + 2] === '=' ? 0 : BASE64_CHARS.indexOf(cleaned[i + 2]!);
    const d =
      cleaned[i + 3] === '=' ? 0 : BASE64_CHARS.indexOf(cleaned[i + 3]!);

    const bits = (a << 18) | (b << 12) | (c << 6) | d;
    bytes.push((bits >> 16) & 0xff);
    if (cleaned[i + 2] !== '=') {
      bytes.push((bits >> 8) & 0xff);
    }
    if (cleaned[i + 3] !== '=') {
      bytes.push(bits & 0xff);
    }
  }

  // Step 2: UTF-8 byte array → JS string
  let str = '';
  let idx = 0;
  while (idx < bytes.length) {
    const byte = bytes[idx]!;
    if (byte < 0x80) {
      // 1-byte: ASCII
      str += String.fromCodePoint(byte);
      idx++;
    } else if ((byte & 0xe0) === 0xc0) {
      // 2-byte character
      str += String.fromCodePoint(
        ((byte & 0x1f) << 6) | (bytes[idx + 1]! & 0x3f)
      );
      idx += 2;
    } else if ((byte & 0xf0) === 0xe0) {
      // 3-byte character
      str += String.fromCodePoint(
        ((byte & 0x0f) << 12) |
          ((bytes[idx + 1]! & 0x3f) << 6) |
          (bytes[idx + 2]! & 0x3f)
      );
      idx += 3;
    } else {
      // 4-byte character (emoji, etc.)
      const codePoint =
        ((byte & 0x07) << 18) |
        ((bytes[idx + 1]! & 0x3f) << 12) |
        ((bytes[idx + 2]! & 0x3f) << 6) |
        (bytes[idx + 3]! & 0x3f);
      str += String.fromCodePoint(codePoint);
      idx += 4;
    }
  }
  return str;
}
