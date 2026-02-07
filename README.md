# @avieldr/react-native-rsa

High-performance native RSA cryptography for React Native. Uses platform-native crypto libraries (Android `KeyPairGenerator`, iOS `Security` framework) for fast, secure operations.

## Features

- **Native RSA key generation** on both iOS and Android
- **Encrypt/Decrypt** with OAEP or PKCS#1 padding
- **Sign/Verify** with PSS or PKCS#1 padding
- **Key sizes**: 1024, 2048, 4096 bit
- **Hash algorithms**: SHA-1, SHA-256, SHA-384, SHA-512
- **Output formats**: PKCS#1 and PKCS#8 (private key), SPKI/X.509 (public key)
- **Key format conversion** between PKCS#1 and PKCS#8
- **Public key extraction** from private key
- **Key validation** (JS-only, no bridge call)
- **Turbo Module** (New Architecture required)

## Why This Package?

### Performance

Uses platform-native crypto APIs (`KeyPairGenerator` on Android, `Security.framework` on iOS) instead of JavaScript implementations or slow bridge calls:

| Operation       | Native (this package) |
| --------------- | --------------------- |
| 2048-bit keygen | ~200ms                |
| Encrypt/Decrypt | < 10ms                |
| Sign/Verify     | < 10ms                |

> Note: Pure JS implementations are significantly less efficient for RSA operations.

### Security

- Uses **OS-hardened cryptographic APIs** — battle-tested implementations maintained by Apple and Google
- No bundled crypto libraries that could become outdated or vulnerable
- Supports modern padding schemes (OAEP, PSS) recommended by security standards

### Lightweight

Zero runtime dependencies — only peer dependencies on React and React Native.

### Flexibility

- Multiple **padding modes**: OAEP/PKCS#1 for encryption, PSS/PKCS#1 for signatures
- Multiple **hash algorithms**: SHA-1, SHA-256, SHA-384, SHA-512
- Multiple **key formats**: PKCS#1 and PKCS#8, with conversion between them
- Full **TypeScript support** with typed errors and options

### Compatibility

- Requires **New Architecture** (Turbo Modules) — React Native **0.71+**
- Android **API 24+** (Android 7.0)
- iOS **13.4+**
- **Expo** — Supported with [development builds](https://docs.expo.dev/develop/development-builds/introduction/) (`npx expo prebuild`). Not compatible with Expo Go.

## Installation

```sh
npm install @avieldr/react-native-rsa
# or
yarn add @avieldr/react-native-rsa
```

For iOS:

```sh
cd ios && pod install
```

> **💡 Tip:** Check out the [`example/`](./example) app in this repository for complete working demonstrations of all features, including key generation, encryption, signing, and error handling.

## Quick Start

```typescript
import RSA, { base64ToUtf8 } from '@avieldr/react-native-rsa';

// Generate a key pair
const { publicKey, privateKey } = await RSA.generateKeyPair(2048);

// Encrypt and decrypt
const encrypted = await RSA.encrypt('Hello, World!', publicKey);
const decryptedBase64 = await RSA.decrypt(encrypted, privateKey);
const decrypted = base64ToUtf8(decryptedBase64); // "Hello, World!"

// Sign and verify
const signature = await RSA.sign('Message to sign', privateKey);
const isValid = await RSA.verify('Message to sign', signature, publicKey); // true
```

## API

### `generateKeyPair(keySize?, options?)`

Generate an RSA key pair using native platform crypto.

```typescript
import RSA from '@avieldr/react-native-rsa';

const { publicKey, privateKey } = await RSA.generateKeyPair(2048);

// With PKCS#8 format
const { publicKey, privateKey } = await RSA.generateKeyPair(2048, {
  format: 'pkcs8',
});
```

| Parameter        | Type                 | Default   | Description                             |
| ---------------- | -------------------- | --------- | --------------------------------------- |
| `keySize`        | `number`             | `2048`    | RSA key size in bits (1024, 2048, 4096) |
| `options.format` | `'pkcs1' \| 'pkcs8'` | `'pkcs1'` | Private key output format               |

**Returns:** `Promise<RSAKeyPair>`

```typescript
interface RSAKeyPair {
  publicKey: string; // PEM (SPKI/X.509): -----BEGIN PUBLIC KEY-----
  privateKey: string; // PEM (PKCS#1): -----BEGIN RSA PRIVATE KEY-----
  // or (PKCS#8): -----BEGIN PRIVATE KEY-----
}
```

---

### `encrypt(data, publicKeyPEM, options?)`

Encrypt data with an RSA public key.

```typescript
// Basic encryption (UTF-8 text)
const encrypted = await RSA.encrypt('Hello, World!', publicKey);

// With options
const encrypted = await RSA.encrypt('Hello, World!', publicKey, {
  padding: 'oaep', // or 'pkcs1'
  hash: 'sha256', // or 'sha1', 'sha384', 'sha512'
});

// Binary data (already base64-encoded)
const encrypted = await RSA.encrypt(binaryDataBase64, publicKey, {
  encoding: 'base64',
});
```

| Parameter          | Type                 | Default    | Description                              |
| ------------------ | -------------------- | ---------- | ---------------------------------------- |
| `data`             | `string`             | —          | Data to encrypt (UTF-8 string or base64) |
| `publicKeyPEM`     | `string`             | —          | Public key in SPKI PEM format            |
| `options.padding`  | `'oaep' \| 'pkcs1'`  | `'oaep'`   | Padding mode (OAEP recommended)          |
| `options.hash`     | `HashAlgorithm`      | `'sha256'` | Hash algorithm (used with OAEP)          |
| `options.encoding` | `'utf8' \| 'base64'` | `'utf8'`   | How to interpret the input string        |

**Returns:** `Promise<string>` — Base64-encoded ciphertext

---

### `decrypt(encrypted, privateKeyPEM, options?)`

Decrypt ciphertext with an RSA private key.

```typescript
import RSA, { base64ToUtf8 } from '@avieldr/react-native-rsa';

const decryptedBase64 = await RSA.decrypt(encrypted, privateKey);
const plaintext = base64ToUtf8(decryptedBase64); // Convert back to UTF-8

// With options (must match encryption options)
const decryptedBase64 = await RSA.decrypt(encrypted, privateKey, {
  padding: 'oaep',
  hash: 'sha256',
});
```

| Parameter         | Type                | Default    | Description                               |
| ----------------- | ------------------- | ---------- | ----------------------------------------- |
| `encrypted`       | `string`            | —          | Base64-encoded ciphertext                 |
| `privateKeyPEM`   | `string`            | —          | Private key in PEM format (PKCS#1/PKCS#8) |
| `options.padding` | `'oaep' \| 'pkcs1'` | `'oaep'`   | Padding mode (must match encryption)      |
| `options.hash`    | `HashAlgorithm`     | `'sha256'` | Hash algorithm (must match encryption)    |

**Returns:** `Promise<string>` — Base64-encoded plaintext (use `base64ToUtf8()` to convert)

---

### `sign(data, privateKeyPEM, options?)`

Sign data with an RSA private key.

```typescript
const signature = await RSA.sign('Message to sign', privateKey);

// With options
const signature = await RSA.sign('Message to sign', privateKey, {
  padding: 'pss', // or 'pkcs1'
  hash: 'sha256',
});
```

| Parameter          | Type                 | Default    | Description                               |
| ------------------ | -------------------- | ---------- | ----------------------------------------- |
| `data`             | `string`             | —          | Data to sign (UTF-8 string or base64)     |
| `privateKeyPEM`    | `string`             | —          | Private key in PEM format (PKCS#1/PKCS#8) |
| `options.padding`  | `'pss' \| 'pkcs1'`   | `'pss'`    | Padding mode (PSS recommended)            |
| `options.hash`     | `HashAlgorithm`      | `'sha256'` | Hash algorithm                            |
| `options.encoding` | `'utf8' \| 'base64'` | `'utf8'`   | How to interpret the input string         |

**Returns:** `Promise<string>` — Base64-encoded signature

---

### `verify(data, signature, publicKeyPEM, options?)`

Verify a signature against data using an RSA public key.

```typescript
const isValid = await RSA.verify('Message to sign', signature, publicKey);
// true if signature is valid, false otherwise

// With options (must match signing options)
const isValid = await RSA.verify('Message to sign', signature, publicKey, {
  padding: 'pss',
  hash: 'sha256',
});
```

| Parameter          | Type                 | Default    | Description                         |
| ------------------ | -------------------- | ---------- | ----------------------------------- |
| `data`             | `string`             | —          | Original data that was signed       |
| `signature`        | `string`             | —          | Base64-encoded signature            |
| `publicKeyPEM`     | `string`             | —          | Public key in SPKI PEM format       |
| `options.padding`  | `'pss' \| 'pkcs1'`   | `'pss'`    | Padding mode (must match signing)   |
| `options.hash`     | `HashAlgorithm`      | `'sha256'` | Hash algorithm (must match signing) |
| `options.encoding` | `'utf8' \| 'base64'` | `'utf8'`   | How to interpret the input string   |

**Returns:** `Promise<boolean>` — `true` if valid, `false` otherwise

---

### `getPublicKeyFromPrivate(privateKeyPEM)`

Extract the public key from an RSA private key.

```typescript
const publicKey = await RSA.getPublicKeyFromPrivate(privateKey);
```

Accepts both PKCS#1 and PKCS#8 private key formats.

**Returns:** `Promise<string>` — Public key in SPKI PEM format

---

### `convertPrivateKey(pem, targetFormat)`

Convert a private key between PKCS#1 and PKCS#8 formats.

```typescript
// Convert PKCS#1 to PKCS#8
const pkcs8Key = await RSA.convertPrivateKey(pkcs1Key, 'pkcs8');

// Convert PKCS#8 to PKCS#1
const pkcs1Key = await RSA.convertPrivateKey(pkcs8Key, 'pkcs1');
```

| Parameter      | Type                 | Description                  |
| -------------- | -------------------- | ---------------------------- |
| `pem`          | `string`             | Private key in PEM format    |
| `targetFormat` | `'pkcs1' \| 'pkcs8'` | Target format for conversion |

**Returns:** `Promise<string>` — Private key in the target format

---

### `getKeyInfo(keyString)`

Analyze a PEM key string and return metadata. Runs entirely in JS — no native bridge call.

```typescript
import { getKeyInfo } from '@avieldr/react-native-rsa';

const info = getKeyInfo(privateKey);
// {
//   isValid: true,
//   format: 'pkcs1',
//   keyType: 'private',
//   pemLineCount: 13,
//   derByteLength: 609,
//   errors: []
// }
```

**Returns:** `RSAKeyInfo`

```typescript
interface RSAKeyInfo {
  isValid: boolean;
  format: 'pkcs1' | 'pkcs8' | 'public' | 'unknown';
  keyType: 'private' | 'public' | 'unknown';
  pemLineCount: number;
  derByteLength: number;
  errors: string[];
}
```

---

## Encoding Utilities

The library provides pure-JS encoding utilities that work in all React Native JS engines.

```typescript
import { utf8ToBase64, base64ToUtf8 } from '@avieldr/react-native-rsa';

// Encode UTF-8 text to base64
const encoded = utf8ToBase64('Hello, 世界! 🎉');

// Decode base64 back to UTF-8
const decoded = base64ToUtf8(encoded);
```

These are useful for:

- Converting decrypted data back to readable text
- Preparing binary data for encryption
- Handling Unicode and emoji correctly

---

## Error Handling

The library throws `RsaError` for invalid inputs and native failures with specific error codes:

```typescript
import RSA, { RsaError } from '@avieldr/react-native-rsa';

try {
  await RSA.encrypt('data', 'invalid-key');
} catch (error) {
  if (error instanceof RsaError) {
    console.log(error.code); // 'INVALID_KEY'
    console.log(error.message); // Detailed error message
    console.log(error.cause); // Original error (if from native layer)
  }
}
```

### Validation Errors

These are thrown **before** calling native code when inputs are invalid:

| Error Code         | Description                               |
| ------------------ | ----------------------------------------- |
| `INVALID_INPUT`    | Required parameter is missing or empty    |
| `INVALID_KEY`      | Key format is wrong or key type mismatch  |
| `INVALID_KEY_SIZE` | Unsupported key size (not 1024/2048/4096) |
| `INVALID_PADDING`  | Unknown padding mode                      |
| `INVALID_HASH`     | Unknown hash algorithm                    |
| `INVALID_FORMAT`   | Unknown key format                        |
| `INVALID_ENCODING` | Unknown encoding type                     |

### Native Operation Errors

These are thrown when the platform crypto operation fails:

| Error Code              | Description                                    |
| ----------------------- | ---------------------------------------------- |
| `KEY_GENERATION_FAILED` | Native key generation failed                   |
| `KEY_EXTRACTION_FAILED` | Failed to extract public key from private key  |
| `KEY_CONVERSION_FAILED` | Failed to convert key between formats          |
| `ENCRYPTION_FAILED`     | Encryption failed (e.g., data too large)       |
| `DECRYPTION_FAILED`     | Decryption failed (e.g., wrong key or padding) |
| `SIGNING_FAILED`        | Signing operation failed                       |
| `VERIFICATION_FAILED`   | Signature verification failed                  |

### TypeScript Support

The error code type is exported for TypeScript users:

```typescript
import type { RsaErrorCode } from '@avieldr/react-native-rsa';

function handleError(code: RsaErrorCode) {
  switch (code) {
    case 'INVALID_KEY':
      // Handle invalid key
      break;
    case 'DECRYPTION_FAILED':
      // Handle decryption failure
      break;
    // ...
  }
}
```

---

## Types

All types are exported for TypeScript users:

```typescript
import type {
  RSAKeyPair,
  RSAKeyInfo,
  GenerateKeyPairOptions,
  KeyFormat,
  EncryptOptions,
  DecryptOptions,
  SignOptions,
  VerifyOptions,
  EncryptionPadding,
  SignaturePadding,
  HashAlgorithm,
  InputEncoding,
  RsaErrorCode,
} from '@avieldr/react-native-rsa';
```

| Type                | Values                                       |
| ------------------- | -------------------------------------------- |
| `KeyFormat`         | `'pkcs1' \| 'pkcs8'`                         |
| `RsaErrorCode`      | See [Error Handling](#error-handling)        |
| `EncryptionPadding` | `'oaep' \| 'pkcs1'`                          |
| `SignaturePadding`  | `'pss' \| 'pkcs1'`                           |
| `HashAlgorithm`     | `'sha1' \| 'sha256' \| 'sha384' \| 'sha512'` |
| `InputEncoding`     | `'utf8' \| 'base64'`                         |

---

## Benchmarks

Typical key generation times on modern devices:

| Key Size | Time     |
| -------- | -------- |
| 1024-bit | ~50ms    |
| 2048-bit | ~200ms   |
| 4096-bit | ~2,000ms |

_Times vary by device. Measured on mid-range Android and iPhone devices._

---

## Security Recommendations

- **Use OAEP padding** for encryption (default) — PKCS#1 v1.5 is vulnerable to padding oracle attacks
- **Use PSS padding** for signatures (default) — more secure than PKCS#1 v1.5
- **Use SHA-256 or higher** — SHA-1 is deprecated for new applications
- **Use 2048-bit keys minimum** — 1024-bit is considered weak

---

## License

MIT
