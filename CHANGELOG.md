# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.4] - 2026-02-07

### Fixed

- Fixed iOS build error: `verify()` now returns `NSNumber` instead of `Bool` to comply with Swift `@objc throws` requirements (Xcode 26+)

## [1.0.3] - 2026-02-07

### Fixed

- Fixed lint and prettier formatting issues
- Added Expo compatibility note to README
- Disabled `no-bitwise` eslint rule for encoding/key-parsing utilities

## [1.0.1] - 2026-02-07

### Fixed

- Corrected repository URLs in package metadata

## [1.0.0] - 2026-02-07

### Added

- RSA key pair generation (1024, 2048, 4096 bit) using native platform crypto
- Encrypt/Decrypt with OAEP and PKCS#1 padding
- Sign/Verify with PSS and PKCS#1 padding
- Hash algorithm support: SHA-1, SHA-256, SHA-384, SHA-512
- Key format output: PKCS#1 and PKCS#8 (private), SPKI/X.509 (public)
- Private key format conversion between PKCS#1 and PKCS#8
- Public key extraction from private key
- JS-only key validation via `getKeyInfo()`
- Encoding utilities: `utf8ToBase64()` and `base64ToUtf8()`
- Typed error handling with `RsaError` and specific error codes
- Full TypeScript support
