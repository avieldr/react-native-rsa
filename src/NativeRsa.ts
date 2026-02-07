import { TurboModuleRegistry, type TurboModule } from 'react-native';

/**
 * Native bridge specification for RSA operations.
 *
 * All methods use flat string parameters (no objects/arrays) because
 * React Native's codegen works best with simple types across the bridge.
 *
 * Data is passed as base64 strings to avoid binary encoding issues.
 * The JS layer (index.ts) handles defaults resolution and UTF-8→base64 encoding.
 */
export interface Spec extends TurboModule {
  /** Generate an RSA key pair → { publicKey, privateKey } in PEM format */
  generateKeyPair(
    keySize: number,
    format: string
  ): Promise<{ publicKey: string; privateKey: string }>;

  /** Extract public key from a private key PEM → public key PEM */
  getPublicKeyFromPrivate(privateKeyPEM: string): Promise<string>;

  /** Encrypt base64 data with a public key → base64 ciphertext */
  encrypt(
    dataBase64: string,
    publicKeyPEM: string,
    padding: string,
    hash: string
  ): Promise<string>;

  /** Decrypt base64 ciphertext with a private key → base64 plaintext */
  decrypt(
    dataBase64: string,
    privateKeyPEM: string,
    padding: string,
    hash: string
  ): Promise<string>;

  /** Sign base64 data with a private key → base64 signature */
  sign(
    dataBase64: string,
    privateKeyPEM: string,
    padding: string,
    hash: string
  ): Promise<string>;

  /** Verify a base64 signature against base64 data → boolean */
  verify(
    dataBase64: string,
    signatureBase64: string,
    publicKeyPEM: string,
    padding: string,
    hash: string
  ): Promise<boolean>;

  /** Convert a private key PEM between PKCS#1 and PKCS#8 formats */
  convertPrivateKey(pem: string, targetFormat: string): Promise<string>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('Rsa');
