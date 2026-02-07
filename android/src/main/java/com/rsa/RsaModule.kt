package com.rsa

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.rsa.core.RSACipher
import com.rsa.core.RSAKeyGenerator
import com.rsa.core.RSASigner
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * React Native TurboModule bridging RSA operations to JavaScript.
 *
 * Each method launches a coroutine on Dispatchers.Default (background thread pool)
 * to keep crypto operations off the main thread, and resolves/rejects the JS promise.
 *
 * Dispatches to:
 *   - [RSAKeyGenerator] for key generation, public key extraction, and format conversion
 *   - [RSACipher] for encrypt/decrypt
 *   - [RSASigner] for sign/verify
 */
class RsaModule(reactContext: ReactApplicationContext) :
  NativeRsaSpec(reactContext) {

  private val supervisorJob = SupervisorJob()
  private val moduleScope = CoroutineScope(Dispatchers.Default + supervisorJob)
  private val keyGenerator = RSAKeyGenerator.getInstance()

  override fun invalidate() {
    supervisorJob.cancel("RsaModule invalidated")
    super.invalidate()
  }

  // --- Key Generation ---

  override fun generateKeyPair(keySize: Double, format: String, promise: Promise) {
    moduleScope.launch {
      try {
        val result = keyGenerator.generateKeyPair(keySize.toInt(), format)
        val map = Arguments.createMap()
        map.putString("publicKey", result.publicKey)
        map.putString("privateKey", result.privateKey)
        promise.resolve(map)
      } catch (e: Exception) {
        promise.reject("RSAKeyGenerationError", e.message, e)
      }
    }
  }

  override fun getPublicKeyFromPrivate(privateKeyPEM: String, promise: Promise) {
    moduleScope.launch {
      try {
        val publicKeyPEM = keyGenerator.getPublicKeyFromPrivate(privateKeyPEM)
        promise.resolve(publicKeyPEM)
      } catch (e: Exception) {
        promise.reject("RSAKeyExtractionError", e.message, e)
      }
    }
  }

  // --- Encrypt / Decrypt ---

  override fun encrypt(dataBase64: String, publicKeyPEM: String, padding: String, hash: String, promise: Promise) {
    moduleScope.launch {
      try {
        val result = RSACipher.encrypt(dataBase64, publicKeyPEM, padding, hash)
        promise.resolve(result)
      } catch (e: Exception) {
        promise.reject("RSAEncryptError", e.message, e)
      }
    }
  }

  override fun decrypt(dataBase64: String, privateKeyPEM: String, padding: String, hash: String, promise: Promise) {
    moduleScope.launch {
      try {
        val result = RSACipher.decrypt(dataBase64, privateKeyPEM, padding, hash)
        promise.resolve(result)
      } catch (e: Exception) {
        promise.reject("RSADecryptError", e.message, e)
      }
    }
  }

  // --- Sign / Verify ---

  override fun sign(dataBase64: String, privateKeyPEM: String, padding: String, hash: String, promise: Promise) {
    moduleScope.launch {
      try {
        val result = RSASigner.sign(dataBase64, privateKeyPEM, padding, hash)
        promise.resolve(result)
      } catch (e: Exception) {
        promise.reject("RSASignError", e.message, e)
      }
    }
  }

  override fun verify(dataBase64: String, signatureBase64: String, publicKeyPEM: String, padding: String, hash: String, promise: Promise) {
    moduleScope.launch {
      try {
        val result = RSASigner.verify(dataBase64, signatureBase64, publicKeyPEM, padding, hash)
        promise.resolve(result)
      } catch (e: Exception) {
        promise.reject("RSAVerifyError", e.message, e)
      }
    }
  }

  // --- Key Format Conversion ---

  override fun convertPrivateKey(pem: String, targetFormat: String, promise: Promise) {
    moduleScope.launch {
      try {
        val result = keyGenerator.convertPrivateKey(pem, targetFormat)
        promise.resolve(result)
      } catch (e: Exception) {
        promise.reject("RSAConvertKeyError", e.message, e)
      }
    }
  }

  companion object {
    const val NAME = NativeRsaSpec.NAME
  }
}
