#import "Rsa.h"

// Import the auto-generated Swift bridging header
#if __has_include("react_native_rsa_turbo/react_native_rsa_turbo-Swift.h")
#import "react_native_rsa_turbo/react_native_rsa_turbo-Swift.h"
#elif __has_include("react-native-rsa-turbo/react_native_rsa_turbo-Swift.h")
#import "react-native-rsa-turbo/react_native_rsa_turbo-Swift.h"
#elif __has_include("Rsa-Swift.h")
#import "Rsa-Swift.h"
#else
// Fallback: forward declare Swift classes used by this file
@class RSAKeyGenerator;
@class RSACipher;
@class RSASigner;
#endif

/**
 * Objective-C++ bridge between React Native TurboModule and Swift implementations.
 *
 * Each method dispatches to a background queue (QOS_CLASS_USER_INITIATED)
 * and calls the corresponding Swift class method, then resolves/rejects
 * the JS promise based on the result.
 *
 * Dispatches to:
 *   - RSAKeyGenerator: key generation, public key extraction, format conversion
 *   - RSACipher: encrypt, decrypt
 *   - RSASigner: sign, verify
 */
@implementation Rsa

// MARK: - Key Generation

- (void)generateKeyPair:(double)keySize
                 format:(NSString *)format
                resolve:(RCTPromiseResolveBlock)resolve
                 reject:(RCTPromiseRejectBlock)reject
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *error = nil;
        RSAKeyGenerator *generator = [RSAKeyGenerator shared];

        RSAKeyPairResult *result = [generator generateKeyPairWithKeySize:(int)keySize
                                                                 format:format
                                                                  error:&error];
        if (error != nil) {
            reject(@"RSAKeyGenerationError", error.localizedDescription, error);
            return;
        }

        if (result == nil) {
            reject(@"RSAKeyGenerationError", @"Unknown error during key generation", nil);
            return;
        }

        NSDictionary *map = @{
            @"publicKey": result.publicKey,
            @"privateKey": result.privateKey
        };
        resolve(map);
    });
}

- (void)getPublicKeyFromPrivate:(NSString *)privateKeyPEM
                        resolve:(RCTPromiseResolveBlock)resolve
                         reject:(RCTPromiseRejectBlock)reject
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *error = nil;
        RSAKeyGenerator *generator = [RSAKeyGenerator shared];

        NSString *publicKeyPEM = [generator getPublicKeyFromPrivateWithPrivateKeyPEM:privateKeyPEM
                                                                               error:&error];
        if (error != nil) {
            reject(@"RSAKeyExtractionError", error.localizedDescription, error);
            return;
        }

        resolve(publicKeyPEM);
    });
}

// MARK: - Encrypt / Decrypt

- (void)encrypt:(NSString *)dataBase64
   publicKeyPEM:(NSString *)publicKeyPEM
        padding:(NSString *)padding
           hash:(NSString *)hash
        resolve:(RCTPromiseResolveBlock)resolve
         reject:(RCTPromiseRejectBlock)reject
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *error = nil;
        // RSACipher.encrypt is a static Swift method → class method in Obj-C
        NSString *result = [RSACipher encryptWithDataBase64:dataBase64
                                              publicKeyPEM:publicKeyPEM
                                                   padding:padding
                                                      hash:hash
                                                     error:&error];
        if (error != nil) {
            reject(@"RSAEncryptError", error.localizedDescription, error);
            return;
        }
        resolve(result);
    });
}

- (void)decrypt:(NSString *)dataBase64
  privateKeyPEM:(NSString *)privateKeyPEM
        padding:(NSString *)padding
           hash:(NSString *)hash
        resolve:(RCTPromiseResolveBlock)resolve
         reject:(RCTPromiseRejectBlock)reject
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *error = nil;
        NSString *result = [RSACipher decryptWithDataBase64:dataBase64
                                             privateKeyPEM:privateKeyPEM
                                                   padding:padding
                                                      hash:hash
                                                     error:&error];
        if (error != nil) {
            reject(@"RSADecryptError", error.localizedDescription, error);
            return;
        }
        resolve(result);
    });
}

// MARK: - Sign / Verify

- (void)sign:(NSString *)dataBase64
privateKeyPEM:(NSString *)privateKeyPEM
      padding:(NSString *)padding
         hash:(NSString *)hash
      resolve:(RCTPromiseResolveBlock)resolve
       reject:(RCTPromiseRejectBlock)reject
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *error = nil;
        NSString *result = [RSASigner signWithDataBase64:dataBase64
                                          privateKeyPEM:privateKeyPEM
                                                padding:padding
                                                   hash:hash
                                                  error:&error];
        if (error != nil) {
            reject(@"RSASignError", error.localizedDescription, error);
            return;
        }
        resolve(result);
    });
}

- (void)verify:(NSString *)dataBase64
signatureBase64:(NSString *)signatureBase64
  publicKeyPEM:(NSString *)publicKeyPEM
       padding:(NSString *)padding
          hash:(NSString *)hash
       resolve:(RCTPromiseResolveBlock)resolve
        reject:(RCTPromiseRejectBlock)reject
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *error = nil;
        NSNumber *result = [RSASigner verifyWithDataBase64:dataBase64
                                          signatureBase64:signatureBase64
                                             publicKeyPEM:publicKeyPEM
                                                  padding:padding
                                                     hash:hash
                                                    error:&error];
        if (error != nil) {
            reject(@"RSAVerifyError", error.localizedDescription, error);
            return;
        }
        resolve(result);
    });
}

// MARK: - Key Format Conversion

- (void)convertPrivateKey:(NSString *)pem
             targetFormat:(NSString *)targetFormat
                  resolve:(RCTPromiseResolveBlock)resolve
                   reject:(RCTPromiseRejectBlock)reject
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSError *error = nil;
        RSAKeyGenerator *generator = [RSAKeyGenerator shared];

        NSString *result = [generator convertPrivateKeyWithPem:pem
                                                 targetFormat:targetFormat
                                                        error:&error];
        if (error != nil) {
            reject(@"RSAConvertKeyError", error.localizedDescription, error);
            return;
        }
        resolve(result);
    });
}

// MARK: - TurboModule Registration

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
    return std::make_shared<facebook::react::NativeRsaSpecJSI>(params);
}

+ (NSString *)moduleName
{
  return @"Rsa";
}

@end
