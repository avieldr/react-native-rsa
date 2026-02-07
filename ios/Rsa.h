#ifdef __cplusplus
#import <RsaSpec/RsaSpec.h>
#endif

@interface Rsa : NSObject
#ifdef __cplusplus
<NativeRsaSpec>
#endif

// --- Key Generation ---

- (void)generateKeyPair:(double)keySize
                 format:(NSString *)format
                resolve:(RCTPromiseResolveBlock)resolve
                 reject:(RCTPromiseRejectBlock)reject;

- (void)getPublicKeyFromPrivate:(NSString *)privateKeyPEM
                        resolve:(RCTPromiseResolveBlock)resolve
                         reject:(RCTPromiseRejectBlock)reject;

// --- Encrypt / Decrypt ---

- (void)encrypt:(NSString *)dataBase64
   publicKeyPEM:(NSString *)publicKeyPEM
        padding:(NSString *)padding
           hash:(NSString *)hash
        resolve:(RCTPromiseResolveBlock)resolve
         reject:(RCTPromiseRejectBlock)reject;

- (void)decrypt:(NSString *)dataBase64
  privateKeyPEM:(NSString *)privateKeyPEM
        padding:(NSString *)padding
           hash:(NSString *)hash
        resolve:(RCTPromiseResolveBlock)resolve
         reject:(RCTPromiseRejectBlock)reject;

// --- Sign / Verify ---

- (void)sign:(NSString *)dataBase64
privateKeyPEM:(NSString *)privateKeyPEM
      padding:(NSString *)padding
         hash:(NSString *)hash
      resolve:(RCTPromiseResolveBlock)resolve
       reject:(RCTPromiseRejectBlock)reject;

- (void)verify:(NSString *)dataBase64
signatureBase64:(NSString *)signatureBase64
  publicKeyPEM:(NSString *)publicKeyPEM
       padding:(NSString *)padding
          hash:(NSString *)hash
       resolve:(RCTPromiseResolveBlock)resolve
        reject:(RCTPromiseRejectBlock)reject;

// --- Key Format Conversion ---

- (void)convertPrivateKey:(NSString *)pem
             targetFormat:(NSString *)targetFormat
                  resolve:(RCTPromiseResolveBlock)resolve
                   reject:(RCTPromiseRejectBlock)reject;

@end
