//
//  RSA.m
//  Nongfadai
//
//  Created by 刘永生 on 15/10/8.
//  Copyright (c) 2015年 刘永生. All rights reserved.
//

#import "NFDRSA.h"

#import "Base64.h"

//#import "NFDBase64.h"

//#import "openssl_wrapper.h"


#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>
#import <Security/Security.h>
//#import "NSData+Base64.h"
//#import <NSData+MKBase64.h>
//#import "NFDBase64.h"

#define kChosenDigestLength CC_SHA1_DIGEST_LENGTH


#define PADDING RSA_PADDING_TYPE_PKCS1

@implementation NFDRSA

+ (NFDRSA *)sharedManager
{
    static NFDRSA *sharedInstance = nil;
    static dispatch_once_t predicate;
    dispatch_once(&predicate, ^{
        if (!sharedInstance) {
            sharedInstance = [[NFDRSA alloc]init];
        }
    });
    return sharedInstance;
}

- (BOOL)importRSAKeyWithType:(KeyType)type
{
    if (type == KeyTypePublic)
    {
        
        BIO *bio_public = NULL;
        bio_public = BIO_new(BIO_s_mem());
        BIO_puts(bio_public, [NFDRSA NFD_formatPublicKey:self.publicKeyStr].UTF8String);
        _rsa = PEM_read_bio_RSA_PUBKEY(bio_public, NULL, NULL, NULL);
        assert(_rsa != NULL);
        
        BIO_free_all(bio_public);
    }
    else
    {
        BIO *bio_private = NULL;
        bio_private = BIO_new(BIO_s_mem());
        BIO_puts(bio_private, [NFDRSA NFD_formatPrivateKey:self.privateKeyStr].UTF8String);
        _rsa = PEM_read_bio_RSAPrivateKey(bio_private, NULL, NULL, "");
        assert(_rsa != NULL);
        
        BIO_free_all(bio_private);
    }
    
    return (_rsa != NULL) ? YES : NO;
}


#pragma mark - RSA加密
- (NSString *) encryptByRsa:(NSString*)content withKeyType:(KeyType)keyType
{
    if (![self importRSAKeyWithType:keyType])
        return nil;
    
    //GBK  根据自己项目需要修改编码格式
    NSStringEncoding encoding = CFStringConvertEncodingToNSStringEncoding(kCFStringEncodingGB_18030_2000);
    NSData *data = [content dataUsingEncoding:encoding];
    
    
    NSArray *dataArray = [self clipData:data withLenght:100];
    
    NSMutableData *mData = [NSMutableData data];
    for (NSData *data in dataArray) {
        [mData appendData:[self encryptByRsaInPart:data withKeyType:keyType]];
    }
    
    NSString *ret = [mData base64EncodedString];
    
    return ret;
}


#pragma mark - RSA解密
- (NSString *) decryptByRsa:(NSString*)content withKeyType:(KeyType)keyType
{
    if (![self importRSAKeyWithType:keyType])
        return nil;
    
    NSData *de64data = [content base64DecodedData];
    
    NSArray *dataArray = [self clipData:de64data withLenght:128];
    
    NSMutableData *mData = [NSMutableData data];
    for (NSData *data in dataArray) {
        [mData appendData:[self decryptByRsaInPart:data withKeyType:keyType]];
    }
    
    //GBK  根据自己项目需要修改编码格式
    NSStringEncoding encoding = CFStringConvertEncodingToNSStringEncoding(kCFStringEncodingGB_18030_2000);
    
    NSMutableString *decryptString = [[NSMutableString alloc] initWithData:mData encoding:encoding];
    
    return decryptString;
}


-(NSArray*)clipData:(NSData*)data withLenght:(int)lenght{
    NSMutableArray *array = [NSMutableArray array];
    
    char *dataPart = (char*)malloc(lenght+1);
    bzero(dataPart, lenght+1);
    
    char *dataBytes = (char*)[data bytes];
    
    for (int i=0; i<data.length; i++) {
        dataPart[i%lenght] = dataBytes[i];
        
        if(i%lenght == (lenght-1)){
            [array addObject:[NSData dataWithBytes:dataPart length:lenght]];
            
            bzero(dataPart, lenght+1);
        }else if (i==data.length-1){
            [array addObject:[NSData dataWithBytes:dataPart length:data.length%lenght]];
        }
    }
    
    free(dataPart);
    dataPart = NULL;
    
    return array;
}

- (NSData *) encryptByRsaInPart:(NSData*)data withKeyType:(KeyType)keyType{
    int status;
    
    NSInteger  flen = [self getBlockSizeWithRSA_PADDING_TYPE:PADDING];
    
    char *encData = (char*)malloc(flen);
    bzero(encData, flen);
    
    switch (keyType) {
        case KeyTypePublic:
            status = RSA_public_encrypt(data.length, (unsigned char*)data.bytes, (unsigned char*)encData, _rsa, PADDING);
            break;
            
        default:
            status = RSA_private_encrypt(data.length, (unsigned char*)data.bytes, (unsigned char*)encData, _rsa, PADDING);
            break;
    }
    
    if (status)
    {
        NSData *returnData = [NSData dataWithBytes:encData length:status];
        free(encData);
        encData = NULL;
        
        return returnData;
    }
    
    free(encData);
    encData = NULL;
    
    return nil;
}

-(NSData *)decryptByRsaInPart:(NSData *)data withKeyType:(KeyType)keyType{
    
    int status;
    
    int length = (int)[data length];
    
    NSInteger flen = [self getBlockSizeWithRSA_PADDING_TYPE:PADDING];
    char *decData = (char*)malloc(flen);
    bzero(decData, flen);
    
    
    switch (keyType) {
        case KeyTypePublic:
            status = RSA_public_decrypt(length, (unsigned char*)[data bytes], (unsigned char*)decData, _rsa, PADDING);
            break;
            
        default:
            status = RSA_private_decrypt(length, (unsigned char*)[data bytes], (unsigned char*)decData, _rsa, PADDING);
            break;
    }
    
    if (status)
    {
        
        NSData *retData = [NSData dataWithBytes:decData length:strlen(decData)];
        
        free(decData);
        decData = NULL;
        
        return retData;
    }
    
    free(decData);
    decData = NULL;
    
    return nil;
}

- (int)getBlockSizeWithRSA_PADDING_TYPE:(RSA_PADDING_TYPE)padding_type
{
    int len = RSA_size(_rsa);
    
    if (padding_type == RSA_PADDING_TYPE_PKCS1 || padding_type == RSA_PADDING_TYPE_SSLV23) {
        len -= 11;
    }
    
    return len;
}


#pragma mark - Publilc
/**
 *   苹果的 SecKeyEncrypt() 函数需要 .der 证书, 而公钥/秘钥只是证书的一部分.
 *   iOS 可以使用自己产生的公钥/秘钥, 所以要将公钥/秘钥伪装成是 iOS 产生的
 */
+ (NSString *)NFD_formatPrivateKey:(NSString *)privateKey {
    const char *pstr = [privateKey UTF8String];
    NSMutableString *result = [NSMutableString string];
    [result appendString:@"-----BEGIN PRIVATE KEY-----\n"];
    int index = 0;
    int count = 0;
    while (index < [privateKey length]) {
        char ch = pstr[index];
        if (ch == '\r' || ch == '\n') {
            ++index;
            continue;
        }
        [result appendFormat:@"%c", ch];
        if (++count == 76)
        {
            [result appendString:@"\n"];
            count = 0;
        }
        index++;
    }
    [result appendString:@"\n-----END PRIVATE KEY-----\n"];
    return result;
}
+ (NSString *)NFD_formatPublicKey:(NSString *)publicKey {
    
    NSMutableString *result = [NSMutableString string];
    
    [result appendString:@"-----BEGIN PUBLIC KEY-----\n"];
    
    int count = 0;
    
    for (int i = 0; i < [publicKey length]; ++i) {
        
        unichar c = [publicKey characterAtIndex:i];
        if (c == '\n' || c == '\r') {
            continue;
        }
        [result appendFormat:@"%c", c];
        if (++count == 76) {
            [result appendString:@"\n"];
            count = 0;
        }
        
    }
    
    [result appendString:@"\n-----END PUBLIC KEY-----\n"];
    
    return result;
    
}


#pragma mark - 后台签名功能不启用作废,但保留

+ (NSString *)signSordInfo:(NSDictionary *)aDic {
    
    // 对字段进行字母序排序
    NSMutableArray *sortedKeyArray = [NSMutableArray arrayWithArray:[aDic allKeys]];
    
    [sortedKeyArray sortUsingComparator:^NSComparisonResult(NSString* key1, NSString* key2) {
        return [key1 compare:key2];
    }];
    
    NSMutableString *paramString = [NSMutableString stringWithString:@""];
    
    // 拼接成 A=B&X=Y
    for (NSString *key in sortedKeyArray)
    {
        if ([aDic[key] length] != 0)
        {
            [paramString appendFormat:@"&%@=%@", key, aDic[key]];
        }
    }
    
    if ([paramString length] > 1)
    {
        [paramString deleteCharactersInRange:NSMakeRange(0, 1)];    // remove first '&'
    }
    
    //    BOOL bMd5Sign = [paramDic[@"sign_type"] isEqualToString:@"MD5"];
    //
    //    if (bMd5Sign)
    //    {
    //        // MD5签名，在最后加上key， 变成 A=B&X=Y&key=1234
    //        [paramString appendFormat:@"&key=%@", self.signKey];
    //    }
    //    else{
    //        // RSA
    //    }
    
    
    //DLog(@"签名原串: %@", paramString);
    
    NSString *signString = [self signTheDataSHA1WithRSA:paramString];
    
    //    DLog(@"%@\n%@",paramString,signString);
    
    signString = (NSString*)CFBridgingRelease(CFURLCreateStringByAddingPercentEscapes(kCFAllocatorDefault, (CFStringRef)signString, NULL, (CFStringRef)@"!*'();:@&=+$,/?%#[]", kCFStringEncodingUTF8));
    
    
    return signString;
    
}
+ (NSString *)signTheDataSHA1WithRSA:(NSString *)plainText
{
    uint8_t* signedBytes = NULL;
    size_t signedBytesSize = 0;
    OSStatus sanityCheck = noErr;
    NSData* signedHash = nil;
    
    /**
     *  私钥后台已经重新生成,本地私钥不可用
     */
    NSString * path = [[NSBundle mainBundle]pathForResource:@"private_key" ofType:@"p12"];
    NSData * data = [NSData dataWithContentsOfFile:path];
    NSMutableDictionary * options = [[NSMutableDictionary alloc] init]; // Set the private key query dictionary.
    [options setObject:@"nfd2015" forKey:(id)kSecImportExportPassphrase];
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    OSStatus securityError = SecPKCS12Import((CFDataRef) data, (CFDictionaryRef)options, &items);
    if (securityError!=noErr) {
        return nil ;
    }
    CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
    SecIdentityRef identityApp =(SecIdentityRef)CFDictionaryGetValue(identityDict,kSecImportItemIdentity);
    SecKeyRef privateKeyRef=nil;
    SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
    signedBytesSize = SecKeyGetBlockSize(privateKeyRef);
    
    NSData *plainTextBytes = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    
    signedBytes = malloc( signedBytesSize * sizeof(uint8_t) ); // Malloc a buffer to hold signature.
    memset((void *)signedBytes, 0x0, signedBytesSize);
    
    sanityCheck = SecKeyRawSign(privateKeyRef,
                                kSecPaddingPKCS1SHA1,
                                (const uint8_t *)[[self getHashBytes:plainTextBytes] bytes],
                                kChosenDigestLength,
                                (uint8_t *)signedBytes,
                                &signedBytesSize);
    
    if (sanityCheck == noErr)
    {
        signedHash = [NSData dataWithBytes:(const void *)signedBytes length:(NSUInteger)signedBytesSize];
    }
    else
    {
        return nil;
    }
    
    if (signedBytes)
    {
        free(signedBytes);
    }
    NSString *signatureResult=[NSString stringWithFormat:@"%@",[signedHash base64EncodedString]];
    return signatureResult;
}

+ (NSData *)getHashBytes:(NSData *)plainText {
    CC_SHA1_CTX ctx;
    uint8_t * hashBytes = NULL;
    NSData * hash = nil;
    
    // Malloc a buffer to hold hash.
    hashBytes = malloc( kChosenDigestLength * sizeof(uint8_t) );
    memset((void *)hashBytes, 0x0, kChosenDigestLength);
    // Initialize the context.
    CC_SHA1_Init(&ctx);
    // Perform the hash.
    CC_SHA1_Update(&ctx, (void *)[plainText bytes], [plainText length]);
    // Finalize the output.
    CC_SHA1_Final(hashBytes, &ctx);
    
    // Build up the SHA1 blob.
    hash = [NSData dataWithBytes:(const void *)hashBytes length:(NSUInteger)kChosenDigestLength];
    if (hashBytes) free(hashBytes);
    
    return hash;
}

@end
