//
//  RSA.h
//  Nongfadai
//
//  Created by 刘永生 on 15/10/8.
//  Copyright (c) 2015年 刘永生 . All rights reserved.
//

#import <Foundation/Foundation.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#import <openssl/bio.h>
#import <openssl/sha.h>

typedef enum {
    KeyTypePublic,
    KeyTypePrivate
}KeyType;

typedef enum {
    RSA_PADDING_TYPE_NONE       = RSA_NO_PADDING,
    RSA_PADDING_TYPE_PKCS1      = RSA_PKCS1_PADDING,
    RSA_PADDING_TYPE_SSLV23     = RSA_SSLV23_PADDING
}RSA_PADDING_TYPE;



#define GNFDRSA [NFDRSA sharedManager]

@interface NFDRSA : NSObject{
    RSA *_rsa;
}

@property (nonatomic, copy) NSString *publicKeyStr;
@property (nonatomic, copy) NSString *privateKeyStr;

+ (NFDRSA *)sharedManager;

/**
 *  加密
 *
 *  @param content 加密内容
 *  @param keyType 私钥/公钥 加密
 *
 *  @return 密文
 */
- (NSString *)encryptByRsa:(NSString*)content withKeyType:(KeyType)keyType;

/**
 *  解密
 *
 *  @param content 解密内容
 *  @param keyType 私钥/公钥 解密
 *
 *  @return 明文
 */
- (NSString *)decryptByRsa:(NSString*)content withKeyType:(KeyType)keyType;


#pragma mark - 后台签名功能不启用作废,但保留
/**
 *  对 信息进行排序 并 RSA 签名
 */
+ (NSString *)signSordInfo:(NSDictionary *)aDic;






@end
