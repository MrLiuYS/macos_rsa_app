//
//  ViewController.h
//  RSA_LYS
//
//  Created by 刘永生 on 16/5/5.
//  Copyright © 2016年 刘永生. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface ViewController : NSViewController<NSOpenSavePanelDelegate> {
    
    __weak IBOutlet NSTextField *_filePathLabel;/**< 未加密源文件路径 */
    
    NSString *_filePathStr;
    
    
    __weak IBOutlet NSTextField *_publicEncryptFilePath;/**< 导入公钥加密文件路径 */
    
    
    __weak IBOutlet NSTextField *_privateEncryptFilePath;/**< 导入私钥加密文件路径 */
    
    __weak IBOutlet NSTextField *_privateKeyTF;/**< 私钥串 */
    
    __weak IBOutlet NSTextField *_publiceKeyTF;/**< 公钥串 */
    
    
}


@end

