//
//  ViewController.m
//  RSA_LYS
//
//  Created by 刘永生 on 16/5/5.
//  Copyright © 2016年 刘永生. All rights reserved.
//

#import "ViewController.h"

#import "NFDRSA.h"

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    // Do any additional setup after loading the view.
}

- (void)secretKey {
    
    NSString * publiceKey = [_publiceKeyTF stringValue];
    
    if (publiceKey.length > 0) {
        GNFDRSA.publicKeyStr = publiceKey;
        
    }
    
    NSString * privateKey = [_privateKeyTF stringValue];
    
    if (publiceKey.length > 0) {
        
        GNFDRSA.privateKeyStr = privateKey;
    }
    
    
}

#pragma mark - 导入未加密源文件
- (IBAction)touchOpenPanel:(id)sender {
    
    
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    [panel setDirectory:NSHomeDirectory()];
    [panel setAllowsMultipleSelection:NO];
    [panel setCanChooseDirectories:YES];
    [panel setCanChooseFiles:YES];
    //    [panel setAllowedFileTypes:@[@"onecodego"]];
    [panel setAllowsOtherFileTypes:YES];
    if ([panel runModal] == NSOKButton) {
        NSString *path = [panel.URLs.firstObject path];
        //code
        
        NSLog(@"%@",path);
        
        [_filePathLabel setStringValue:path];
        
        _filePathStr = path;
        
    }
    
}

#pragma mark - 私钥加密导出源文件
- (IBAction)touchEncryptFromPrivateKey:(id)sender {
    
    [self secretKey];
    
    NSString *content = [NSString stringWithContentsOfFile:_filePathStr encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"read success: %@",content);
    
    NSString *encryptStr = [GNFDRSA encryptByRsa:content withKeyType:KeyTypePrivate];
    
    [self exportFiledName:@"私钥加密文件" content:encryptStr];
    
}
#pragma mark - 公钥加密导出源文件
- (IBAction)touchEncryptFromPublic:(id)sender {
    
    [self secretKey];
    
    NSString *content = [NSString stringWithContentsOfFile:_filePathStr encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"read success: %@",content);
    
    NSString *encryptStr = [GNFDRSA encryptByRsa:content withKeyType:KeyTypePublic];
    
    [self exportFiledName:@"公钥加密文件" content:encryptStr];
    
}


#pragma mark - 导入公钥加密文件
- (IBAction)touchImputPublicEncryptFile:(id)sender {
    
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    [panel setDirectory:NSHomeDirectory()];
    [panel setAllowsMultipleSelection:NO];
    [panel setCanChooseDirectories:YES];
    [panel setCanChooseFiles:YES];
    //    [panel setAllowedFileTypes:@[@"onecodego"]];
    [panel setAllowsOtherFileTypes:YES];
    if ([panel runModal] == NSOKButton) {
        NSString *path = [panel.URLs.firstObject path];
        //code
        
        NSLog(@"%@",path);
        
        [_publicEncryptFilePath setStringValue:path];
        
        
    }
    
}
#pragma mark - 导出用私钥解密的文件
- (IBAction)touchExportPrivateDecrypt:(id)sender {
    
    [self secretKey];
    
    NSString * filePath = [_publicEncryptFilePath stringValue];
    
    NSString *content = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"read success: %@",content);
    
    NSString *encryptStr = [GNFDRSA decryptByRsa:content withKeyType:KeyTypePrivate];
    
    [self exportFiledName:@"私钥解密文件" content:encryptStr];
    
    
}




#pragma mark - 导入私钥加密文件

- (IBAction)touchImputPrivateEncryptFile:(id)sender {
    
    
    NSOpenPanel *panel = [NSOpenPanel openPanel];
    [panel setDirectory:NSHomeDirectory()];
    [panel setAllowsMultipleSelection:NO];
    [panel setCanChooseDirectories:YES];
    [panel setCanChooseFiles:YES];
    //    [panel setAllowedFileTypes:@[@"onecodego"]];
    [panel setAllowsOtherFileTypes:YES];
    if ([panel runModal] == NSOKButton) {
        NSString *path = [panel.URLs.firstObject path];
        //code
        
        NSLog(@"%@",path);
        
        [_privateEncryptFilePath setStringValue:path];
        
        
    }
    
}

#pragma mark - 导出公钥解密的文件
- (IBAction)touchExportPublicDecrypt:(id)sender {
    
    [self secretKey];
    
    NSString * filePath = [_privateEncryptFilePath stringValue];
    
    NSString *content = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"read success: %@",content);
    
    NSString *encryptStr = [GNFDRSA decryptByRsa:content withKeyType:KeyTypePublic];
    
    [self exportFiledName:@"公钥解密文件" content:encryptStr];
    
}






- (void)exportFiledName:(NSString *)aName content:(NSString *)aContent {
    
    NSSavePanel*    panel = [NSSavePanel savePanel];
    [panel setNameFieldStringValue:aName];
    [panel setMessage:@"请选择保存的路径"];
    [panel setAllowsOtherFileTypes:YES];
    //    [panel setAllowedFileTypes:@[@"onecodego"]];
    [panel setExtensionHidden:YES];
    [panel setCanCreateDirectories:YES];
    [panel beginSheetModalForWindow:[[self view] window] completionHandler:^(NSInteger result){
        if (result == NSFileHandlingPanelOKButton)
        {
            NSString *path = [[panel URL] path];
            [aContent writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
    }];
    
    
}




- (IBAction)touchSave:(id)sender {
    
    
    if (_filePathStr.length == 0) {
        
        NSLog(@"请先添加文件");
        return;
        
    }
    
    
    //    GNFDRSA.publicKeyStr = 
    
    
    NSString *content = [NSString stringWithContentsOfFile:_filePathStr encoding:NSUTF8StringEncoding error:nil];
    NSLog(@"read success: %@",content);
    
    NSString *encryptStr = [GNFDRSA encryptByRsa:content withKeyType:KeyTypePrivate];
    
    
    NSSavePanel*    panel = [NSSavePanel savePanel];
    [panel setNameFieldStringValue:@"Untitle"];
    [panel setMessage:@"Choose the path to save the document"];
    [panel setAllowsOtherFileTypes:YES];
    //    [panel setAllowedFileTypes:@[@"onecodego"]];
    [panel setExtensionHidden:YES];
    [panel setCanCreateDirectories:YES];
    [panel beginSheetModalForWindow:[[self view] window] completionHandler:^(NSInteger result){
        if (result == NSFileHandlingPanelOKButton)
        {
            NSString *path = [[panel URL] path];
            [encryptStr writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
        }
    }];
    
    
}




- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];
    
    // Update the view, if already loaded.
}

@end
