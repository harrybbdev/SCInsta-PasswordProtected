#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import "PassStore.h"
static NSString *const kService = @"com.scinsta.passlock";
static NSString *const kAccount = @"user";

NSString *PSReadPass(void) {
    NSDictionary *q = @{ (__bridge id)kSecClass:            (__bridge id)kSecClassGenericPassword,
                         (__bridge id)kSecAttrService:       kService,
                         (__bridge id)kSecAttrAccount:       kAccount,
                         (__bridge id)kSecReturnData:        @YES };
    CFTypeRef data = NULL;
    if (SecItemCopyMatching((__bridge CFDictionaryRef)q, &data) == errSecSuccess) {
        NSString *p = [[NSString alloc] initWithData:(__bridge_transfer NSData*)data
                                            encoding:NSUTF8StringEncoding];
        return p;
    }
    return nil;
}

BOOL PSWritePass(NSString *pass) {
    NSData *d = [pass dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *attrs = @{ (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
                             (__bridge id)kSecAttrService: kService,
                             (__bridge id)kSecAttrAccount: kAccount };
    SecItemDelete((__bridge CFDictionaryRef)attrs);                 // clean old
    NSDictionary *add = @{ (__bridge id)kSecClass:       (__bridge id)kSecClassGenericPassword,
                           (__bridge id)kSecAttrService: kService,
                           (__bridge id)kSecAttrAccount: kAccount,
                           (__bridge id)kSecValueData:  d };
    return SecItemAdd((__bridge CFDictionaryRef)add, NULL) == errSecSuccess;
}
