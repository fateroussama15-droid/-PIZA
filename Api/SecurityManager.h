#import <Foundation/Foundation.h>

typedef NS_OPTIONS(NSUInteger, SecurityCheckFlags) {
    SecurityCheckNone             = 0,
    SecurityCheckAntiDylibInject  = 1 << 0,
    SecurityCheckAntiDebInject    = 1 << 1,
    SecurityCheckAntiFramework    = 1 << 2,
    SecurityCheckAntiDebugger     = 1 << 3,
    SecurityCheckAntiJailbreak    = 1 << 4,
    SecurityCheckIntegrityCheck   = 1 << 5,
    SecurityCheckAll              = 0xFFFFFFFF
};

@interface SecurityManager : NSObject

@property (class, nonatomic, assign) SecurityCheckFlags enabledChecks;

+ (BOOL)isDylibInjected;
+ (BOOL)isDebInjected;
+ (BOOL)isFrameworkInjected;
+ (BOOL)isDebuggerAttached;
+ (BOOL)isJailbroken;
+ (BOOL)isCodeIntegrityValid;

+ (BOOL)runAllEnabledChecks;

+ (void)enableCheck:(SecurityCheckFlags)check;
+ (void)disableCheck:(SecurityCheckFlags)check;
+ (BOOL)isCheckEnabled:(SecurityCheckFlags)check;

+ (NSString *)decryptString:(NSString *)encrypted withKey:(NSUInteger)key;
+ (NSString *)encryptString:(NSString *)plaintext withKey:(NSUInteger)key;

+ (NSString *)deviceFingerprint;

@end
