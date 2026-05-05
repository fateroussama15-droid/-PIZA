#import "SecurityManager.h"
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <unistd.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/utsname.h>

static SecurityCheckFlags _enabledChecks = SecurityCheckAll;

@implementation SecurityManager

#pragma mark - Toggle Management

+ (SecurityCheckFlags)enabledChecks {
    return _enabledChecks;
}

+ (void)setEnabledChecks:(SecurityCheckFlags)flags {
    _enabledChecks = flags;
}

+ (void)enableCheck:(SecurityCheckFlags)check {
    _enabledChecks |= check;
}

+ (void)disableCheck:(SecurityCheckFlags)check {
    _enabledChecks &= ~check;
}

+ (BOOL)isCheckEnabled:(SecurityCheckFlags)check {
    return (_enabledChecks & check) != 0;
}

#pragma mark - Anti Dylib Injection

+ (BOOL)isDylibInjected {
    if (![self isCheckEnabled:SecurityCheckAntiDylibInject]) return NO;

    uint32_t count = _dyld_image_count();
    NSArray *suspiciousPatterns = @[
        @"MobileSubstrate",
        @"SubstrateLoader",
        @"SubstrateInserter",
        @"CydiaSubstrate",
        @"libcycript",
        @"cynject",
        @"libReveal",
        @"libFLEX",
        @"FridaGadget",
        @"frida-agent",
        @"SSLKillSwitch",
        @"Shadow.dylib",
        @"Choicy",
        @"TweakInject",
        @"ElleKit",
        @"substitute",
        @"libhooker",
        @"Dopamine",
        @"roothide"
    ];

    for (uint32_t i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (!imageName) continue;
        NSString *name = [NSString stringWithUTF8String:imageName];
        for (NSString *pattern in suspiciousPatterns) {
            if ([name localizedCaseInsensitiveContainsString:pattern]) {
                return YES;
            }
        }
    }

    void *substrate = dlopen("/Library/MobileSubstrate/MobileSubstrate.dylib", RTLD_NOLOAD);
    if (substrate) {
        dlclose(substrate);
        return YES;
    }

    void *libhooker = dlopen("/usr/lib/libhooker.dylib", RTLD_NOLOAD);
    if (libhooker) {
        dlclose(libhooker);
        return YES;
    }

    void *ellekit = dlopen("/usr/lib/libellekit.dylib", RTLD_NOLOAD);
    if (ellekit) {
        dlclose(ellekit);
        return YES;
    }

    if (dlsym(RTLD_DEFAULT, "MSHookFunction") != NULL) return YES;
    if (dlsym(RTLD_DEFAULT, "MSHookMessageEx") != NULL) return YES;
    if (dlsym(RTLD_DEFAULT, "LHHookFunction") != NULL) return YES;
    if (dlsym(RTLD_DEFAULT, "SubGetImageByName") != NULL) return YES;

    return NO;
}

#pragma mark - Anti Deb Injection

+ (BOOL)isDebInjected {
    if (![self isCheckEnabled:SecurityCheckAntiDebInject]) return NO;

    NSArray *debPaths = @[
        @"/Library/MobileSubstrate/DynamicLibraries/",
        @"/usr/lib/TweakInject/",
        @"/var/jb/Library/MobileSubstrate/DynamicLibraries/",
        @"/var/jb/usr/lib/TweakInject/",
        @"/var/LIY/",
        @"/usr/lib/substitute/",
        @"/var/jb/usr/lib/substitute/"
    ];

    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *path in debPaths) {
        if ([fm fileExistsAtPath:path]) {
            NSArray *contents = [fm contentsOfDirectoryAtPath:path error:nil];
            for (NSString *file in contents) {
                if ([file hasSuffix:@".dylib"] || [file hasSuffix:@".plist"]) {
                    return YES;
                }
            }
        }
    }

    NSArray *dpkgPaths = @[
        @"/var/lib/dpkg/info/",
        @"/var/jb/var/lib/dpkg/info/"
    ];
    for (NSString *dpkgPath in dpkgPaths) {
        if ([fm fileExistsAtPath:dpkgPath]) {
            NSArray *contents = [fm contentsOfDirectoryAtPath:dpkgPath error:nil];
            for (NSString *file in contents) {
                if ([file hasSuffix:@".list"]) {
                    NSString *fullPath = [dpkgPath stringByAppendingPathComponent:file];
                    NSString *content = [NSString stringWithContentsOfFile:fullPath encoding:NSUTF8StringEncoding error:nil];
                    if (content && [content containsString:@".dylib"]) {
                        return YES;
                    }
                }
            }
        }
    }

    return NO;
}

#pragma mark - Anti Framework Injection

+ (BOOL)isFrameworkInjected {
    if (![self isCheckEnabled:SecurityCheckAntiFramework]) return NO;

    uint32_t count = _dyld_image_count();
    NSArray *suspiciousFrameworks = @[
        @"RevealServer.framework",
        @"FLEX.framework",
        @"FLEXing.framework",
        @"FridaGadget.framework",
        @"Cycript.framework",
        @"InspectiveC.framework",
        @"Reveal.framework"
    ];

    for (uint32_t i = 0; i < count; i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (!imageName) continue;
        NSString *name = [NSString stringWithUTF8String:imageName];
        for (NSString *fw in suspiciousFrameworks) {
            if ([name containsString:fw]) {
                return YES;
            }
        }
    }

    NSArray *frameworkPaths = @[
        @"/Library/Frameworks/",
        @"/var/jb/Library/Frameworks/",
        @"/System/Library/PrivateFrameworks/"
    ];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *fwPath in frameworkPaths) {
        if ([fm fileExistsAtPath:fwPath]) {
            NSArray *contents = [fm contentsOfDirectoryAtPath:fwPath error:nil];
            for (NSString *item in contents) {
                for (NSString *suspicious in suspiciousFrameworks) {
                    if ([item isEqualToString:suspicious]) {
                        return YES;
                    }
                }
            }
        }
    }

    return NO;
}

#pragma mark - Anti Debugger

+ (BOOL)isDebuggerAttached {
    if (![self isCheckEnabled:SecurityCheckAntiDebugger]) return NO;

    int mib[4];
    struct kinfo_proc info;
    size_t infoSize = sizeof(info);

    info.kp_proc.p_flag = 0;
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();

    if (sysctl(mib, 4, &info, &infoSize, NULL, 0) == 0) {
        if ((info.kp_proc.p_flag & P_TRACED) != 0) {
            return YES;
        }
    }

    if (getppid() != 1) {
        if (isatty(STDOUT_FILENO) || isatty(STDERR_FILENO) || isatty(STDIN_FILENO)) {
            return YES;
        }
    }

    return NO;
}

#pragma mark - Anti Jailbreak

+ (BOOL)isJailbroken {
    if (![self isCheckEnabled:SecurityCheckAntiJailbreak]) return NO;

    NSArray *jailbreakPaths = @[
        @"/Applications/Cydia.app",
        @"/Applications/Sileo.app",
        @"/Applications/Zebra.app",
        @"/Applications/Installer.app",
        @"/usr/sbin/sshd",
        @"/usr/bin/ssh",
        @"/usr/libexec/ssh-keysign",
        @"/bin/bash",
        @"/usr/sbin/frida-server",
        @"/usr/bin/cycript",
        @"/usr/local/bin/cycript",
        @"/etc/apt",
        @"/etc/apt/sources.list.d/cydia.list",
        @"/private/var/lib/apt/",
        @"/private/var/lib/cydia",
        @"/private/var/mobile/Library/SBSettings/Themes",
        @"/private/var/stash",
        @"/var/jb",
        @"/var/binpack",
        @"/var/jb/usr/bin/dpkg",
        @"/var/jb/Library/dpkg/"
    ];

    struct stat statBuf;
    for (NSString *path in jailbreakPaths) {
        if (stat([path UTF8String], &statBuf) == 0) {
            return YES;
        }
    }

    if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://"]]) {
        return YES;
    }
    if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"sileo://"]]) {
        return YES;
    }

    NSError *writeError = nil;
    [@"jb_test" writeToFile:@"/private/var/jb_test.txt"
                 atomically:YES
                   encoding:NSUTF8StringEncoding
                      error:&writeError];
    if (!writeError) {
        [[NSFileManager defaultManager] removeItemAtPath:@"/private/var/jb_test.txt" error:nil];
        return YES;
    }

    if (getenv("DYLD_INSERT_LIBRARIES") != NULL) {
        return YES;
    }

    return NO;
}

#pragma mark - Code Integrity

+ (BOOL)isCodeIntegrityValid {
    if (![self isCheckEnabled:SecurityCheckIntegrityCheck]) return NO;

    NSBundle *mainBundle = [NSBundle mainBundle];
    NSString *executablePath = mainBundle.executablePath;
    if (!executablePath) return NO;

    NSData *execData = [NSData dataWithContentsOfFile:executablePath];
    if (!execData) return NO;

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(execData.bytes, (CC_LONG)execData.length, hash);

    NSString *embeddedMobileProv = [mainBundle pathForResource:@"embedded" ofType:@"mobileprovision"];
    if (!embeddedMobileProv) {
        return NO;
    }

    NSDictionary *infoPlist = mainBundle.infoDictionary;
    if (!infoPlist[@"CFBundleIdentifier"]) {
        return NO;
    }

    return YES;
}

#pragma mark - Run All Checks

+ (BOOL)runAllEnabledChecks {
    if ([self isDylibInjected]) return NO;
    if ([self isDebInjected]) return NO;
    if ([self isFrameworkInjected]) return NO;
    if ([self isDebuggerAttached]) return NO;
    if ([self isJailbroken]) return NO;
    return YES;
}

#pragma mark - String Encryption/Decryption (XOR-based)

+ (NSString *)encryptString:(NSString *)plaintext withKey:(NSUInteger)key {
    NSData *data = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableData *encrypted = [NSMutableData dataWithLength:data.length];
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    uint8_t *outBytes = (uint8_t *)encrypted.mutableBytes;

    uint8_t keyBytes[8];
    for (int i = 0; i < 8; i++) {
        keyBytes[i] = (key >> (i * 8)) & 0xFF;
    }

    for (NSUInteger i = 0; i < data.length; i++) {
        outBytes[i] = bytes[i] ^ keyBytes[i % 8];
    }

    return [encrypted base64EncodedStringWithOptions:0];
}

+ (NSString *)decryptString:(NSString *)encrypted withKey:(NSUInteger)key {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:encrypted options:0];
    if (!data) return nil;

    NSMutableData *decrypted = [NSMutableData dataWithLength:data.length];
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    uint8_t *outBytes = (uint8_t *)decrypted.mutableBytes;

    uint8_t keyBytes[8];
    for (int i = 0; i < 8; i++) {
        keyBytes[i] = (key >> (i * 8)) & 0xFF;
    }

    for (NSUInteger i = 0; i < data.length; i++) {
        outBytes[i] = bytes[i] ^ keyBytes[i % 8];
    }

    return [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
}

#pragma mark - Device Fingerprint

+ (NSString *)deviceFingerprint {
    struct utsname systemInfo;
    uname(&systemInfo);
    NSString *machine = [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding];

    NSString *vendorId = [[[UIDevice currentDevice] identifierForVendor] UUIDString];
    NSString *systemVersion = [[UIDevice currentDevice] systemVersion];
    NSString *model = [[UIDevice currentDevice] model];

    NSProcessInfo *processInfo = [NSProcessInfo processInfo];
    unsigned long long physicalMemory = processInfo.physicalMemory;
    NSUInteger processorCount = processInfo.processorCount;

    CGRect screenBounds = [[UIScreen mainScreen] bounds];
    CGFloat scale = [[UIScreen mainScreen] scale];

    NSString *raw = [NSString stringWithFormat:@"%@|%@|%@|%@|%llu|%lu|%.0fx%.0f@%.0f",
                     vendorId, machine, systemVersion, model,
                     physicalMemory, (unsigned long)processorCount,
                     screenBounds.size.width, screenBounds.size.height, scale];

    NSData *rawData = [raw dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(rawData.bytes, (CC_LONG)rawData.length, hash);

    NSMutableString *fingerprint = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [fingerprint appendFormat:@"%02x", hash[i]];
    }

    return [fingerprint copy];
}

@end
