#import "APIHandler.h"
#import "SecurityManager.h"
#import <AdSupport/AdSupport.h>
#include <mach-o/dyld.h>
#import <CommonCrypto/CommonDigest.h>

#define ENCRYPTION_KEY 0xA7B3C9D5E1F20864ULL

static DeviceIDMode _currentDeviceIDMode = DeviceIDModeVendor;
static NSString *_cachedPackageName = nil;

static NSString *_encryptedAPIBaseURL = nil;
static NSString *_encryptedValidateEndpoint = nil;
static NSString *_encryptedOffsetsEndpoint = nil;

@implementation APIHandler

#pragma mark - Encrypted URL Management

+ (void)initialize {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _encryptedAPIBaseURL = [SecurityManager encryptString:@"https://a11806-37c5.xs001.jrnm.app"
                                                     withKey:ENCRYPTION_KEY];
        _encryptedValidateEndpoint = [SecurityManager encryptString:@"/validate"
                                                            withKey:ENCRYPTION_KEY];
        _encryptedOffsetsEndpoint = [SecurityManager encryptString:@"/get-offsets"
                                                           withKey:ENCRYPTION_KEY];
    });
}

+ (NSString *)apiBaseURL {
    return [SecurityManager decryptString:_encryptedAPIBaseURL withKey:ENCRYPTION_KEY];
}

+ (NSString *)validateEndpoint {
    return [SecurityManager decryptString:_encryptedValidateEndpoint withKey:ENCRYPTION_KEY];
}

+ (NSString *)offsetsEndpoint {
    return [SecurityManager decryptString:_encryptedOffsetsEndpoint withKey:ENCRYPTION_KEY];
}

+ (NSString *)buildURLWithEndpoint:(NSString *)endpoint params:(NSDictionary *)params {
    NSString *base = [self apiBaseURL];
    NSMutableString *url = [NSMutableString stringWithFormat:@"%@%@", base, endpoint];
    if (params.count > 0) {
        [url appendString:@"?"];
        NSMutableArray *pairs = [NSMutableArray array];
        for (NSString *key in params) {
            NSString *encodedVal = [params[key] stringByAddingPercentEncodingWithAllowedCharacters:
                                    [NSCharacterSet URLQueryAllowedCharacterSet]];
            [pairs addObject:[NSString stringWithFormat:@"%@=%@", key, encodedVal]];
        }
        [url appendString:[pairs componentsJoinedByString:@"&"]];
    }
    return [url copy];
}

#pragma mark - Device ID Mode

+ (void)setDeviceIDMode:(DeviceIDMode)mode {
    _currentDeviceIDMode = mode;
}

+ (NSString *)getDeviceID {
    switch (_currentDeviceIDMode) {
        case DeviceIDModeVendor:
            return [self getHWID];
        case DeviceIDModeFingerprint:
            return [SecurityManager deviceFingerprint];
        case DeviceIDModeComposite: {
            NSString *vendor = [self getHWID];
            NSString *fingerprint = [SecurityManager deviceFingerprint];
            NSString *combined = [NSString stringWithFormat:@"%@:%@", vendor, fingerprint];
            NSData *data = [combined dataUsingEncoding:NSUTF8StringEncoding];
            unsigned char hash[CC_SHA256_DIGEST_LENGTH];
            CC_SHA256(data.bytes, (CC_LONG)data.length, hash);
            NSMutableString *result = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
            for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
                [result appendFormat:@"%02x", hash[i]];
            }
            return [result copy];
        }
    }
    return [self getHWID];
}

#pragma mark - HWID

+ (NSString *)getHWID {
    return [[[UIDevice currentDevice] identifierForVendor] UUIDString];
}

#pragma mark - Key Storage (encrypted)

+ (NSString *)storageKeyPrefix {
    NSString *bundleId = [[NSBundle mainBundle] bundleIdentifier] ?: @"com.unknown.app";
    NSData *data = [bundleId dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char hash[CC_MD5_DIGEST_LENGTH];
    CC_MD5(data.bytes, (CC_LONG)data.length, hash);
    return [NSString stringWithFormat:@"%02x%02x%02x%02x", hash[0], hash[1], hash[2], hash[3]];
}

+ (void)saveKey:(NSString *)key {
    NSString *encKey = [SecurityManager encryptString:key withKey:ENCRYPTION_KEY];
    NSString *storageKey = [NSString stringWithFormat:@"%@_sk", [self storageKeyPrefix]];
    [[NSUserDefaults standardUserDefaults] setObject:encKey forKey:storageKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

+ (NSString *)getSavedKey {
    NSString *storageKey = [NSString stringWithFormat:@"%@_sk", [self storageKeyPrefix]];
    NSString *encKey = [[NSUserDefaults standardUserDefaults] stringForKey:storageKey];
    if (!encKey) return nil;
    return [SecurityManager decryptString:encKey withKey:ENCRYPTION_KEY];
}

+ (void)saveExpiry:(NSString *)expiry {
    NSString *encExpiry = [SecurityManager encryptString:expiry withKey:ENCRYPTION_KEY];
    NSString *storageKey = [NSString stringWithFormat:@"%@_se", [self storageKeyPrefix]];
    [[NSUserDefaults standardUserDefaults] setObject:encExpiry forKey:storageKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

+ (NSString *)getSavedExpiry {
    NSString *storageKey = [NSString stringWithFormat:@"%@_se", [self storageKeyPrefix]];
    NSString *encExpiry = [[NSUserDefaults standardUserDefaults] stringForKey:storageKey];
    if (!encExpiry) return nil;
    return [SecurityManager decryptString:encExpiry withKey:ENCRYPTION_KEY];
}

+ (void)savePackageName:(NSString *)pkg {
    _cachedPackageName = [pkg copy];
    NSString *encPkg = [SecurityManager encryptString:pkg withKey:ENCRYPTION_KEY];
    NSString *storageKey = [NSString stringWithFormat:@"%@_sp", [self storageKeyPrefix]];
    [[NSUserDefaults standardUserDefaults] setObject:encPkg forKey:storageKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

+ (NSString *)getSavedPackageName {
    if (_cachedPackageName) return _cachedPackageName;
    NSString *storageKey = [NSString stringWithFormat:@"%@_sp", [self storageKeyPrefix]];
    NSString *encPkg = [[NSUserDefaults standardUserDefaults] stringForKey:storageKey];
    if (!encPkg) return nil;
    _cachedPackageName = [SecurityManager decryptString:encPkg withKey:ENCRYPTION_KEY];
    return _cachedPackageName;
}

#pragma mark - Security Toggles

+ (void)enableSecurityCheck:(SecurityCheckFlags)check {
    [SecurityManager enableCheck:check];
}

+ (void)disableSecurityCheck:(SecurityCheckFlags)check {
    [SecurityManager disableCheck:check];
}

#pragma mark - Crash / Freeze

+ (void)executeCrashWithOffset:(NSString *)offsetStr {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (offsetStr && offsetStr.length > 0) {
            uint64_t offset = strtoull([offsetStr UTF8String], NULL, 16);
            if (offset > 0) {
                uint64_t slide = (uint64_t)_dyld_get_image_vmaddr_slide(0);
                typedef void (*crash_fn_t)(void*, void*, void*, void*);
                crash_fn_t fn = (crash_fn_t)(offset + slide);
                fn(NULL, NULL, NULL, NULL);
                return;
            }
        }
        volatile int *null_ptr = NULL;
        *null_ptr = 0;
    });
}

+ (void)executeCrash {
    [self executeCrashWithOffset:nil];
}

+ (void)executeFreeze {
    dispatch_async(dispatch_get_main_queue(), ^{
        [[NSNotificationCenter defaultCenter]
            postNotificationName:@"ZoldikFreezePanel" object:nil];
    });
}

+ (void)handleAction:(NSString *)action withOffset:(NSString *)offset {
    if ([action isEqualToString:@"crash"])  { [self executeCrashWithOffset:offset]; return; }
    if ([action isEqualToString:@"freeze"]) { [self executeFreeze]; return; }
}

#pragma mark - Security Pre-check

+ (BOOL)performSecurityPreCheck {
    if (![SecurityManager runAllEnabledChecks]) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(arc4random_uniform(3) * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            [self executeCrash];
        });
        return NO;
    }
    return YES;
}

#pragma mark - Request Signing

+ (NSString *)signRequest:(NSString *)urlString {
    NSTimeInterval timestamp = [[NSDate date] timeIntervalSince1970];
    NSString *raw = [NSString stringWithFormat:@"%@|%.0f|%@", urlString, timestamp, [self getDeviceID]];
    NSData *data = [raw dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, hash);
    NSMutableString *sig = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [sig appendFormat:@"%02x", hash[i]];
    }
    return [sig copy];
}

#pragma mark - Validate Key

+ (void)validateKey:(NSString *)key completion:(void (^)(BOOL success, NSString *message, NSString *expiry))completion {
    if (![self performSecurityPreCheck]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            completion(NO, @"Security check failed", nil);
        });
        return;
    }

    if (!key || key.length == 0) {
        dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, @"No API key entered", nil); });
        return;
    }

    NSString *deviceId = [self getDeviceID];
    NSString *urlString = [self buildURLWithEndpoint:[self validateEndpoint]
                                              params:@{
        @"api_key": key,
        @"device_id": deviceId
    }];

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlString]];
    request.HTTPMethod = @"GET";
    request.timeoutInterval = 12.0;

    NSString *signature = [self signRequest:urlString];
    [request setValue:signature forHTTPHeaderField:@"X-Request-Signature"];
    [request setValue:[NSString stringWithFormat:@"%.0f", [[NSDate date] timeIntervalSince1970]]
   forHTTPHeaderField:@"X-Timestamp"];
    [request setValue:[self getDeviceID] forHTTPHeaderField:@"X-Device-Fingerprint"];

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    config.URLCache = nil;
    config.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config];

    NSURLSessionDataTask *task = [session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                completion(NO, [NSString stringWithFormat:@"Network error: %@", error.localizedDescription], nil);
            });
            return;
        }

        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
        NSDictionary *json = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;

        if (httpResp.statusCode == 403) {
            NSString *action = json[@"action"];
            if (action) { [self handleAction:action withOffset:json[@"crash_offset"]]; return; }
            NSString *msg = @"Invalid key, expired, max devices reached, or already used";
            dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, msg, nil); });
            return;
        }

        if (httpResp.statusCode != 200 || !json || ![json isKindOfClass:[NSDictionary class]]) {
            NSString *msg = [NSString stringWithFormat:@"Server responded with status %ld", (long)httpResp.statusCode];
            dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, msg, nil); });
            return;
        }

        NSString *action = json[@"action"] ?: @"run";
        if (![action isEqualToString:@"run"]) {
            [self handleAction:action withOffset:json[@"crash_offset"]];
            return;
        }

        if (![json[@"status"] isEqualToString:@"valid"]) {
            NSString *detail = json[@"detail"] ?: @"Validation failed";
            dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, detail, nil); });
            return;
        }

        NSString *expiresAt = json[@"expires_at"] ?: json[@"expiry"] ?: @"Unknown";
        NSString *remaining = json[@"remaining"] ?: @"N/A";
        NSString *devices   = json[@"devices"]   ?: @"N/A";
        NSString *pkg       = json[@"package"]   ?: @"Standard";

        [self savePackageName:pkg];

        NSString *welcomeMsg = [NSString stringWithFormat:
            @"Welcome to %@!\n\nPackage: %@\nExpires at: %@\nTime left: %@\nDevices: %@",
            pkg, pkg, expiresAt, remaining, devices];

        [self saveKey:key];
        [self saveExpiry:expiresAt];

        dispatch_async(dispatch_get_main_queue(), ^{ completion(YES, welcomeMsg, expiresAt); });
    }];

    [task resume];
}

#pragma mark - Fetch Offsets

+ (void)fetchOffsets:(void (^)(NSDictionary *offsets))completion {
    if (![self performSecurityPreCheck]) {
        if (completion) completion(nil);
        return;
    }

    NSString *key = [self getSavedKey];
    if (!key) { if (completion) completion(nil); return; }

    NSString *urlString = [self buildURLWithEndpoint:[self offsetsEndpoint]
                                              params:@{@"api_key": key}];

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlString]];
    request.HTTPMethod = @"GET";
    request.timeoutInterval = 10.0;

    NSString *signature = [self signRequest:urlString];
    [request setValue:signature forHTTPHeaderField:@"X-Request-Signature"];
    [request setValue:[self getDeviceID] forHTTPHeaderField:@"X-Device-Fingerprint"];

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    config.URLCache = nil;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config];

    NSURLSessionDataTask *task = [session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
        if (!data || error || httpResp.statusCode != 200) {
            [self executeCrash]; return;
        }
        NSDictionary *json    = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        NSDictionary *offsets = json[@"offsets"];
        if (!offsets || offsets.count == 0) { [self executeCrash]; return; }
        if (completion) dispatch_async(dispatch_get_main_queue(), ^{ completion(offsets); });
    }];

    [task resume];
}

#pragma mark - Fetch Security Config from Server

+ (void)fetchSecurityConfig {
    NSString *key = [self getSavedKey];
    if (!key) return;

    NSString *encSecEndpoint = [SecurityManager encryptString:@"/security-config" withKey:ENCRYPTION_KEY];
    NSString *secEndpoint = [SecurityManager decryptString:encSecEndpoint withKey:ENCRYPTION_KEY];

    NSString *urlString = [self buildURLWithEndpoint:secEndpoint
                                              params:@{@"api_key": key}];

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlString]];
    request.HTTPMethod = @"GET";
    request.timeoutInterval = 10.0;

    NSString *signature = [self signRequest:urlString];
    [request setValue:signature forHTTPHeaderField:@"X-Request-Signature"];
    [request setValue:[self getDeviceID] forHTTPHeaderField:@"X-Device-Fingerprint"];

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    config.URLCache = nil;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config];

    NSURLSessionDataTask *task = [session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error || !data) return;
        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
        if (httpResp.statusCode != 200) return;

        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        if (!json || ![json isKindOfClass:[NSDictionary class]]) return;

        NSDictionary *secConfig = json[@"security"];
        if (!secConfig || ![secConfig isKindOfClass:[NSDictionary class]]) return;

        BOOL antiInject = [secConfig[@"anti_inject"] boolValue];
        if (antiInject) {
            [SecurityManager setEnabledChecks:SecurityCheckAll];
        } else {
            [SecurityManager setEnabledChecks:SecurityCheckNone];
        }

        BOOL dylibCrash = [secConfig[@"dylib_crash"] boolValue];
        if (dylibCrash) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self executeCrash];
            });
            return;
        }
    }];

    [task resume];
}

#pragma mark - Periodic Check

+ (void)periodicCheck {
    if (![SecurityManager runAllEnabledChecks]) {
        [self executeCrash];
        return;
    }

    NSString *key = [self getSavedKey];
    if (!key) return;

    NSString *deviceId = [self getDeviceID];
    NSString *urlString = [self buildURLWithEndpoint:[self validateEndpoint]
                                              params:@{
        @"api_key": key,
        @"device_id": deviceId
    }];

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlString]];
    request.HTTPMethod = @"GET";
    request.timeoutInterval = 8.0;

    NSString *signature = [self signRequest:urlString];
    [request setValue:signature forHTTPHeaderField:@"X-Request-Signature"];
    [request setValue:[self getDeviceID] forHTTPHeaderField:@"X-Device-Fingerprint"];

    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    config.URLCache = nil;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config];

    NSURLSessionDataTask *task = [session dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        if (error) return;
        NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)response;
        NSDictionary *json = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
        if (httpResp.statusCode == 403) {
            NSString *action = json[@"action"];
            if (action) [self handleAction:action withOffset:json[@"crash_offset"]];
            return;
        }
        if (httpResp.statusCode == 200 && json) {
            NSString *action = json[@"action"] ?: @"run";
            if (![action isEqualToString:@"run"]) [self handleAction:action withOffset:json[@"crash_offset"]];
        }
    }];

    [task resume];
}

+ (void)startPeriodicCheckLoop {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        [NSThread sleepForTimeInterval:30.0];
        while (YES) {
            [APIHandler fetchSecurityConfig];
            [APIHandler periodicCheck];
            [APIHandler fetchOffsets:^(NSDictionary *offsets) {
                if (offsets) {
                    [[NSNotificationCenter defaultCenter]
                        postNotificationName:@"ZoldikRefreshOffsets"
                        object:offsets];
                }
            }];
            [NSThread sleepForTimeInterval:60.0];
        }
    });
}

#pragma mark - Login Alert (Dynamic Package Name)

+ (void)showLoginAlertOnViewController:(UIViewController *)vc {
    if (![self performSecurityPreCheck]) return;

    NSString *pkgName = [self getSavedPackageName];
    if (!pkgName || pkgName.length == 0) {
        pkgName = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleDisplayName"]
                  ?: [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleName"]
                  ?: @"App";
    }

    NSString *titleText = [NSString stringWithFormat:@"%@ Login", pkgName];

    NSString *encTitle = [SecurityManager encryptString:titleText withKey:ENCRYPTION_KEY];
    NSString *encPlaceholder = [SecurityManager encryptString:@"Enter your API key" withKey:ENCRYPTION_KEY];
    NSString *encLogin = [SecurityManager encryptString:@"Login" withKey:ENCRYPTION_KEY];
    NSString *encCancel = [SecurityManager encryptString:@"Cancel" withKey:ENCRYPTION_KEY];

    NSString *decTitle = [SecurityManager decryptString:encTitle withKey:ENCRYPTION_KEY];
    NSString *decPlaceholder = [SecurityManager decryptString:encPlaceholder withKey:ENCRYPTION_KEY];
    NSString *decLogin = [SecurityManager decryptString:encLogin withKey:ENCRYPTION_KEY];
    NSString *decCancel = [SecurityManager decryptString:encCancel withKey:ENCRYPTION_KEY];

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:decTitle
                                                                  message:nil
                                                           preferredStyle:UIAlertControllerStyleAlert];

    [alert addTextFieldWithConfigurationHandler:^(UITextField *textField) {
        textField.placeholder = decPlaceholder;
        textField.secureTextEntry = YES;
        textField.autocorrectionType = UITextAutocorrectionTypeNo;
        textField.autocapitalizationType = UITextAutocapitalizationTypeNone;
    }];

    UIAlertAction *loginAction = [UIAlertAction actionWithTitle:decLogin
                                                          style:UIAlertActionStyleDefault
                                                        handler:^(UIAlertAction *action) {
        NSString *key = alert.textFields.firstObject.text;
        [self validateKey:key completion:^(BOOL success, NSString *message, NSString *expiry) {
            UIAlertController *resultAlert = [UIAlertController
                alertControllerWithTitle:success ? @"Success" : @"Error"
                                 message:message
                          preferredStyle:UIAlertControllerStyleAlert];
            [resultAlert addAction:[UIAlertAction actionWithTitle:@"OK"
                                                           style:UIAlertActionStyleDefault
                                                         handler:^(UIAlertAction *a) {
                if (!success) {
                    [self showLoginAlertOnViewController:vc];
                }
            }]];
            [vc presentViewController:resultAlert animated:YES completion:nil];
        }];
    }];

    UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:decCancel
                                                           style:UIAlertActionStyleCancel
                                                         handler:nil];

    [alert addAction:loginAction];
    [alert addAction:cancelAction];

    dispatch_async(dispatch_get_main_queue(), ^{
        [vc presentViewController:alert animated:YES completion:nil];
    });
}

@end

__attribute__((constructor)) static void ZoldikAPIHandlerInit() {
    if (![SecurityManager runAllEnabledChecks]) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{
            volatile int *p = NULL;
            *p = 0;
        });
        return;
    }
    [APIHandler startPeriodicCheckLoop];
}
