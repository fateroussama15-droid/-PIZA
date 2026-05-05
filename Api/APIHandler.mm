#import "APIHandler.h"
#import <AdSupport/AdSupport.h>
#include <mach-o/dyld.h>


@implementation APIHandler

+ (NSString *)getHWID {
    return [[[UIDevice currentDevice] identifierForVendor] UUIDString];
}

+ (void)saveKey:(NSString *)key {
    [[NSUserDefaults standardUserDefaults] setObject:key forKey:@"Zoldik_Saved_Key"];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

+ (NSString *)getSavedKey {
    return [[NSUserDefaults standardUserDefaults] stringForKey:@"Zoldik_Saved_Key"];
}

+ (void)saveExpiry:(NSString *)expiry {
    [[NSUserDefaults standardUserDefaults] setObject:expiry forKey:@"Zoldik_Saved_Expiry"];
    [[NSUserDefaults standardUserDefaults] synchronize];
}

+ (NSString *)getSavedExpiry {
    return [[NSUserDefaults standardUserDefaults] stringForKey:@"Zoldik_Saved_Expiry"];
}

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

+ (void)validateKey:(NSString *)key completion:(void (^)(BOOL success, NSString *message, NSString *expiry))completion {
    if (!key || key.length == 0) {
        dispatch_async(dispatch_get_main_queue(), ^{ completion(NO, @"No API key entered", nil); });
        return;
    }

    NSString *deviceId    = [self getHWID];
    NSString *encodedKey  = [key stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
    NSString *encodedDev  = [deviceId stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
    NSString *urlString   = [NSString stringWithFormat:@"https://a11806-37c5.xs001.jrnm.app/validate?api_key=%@&device_id=%@", encodedKey, encodedDev];

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlString]];
    request.HTTPMethod      = @"GET";
    request.timeoutInterval = 12.0;

    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
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

        NSString *welcomeMsg = [NSString stringWithFormat:
            @"Welcome to Zoldik!\n\nPackage: %@\nExpires at: %@\nTime left: %@\nDevices: %@",
            pkg, expiresAt, remaining, devices];

        [self saveKey:key];
        [self saveExpiry:expiresAt];

        dispatch_async(dispatch_get_main_queue(), ^{ completion(YES, welcomeMsg, expiresAt); });
    }];

    [task resume];
}

+ (void)fetchOffsets:(void (^)(NSDictionary *offsets))completion {
    NSString *key = [self getSavedKey];
    if (!key) { if (completion) completion(nil); return; }

    NSString *encodedKey = [key stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
    NSString *urlString  = [NSString stringWithFormat:@"https://a11806-37c5.xs001.jrnm.app/get-offsets?api_key=%@", encodedKey];

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlString]];
    request.HTTPMethod      = @"GET";
    request.timeoutInterval = 10.0;

    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
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

+ (void)periodicCheck {
    NSString *key = [self getSavedKey];
    if (!key) return;

    NSString *deviceId   = [self getHWID];
    NSString *encodedKey = [key stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
    NSString *encodedDev = [deviceId stringByAddingPercentEncodingWithAllowedCharacters:[NSCharacterSet URLQueryAllowedCharacterSet]];
    NSString *urlString  = [NSString stringWithFormat:@"https://a11806-37c5.xs001.jrnm.app/validate?api_key=%@&device_id=%@", encodedKey, encodedDev];

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:urlString]];
    request.HTTPMethod      = @"GET";
    request.timeoutInterval = 8.0;

    NSURLSessionDataTask *task = [[NSURLSession sharedSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
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

@end

__attribute__((constructor)) static void ZoldikAPIHandlerInit() {
    [APIHandler startPeriodicCheckLoop];
}
