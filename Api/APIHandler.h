#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import "SecurityManager.h"

@interface APIHandler : NSObject

// Validate key on login
+ (void)validateKey:(NSString *)key completion:(void (^)(BOOL success, NSString *message, NSString *expiry))completion;

// Fetch offsets from server - call after validateKey succeeds
+ (void)fetchOffsets:(void (^)(NSDictionary *offsets))completion;

// Periodic check - auto-started via __attribute__((constructor))
+ (void)startPeriodicCheckLoop;
+ (void)periodicCheck;

// Storage helpers
+ (void)saveKey:(NSString *)key;
+ (NSString *)getSavedKey;
+ (void)saveExpiry:(NSString *)expiry;
+ (NSString *)getSavedExpiry;
+ (NSString *)getHWID;

// Security toggles
+ (void)enableSecurityCheck:(SecurityCheckFlags)check;
+ (void)disableSecurityCheck:(SecurityCheckFlags)check;

// Device ID mode (UDID vs vendor ID vs fingerprint)
typedef NS_ENUM(NSUInteger, DeviceIDMode) {
    DeviceIDModeVendor      = 0,
    DeviceIDModeFingerprint = 1,
    DeviceIDModeComposite   = 2
};
+ (void)setDeviceIDMode:(DeviceIDMode)mode;
+ (NSString *)getDeviceID;

// Fetch security config from server and apply toggles
+ (void)fetchSecurityConfig;

// Login alert with dynamic package name
+ (void)showLoginAlertOnViewController:(UIViewController *)vc;

@end
