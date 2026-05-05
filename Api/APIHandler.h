#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@interface APIHandler : NSObject

// Validate key on login
+ (void)validateKey:(NSString *)key completion:(void (^)(BOOL success, NSString *message, NSString *expiry))completion;

// Fetch offsets from server — call after validateKey succeeds
// If server disabled offsets or sent fake ones → auto crash
+ (void)fetchOffsets:(void (^)(NSDictionary *offsets))completion;

// Periodic check — auto-started via __attribute__((constructor)) in APIHandler.mm
// No need to call manually from anywhere
+ (void)startPeriodicCheckLoop;
+ (void)periodicCheck;

// Storage helpers
+ (void)saveKey:(NSString *)key;
+ (NSString *)getSavedKey;
+ (void)saveExpiry:(NSString *)expiry;
+ (NSString *)getSavedExpiry;
+ (NSString *)getHWID;

@end
