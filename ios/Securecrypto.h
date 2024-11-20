
#ifdef RCT_NEW_ARCH_ENABLED
#import "RNSecurecryptoSpec.h"

@interface Securecrypto : NSObject <NativeSecurecryptoSpec>
#else
#import <React/RCTBridgeModule.h>

@interface Securecrypto : NSObject <RCTBridgeModule>
#endif

@end
