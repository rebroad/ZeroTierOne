//
//  ProxyKitTest.h
//  EvoVideoPlayer
//
//  Created by Joseph Henry on 2/27/16.
//  Copyright © 2016 Evo Inc. All rights reserved.
//

#ifndef ProxyKitTest_h
#define ProxyKitTest_h

@import ProxyKit;

@interface ProxyKitTest : NSObject

@property (nonatomic, strong) SOCKSProxy *proxy;
@property (nonatomic, strong) GCDAsyncProxySocket *clientSocket;
@property (nonatomic) uint16_t portNumber;

- (void) start_proxy_server;
- (void) tearDown;
- (void) testClientInitialization;

@end

#endif /* ProxyKitTest_h */




