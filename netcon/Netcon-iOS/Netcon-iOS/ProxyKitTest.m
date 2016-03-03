//
//  ProxyKitTest.m
//  Netcon-iOS
//
//  Created by Joseph Henry on 2/25/16.
//  Copyright © 2016 ZeroTier. All rights reserved.
//

#import <Foundation/Foundation.h>
@import ProxyKit;

#import "ProxyKitTest.h"


@implementation ProxyKitTest

- (void) start_proxy_server
{
    NSError *error = nil;
    self.proxy = [[SOCKSProxy alloc] init];
    self.proxy.delegate = self;
    self.proxy.callbackQueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
    BOOL success = [self.proxy startProxyOnPort:1337 error:&error];
    
    //if(success)
    //    printf("success = %d\n", success);
    if(!success)
        NSLog(@" error => %@ ", [error localizedDescription]);
}

- (void)tearDown
{
    printf("tearDown()\n");
    if (self.proxy) {
        [self.proxy disconnect];
    }
}

- (void)testClientInitialization
{
    printf("Proxy.testClientInitialization()\n");
    NSError *error = nil;
    self.clientSocket = [[GCDAsyncProxySocket alloc] initWithDelegate:self delegateQueue:dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0)];
    [self.clientSocket setProxyHost:@"localhost" port:1337 version:GCDAsyncSocketSOCKSVersion5];
    BOOL success = [self.clientSocket connectToHost:@"http://10.242.211.245/" onPort:80 error:&error];
    
    NSString * getRequest = @"GET / HTTP/1.0\r\n\r\n";
    NSData *data = [getRequest dataUsingEncoding:NSUTF8StringEncoding];
    [self.clientSocket writeData:data withTimeout:-1 tag:111222];
    
    //if(success)
    //    printf("success = %d\n", success);
    if(!success)
        NSLog(@" error => %@ ", [error localizedDescription]);
}

@end