/*
 * ZeroTier One - Network Virtualization Everywhere
 * Copyright (C) 2011-2015  ZeroTier, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * ZeroTier may be used and distributed under the terms of the GPLv3, which
 * are available at: http://www.gnu.org/licenses/gpl-3.0.html
 *
 * If you would like to embed ZeroTier into a commercial application or
 * redistribute it in a modified binary form, please contact ZeroTier Networks
 * LLC. Start here: http://www.zerotier.com/
 */

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
    
    // if(success)
        // printf("success = %d\n", success);
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
    
    // if(success)
        // printf("success = %d\n", success);
    if(!success)
        NSLog(@" error => %@ ", [error localizedDescription]);
}

@end