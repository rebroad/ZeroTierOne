//
//  NetconWrapper.cpp
//  Netcon-iOS
//
//  Created by Joseph Henry on 2/14/16.
//  Copyright © 2016 ZeroTier. All rights reserved.
//

#include "NetconWrapper.hpp"

#define INTERCEPT_ENABLED   111
#define INTERCEPT_DISABLED  222

#include "NetconServiceSetup.hpp"

// Starts a service at the specified path
extern "C" int start_service(const char * path) {
    init_service(INTERCEPT_DISABLED, path);
    return 1;
}