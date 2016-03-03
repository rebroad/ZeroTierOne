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

// Performs initial symbol interposing
#include "OneServiceSetup.hpp"

// Starts a service at the specified path
extern "C" int start_service(const char * path) {
    init_service(INTERCEPT_DISABLED, path);
    return 1;
}

extern "C" void disable_intercept() {
    set_intercept_status(INTERCEPT_DISABLED);
}

extern "C" void enable_intercept() {
    set_intercept_status(INTERCEPT_ENABLED);
}