//
//  NetconWrapper.cpp
//  Netcon-iOS
//
//  Created by Joseph Henry on 2/14/16.
//  Copyright © 2016 ZeroTier. All rights reserved.
//

#include "NetconWrapper.hpp"

extern "C" {

#include "Intercept.h"

}

extern "C" int start_intercept() {
    init_new_intercept_no_spawn(111);
    return 1;
}


#include "OneServiceSetup.hpp"

extern "C" int start_service(const char * path) {
    init_new_service(path);
    return 1;
}