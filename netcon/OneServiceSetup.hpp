//
//  Mock.hpp
//  ZTNC
//
//  Created by Joseph Henry on 2/1/16.
//  Copyright © 2016 ZeroTier. All rights reserved.
//

#ifndef ONE_SERVICE_SETUP_HPP
#define ONE_SERVICE_SETUP_HPP

void init_service(int key, const char * path);
void init_intercept(int key);
void *start_OneService(void *thread_id);

#endif
