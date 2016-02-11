//
//  Common.c
//  ZTNC
//
//  Created by Joseph Henry on 1/28/16.
//  Copyright © 2016 ZeroTier. All rights reserved.
//

#include <stdio.h>
#include <netdb.h>
#include <stdarg.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
//#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/syscall.h>

#include <vector>
#include "Common.hpp"

#include "Mutex.hpp"

ZeroTier::Mutex _msg_m;
std::vector<std::string> msgs;

// Assembles and returns a debug string containing the most recent debug statements from the service
// FIXME: We should develop a better mechanism for this in production


#if defined(__APPLE__)
#include "TargetConditionals.h"
#if TARGET_IPHONE_SIMULATOR || TARGET_OS_IPHONE

std::string get_debug_msg() {
    ZeroTier::Mutex::Lock _l(_msg_m);
    
    std::string debug_str;
    
    if(msgs.size() > 0) {
        debug_str = msgs.back();
        msgs.pop_back();
    }
    return debug_str;
}

void push_msg(const char * msg)
{
    ZeroTier::Mutex::Lock _l(_msg_m);
    msgs.push_back(msg);
}

#endif
#endif




#ifdef NETCON_INTERCEPT

void print_addr(struct sockaddr *addr)
{
    char *s = NULL;
    switch(addr->sa_family) {
        case AF_INET: {
            struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
            s = malloc(INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(addr_in->sin_addr), s, INET_ADDRSTRLEN);
            break;
        }
        case AF_INET6: {
            struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
            s = malloc(INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(addr_in6->sin6_addr), s, INET6_ADDRSTRLEN);
            break;
        }
        default:
            break;
    }
    fprintf(stderr, "IP address: %s\n", s);
    free(s);
}
#endif

    void dwr(int level, const char *fmt, ... )
    {
        if(level > DEBUG_LEVEL)
            return;
        int saveerr;
        saveerr = errno;
        va_list ap;
        va_start(ap, fmt);
        
#if defined(__APPLE__)
    #include "TargetConditionals.h"
    #if TARGET_IPHONE_SIMULATOR || TARGET_OS_IPHONE
        // For pushing messages to an iOS thread watching for debug statements. FIXME: Remove for production
        char buf[100];
        memset(buf, 0, sizeof(buf));
        push_msg(fmt);
    #endif
#endif
        
#ifdef VERBOSE // So we can cut out some clutter in the strace output while debugging
        char timestring[20];
        time_t timestamp;
        timestamp = time(NULL);
        strftime(timestring, sizeof(timestring), "%H:%M:%S", localtime(&timestamp));
        pid_t tid = syscall(SYS_gettid);
        fprintf(stderr, "%s [tid=%7d] ", timestring, tid);
#endif
        vfprintf(stderr, fmt, ap);
        fflush(stderr);
        
        errno = saveerr;
        va_end(ap);
    }
