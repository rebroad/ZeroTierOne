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

#include "Common.hpp"

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
