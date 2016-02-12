//
//  Intercept.cpp
//  ZTNC
//
//  Created by Joseph Henry on 1/28/16.
//  Copyright © 2016 ZeroTier. All rights reserved.
//




#ifdef USE_GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <dlfcn.h>
#include <strings.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <pwd.h>
#include <errno.h>
#include <stdarg.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#if defined(__linux__)
#include <linux/errno.h>
#include <sys/syscall.h>
#include <linux/net.h> /* for NPROTO */
#endif


#ifdef __cplusplus
extern "C" {
#endif

    
#if defined(__linux__)
#define SOCK_MAX (SOCK_PACKET + 1)
#endif
#define SOCK_TYPE_MASK 0xf

#include "Intercept.h"
#include "RPC.hpp"
#include "Common.hpp"

#include "fishhook.h"

void print_addr(struct sockaddr *addr);
void dwr(int level, const char *fmt, ... );

static char *netpath = (char *)0;

// ----------------- FISH HOOK test section ---------------------------



int test_rebind()
{
    return internal_test_rebind();
}

#define SOCKET_SIG int socket_family, int socket_type, int protocol

static int (*orig_socket)(SOCKET_SIG);
int my_socket(SOCKET_SIG)
{
    printf("my socket!\n");
    return 1;
}


int internal_test_rebind()
{
    /*
    rebind_symbols((struct rebinding[1]){
        {"socket",
            (int(*)(int, int, int))&my_socket,
            (void *)&orig_socket}}, 1);
    */
    return 1;
}



/*------------------------------------------------------------------------------
 ------------------- Intercept<--->Service Comm mechanisms ----------------------
 ------------------------------------------------------------------------------*/

#define INTERCEPTED_THREAD_ID   111
#define IOS_SERVICE_THREAD_ID   222

// FIXME: 
//#include "OneServiceSetup.hpp"

/* TEST SECTION */

pthread_t intercept_thread;
int * intercept_thread_id;
pthread_key_t thr_id_key;

void *start_new_intercept(void *thread_id)
{
    //fprintf(stderr, "start_new_intercept(): tid = %d\n", pthread_mach_thread_np(pthread_self()));
    pthread_setspecific(thr_id_key, thread_id);
    set_up_intercept();
    
    int key = *((int*)pthread_getspecific(thr_id_key));
    
    //if(key == IOS_SERVICE_THREAD_ID)
    //    start_OneService();
    return NULL;
}
void init_new_intercept(int key)
{
    //fprintf(stderr, "init_new_intercept(): tid = %d\n", pthread_mach_thread_np(pthread_self()));
    pthread_key_create(&thr_id_key, NULL);
    intercept_thread_id = (int*)malloc(sizeof(int));
    *intercept_thread_id = key;
    pthread_create(&intercept_thread, NULL, start_new_intercept, (void *)(intercept_thread_id));
}

void init_new_intercept_no_spawn(int key)
{
    //fprintf(stderr, "init_new_intercept_no_spawn(): tid = %d\n", pthread_mach_thread_np(pthread_self()));
    pthread_key_create(&thr_id_key, NULL);
    intercept_thread_id = (int*)malloc(sizeof(int));
    *intercept_thread_id = key;
    start_new_intercept(intercept_thread_id);
}


/* Check whether the socket is mapped to the service or not. We
 need to know if this is a regular AF_LOCAL socket or an end of a socketpair
 that the service uses. We don't want to keep state in the intercept, so
 we simply ask the service via an RPC */

int connected_to_service(int sockfd)
{
    dwr(MSG_DEBUG,"connected_to_service():\n");
    socklen_t len;
    struct sockaddr_storage addr;
    len = sizeof addr;
    struct sockaddr_un * addr_un;
    getpeername(sockfd, (struct sockaddr*)&addr, &len);
    if (addr.ss_family == AF_LOCAL || addr.ss_family == AF_LOCAL) {
        addr_un = (struct sockaddr_un*)&addr;
        if(strcmp(addr_un->sun_path, netpath) == 0) {
            dwr(MSG_DEBUG,"connected_to_service(): Yes, %s\n", addr_un->sun_path);
            return 1;
        }
    }
    dwr(MSG_DEBUG,"connected_to_service(): Not connected to service\n");
    return 0;
}

void load_symbols()
{
    if (!realconnect) {
#if defined(__linux__)
        realaccept4 = dlsym(RTLD_NEXT, "accept4");
        realsyscall = dlsym(RTLD_NEXT, "syscall");
#endif
        realconnect = (int(*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "connect");
        realbind = (int(*)(int, const struct sockaddr *, socklen_t))dlsym(RTLD_NEXT, "bind");
        realaccept = (int(*)(int, struct sockaddr *, socklen_t *))dlsym(RTLD_NEXT, "accept");
        reallisten = (int(*)(int, int))dlsym(RTLD_NEXT, "listen");
        realsocket = (int(*)(int, int, int))dlsym(RTLD_NEXT, "socket");
        realbind = (int(*)(int, const sockaddr *, socklen_t))dlsym(RTLD_NEXT, "bind");
        realsetsockopt = (int(*)(int, int, int, const void *, socklen_t))dlsym(RTLD_NEXT, "setsockopt");
        realgetsockopt = (int(*)(int, int, int, void *, socklen_t *))dlsym(RTLD_NEXT, "getsockopt");
        realclose = (int(*)(int))dlsym(RTLD_NEXT, "close");
        realgetsockname = (int(*)(int, struct sockaddr *, socklen_t *))dlsym(RTLD_NEXT, "getsockname");
    }
}

/* get symbols and initialize mutexes */
int set_up_intercept()
{
    printf("LOADING SYMBOLS\n");
    load_symbols();
    
    void *spec = pthread_getspecific(thr_id_key);
    if(spec != NULL) {
        if(*((int*)spec) == INTERCEPTED_THREAD_ID)
        {
            if (!netpath) {
                // FIXME:
                
#if defined(__APPLE__)
    #include "TargetConditionals.h"
    #if TARGET_IPHONE_SIMULATOR
        netpath = (char*)"/iosdev/data/Library/Application Support/ZeroTier/One/nc_e5cd7a9e1c87bace";
    #elif TARGET_OS_IPHONE
        // FIXME
        // Working directory is reset to a crazy path upon startup, that is done in start_OneService and should be fixed before production
        netpath = "ZeroTier/One/nc_e5cd7a9e1c87bace";
    #endif
#endif
                
                //netpath = getenv("ZT_NC_NETWORK");
                if (!netpath)
                    return 0;
                //dwr(MSG_DEBUG,"Connecting to service at: %s\n", netpath);
                /* Hook/intercept Posix net API symbols */
                rpc_mutex_init();
            }
            return 1;
        }
    }
    return 0;
}

/*------------------------------------------------------------------------------
 --------------------------------- setsockopt() ---------------------------------
 ------------------------------------------------------------------------------*/

/* int socket, int level, int option_name, const void *option_value, socklen_t option_len */
int setsockopt(SETSOCKOPT_SIG)
{
    if (!set_up_intercept())
        return realsetsockopt(socket, level, option_name, option_value, option_len);
    
    dwr(MSG_DEBUG,"setsockopt(%d)\n", socket);
#if defined(__linux__)
    if(level == SOL_IPV6 && option_name == IPV6_V6ONLY)
        return 0;
    if(level == SOL_IP && (option_name == IP_TTL || option_name == IP_TOS))
        return 0;
#endif
    if(level == IPPROTO_TCP || (level == SOL_SOCKET && option_name == SO_KEEPALIVE))
        return 0;
    if(realsetsockopt(socket, level, option_name, option_value, option_len) < 0)
        perror("setsockopt():\n");
    return 0;
}

/*------------------------------------------------------------------------------
 --------------------------------- getsockopt() ---------------------------------
 ------------------------------------------------------------------------------*/

/* int sockfd, int level, int optname, void *optval, socklen_t *optlen */
int getsockopt(GETSOCKOPT_SIG)
{
    dwr(MSG_DEBUG,"getsockopt(%d)\n", sockfd);
    if (!set_up_intercept() || !connected_to_service(sockfd))
        return realgetsockopt(sockfd, level, optname, optval, optlen);
    if(optname == SO_TYPE) {
        int* val = (int*)optval;
        *val = 2;
        optval = (void*)val;
    }
    return 0;
}

/*------------------------------------------------------------------------------
 ----------------------------------- socket() -----------------------------------
 ------------------------------------------------------------------------------*/

/* int socket_family, int socket_type, int protocol
 socket() intercept function */
int socket(SOCKET_SIG)
{
    if (!set_up_intercept())
        return realsocket(socket_family, socket_type, protocol);
    fprintf(stderr, "socket(): tid = %d\n", pthread_mach_thread_np(pthread_self()));
    /* Check that type makes sense */
#if defined(__linux__)
    int flags = socket_type & ~SOCK_TYPE_MASK;
    if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK)) {
        errno = EINVAL;
        return -1;
    }
#endif
    socket_type &= SOCK_TYPE_MASK;
    /* Check protocol is in range */
#if defined(__linux__)
    if (socket_family < 0 || socket_family >= NPROTO){
        errno = EAFNOSUPPORT;
        return -1;
    }
    if (socket_type < 0 || socket_type >= SOCK_MAX) {
        errno = EINVAL;
        return -1;
    }
#endif
    /* TODO: detect ENFILE condition */
    if(socket_family == AF_LOCAL
#if defined(__linux__)
       || socket_family == AF_NETLINK
#endif
       || socket_family == AF_UNIX) {
        int err = realsocket(socket_family, socket_type, protocol);
        dwr(MSG_DEBUG,"realsocket() = %d\n", err);
        return err;
    }
    /* Assemble and send RPC */
    struct socket_st rpc_st;
    rpc_st.socket_family = socket_family;
    rpc_st.socket_type = socket_type;
    rpc_st.protocol = protocol;
#if defined(__linux__)
    rpc_st.__tid = syscall(SYS_gettid);
#endif
    /* -1 is passed since we we're generating the new socket in this call */
    return rpc_send_command(netpath, RPC_SOCKET, -1, &rpc_st, sizeof(struct socket_st));
}

/*------------------------------------------------------------------------------
 ---------------------------------- connect() -----------------------------------
 ------------------------------------------------------------------------------*/

/* int __fd, const struct sockaddr * __addr, socklen_t __len
 connect() intercept function */
int connect(CONNECT_SIG)
{
    printf("INTERCEPTED CF socket()\n");
    if (!set_up_intercept())
        return realconnect(__fd, __addr, __len);
    
    struct sockaddr_in *connaddr;
    connaddr = (struct sockaddr_in *)__addr;
    if(__addr->sa_family == AF_LOCAL || __addr->sa_family == AF_UNIX) {
        struct sockaddr_storage storage;
        memcpy(&storage, __addr, __len);
        struct sockaddr_un *s_un = (struct sockaddr_un*)&storage;
        dwr(MSG_DEBUG, "connect(): address = %s\n", s_un->sun_path);
    }
    
    int port = connaddr->sin_port;
    int ip = connaddr->sin_addr.s_addr;
    unsigned char d[4];
    d[0] = ip & 0xFF;
    d[1] = (ip >>  8) & 0xFF;
    d[2] = (ip >> 16) & 0xFF;
    d[3] = (ip >> 24) & 0xFF;
    dwr(MSG_DEBUG,"connect(): %d.%d.%d.%d: %d\n", d[0],d[1],d[2],d[3], ntohs(port));
    
    dwr(MSG_DEBUG,"connect(%d):\n", __fd);
    /* Check that this is a valid fd */
    if(fcntl(__fd, F_GETFD) < 0) {
        errno = EBADF;
        return -1;
    }
    /* Check that it is a socket */
    int sock_type;
    socklen_t sock_type_len = sizeof(sock_type);
    if(getsockopt(__fd, SOL_SOCKET, SO_TYPE, (void *) &sock_type, &sock_type_len) < 0) {
        errno = ENOTSOCK;
        return -1;
    }
#if defined(__linux__)
    /* Check family */
    if (connaddr->sin_family < 0 || connaddr->sin_family >= NPROTO){
        errno = EAFNOSUPPORT;
        return -1;
    }
#endif
    // FIXME
    /* make sure we don't touch any standard outputs */
    if(__fd == 0 || __fd == 1 || __fd == 2)
        return(realconnect(__fd, __addr, __len));
    
    if(__addr != NULL && (connaddr->sin_family == AF_LOCAL
#if defined(__linux__)
                          || connaddr->sin_family == PF_NETLINK
                          || connaddr->sin_family == AF_NETLINK
#endif
                          || connaddr->sin_family == AF_UNIX)) {
        return realconnect(__fd, __addr, __len);
    }
    /* Assemble and send RPC */
    struct connect_st rpc_st;
#if defined(__linux__)
    rpc_st.__tid = syscall(SYS_gettid);
#endif
    rpc_st.__fd = __fd;
    //memcpy(&rpc_st.__addr, __addr, sizeof(struct sockaddr_storage));
    memcpy(&rpc_st.__len, &__len, sizeof(socklen_t));
    return rpc_send_command(netpath, RPC_CONNECT, __fd, &rpc_st, sizeof(struct connect_st));
}

/*------------------------------------------------------------------------------
 ------------------------------------ bind() ------------------------------------
 ------------------------------------------------------------------------------*/

/* int sockfd, const struct sockaddr *addr, socklen_t addrlen
 bind() intercept function */
int bind(BIND_SIG)
{
    if (!set_up_intercept())
        return realbind(sockfd, addr, addrlen);
    
    dwr(MSG_DEBUG,"bind(%d):\n", sockfd);
    /* Check that this is a valid fd */
    if(fcntl(sockfd, F_GETFD) < 0) {
        errno = EBADF;
        return -1;
    }
    /* Check that it is a socket */
    int opt = -1;
    socklen_t opt_len;
    if(getsockopt(sockfd, SOL_SOCKET, SO_TYPE, (void *) &opt, &opt_len) < 0) {
        errno = ENOTSOCK;
        return -1;
    }
    /* make sure we don't touch any standard outputs */
    if(sockfd == 0 || sockfd == 1 || sockfd == 2)
        return(realbind(sockfd, addr, addrlen));
    /* If local, just use normal syscall */
    struct sockaddr_in *connaddr;
    connaddr = (struct sockaddr_in *)addr;
    
    if(connaddr->sin_family == AF_LOCAL
#if defined(__linux__)
       || connaddr->sin_family == AF_NETLINK
#endif
       || connaddr->sin_family == AF_UNIX) {
        int err = realbind(sockfd, addr, addrlen);
        dwr(MSG_DEBUG,"realbind, err = %d\n", err);
        return err;
    }
    int port = connaddr->sin_port;
    int ip = connaddr->sin_addr.s_addr;
    unsigned char d[4];
    d[0] = ip & 0xFF;
    d[1] = (ip >>  8) & 0xFF;
    d[2] = (ip >> 16) & 0xFF;
    d[3] = (ip >> 24) & 0xFF;
    dwr(MSG_DEBUG,"bind(): %d.%d.%d.%d: %d\n", d[0],d[1],d[2],d[3], ntohs(port));
    /* Assemble and send RPC */
    struct bind_st rpc_st;
    rpc_st.sockfd = sockfd;
#if defined(__linux__)
    rpc_st.__tid = syscall(SYS_gettid);
#endif
   // memcpy(&rpc_st.addr, addr, sizeof(struct sockaddr_storage));
    memcpy(&rpc_st.addrlen, &addrlen, sizeof(socklen_t));
    return rpc_send_command(netpath, RPC_BIND, sockfd, &rpc_st, sizeof(struct bind_st));
}

/*------------------------------------------------------------------------------
 ----------------------------------- accept4() ----------------------------------
 ------------------------------------------------------------------------------*/

/* int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags */
#if defined(__linux__)
int accept4(ACCEPT4_SIG)
{
    dwr(MSG_DEBUG,"accept4(%d):\n", sockfd);
    if ((flags & SOCK_CLOEXEC))
        fcntl(sockfd, F_SETFL, FD_CLOEXEC);
    if ((flags & SOCK_NONBLOCK))
        fcntl(sockfd, F_SETFL, O_NONBLOCK);
    return accept(sockfd, addr, addrlen);
}
#endif

/*------------------------------------------------------------------------------
 ----------------------------------- accept() -----------------------------------
 ------------------------------------------------------------------------------*/

/* int sockfd struct sockaddr *addr, socklen_t *addrlen
 accept() intercept function */
int accept(ACCEPT_SIG)
{
    if (!set_up_intercept())
        return realaccept(sockfd, addr, addrlen);
    fprintf(stderr, "accept(): tid = %d\n", pthread_mach_thread_np(pthread_self()));
    /* Check that this is a valid fd */
    if(fcntl(sockfd, F_GETFD) < 0) {
        return -1;
        errno = EBADF;
        dwr(MSG_DEBUG,"EBADF\n");
        return -1;
    }
    /* Check that it is a socket */
    int opt;
    socklen_t opt_len;
    if(getsockopt(sockfd, SOL_SOCKET, SO_TYPE, (void *) &opt, &opt_len) < 0) {
        errno = ENOTSOCK;
        dwr(MSG_DEBUG,"ENOTSOCK\n");
        return -1;
    }
    /* Check that this socket supports accept() */
    if(!(opt && (SOCK_STREAM | SOCK_SEQPACKET))) {
        errno = EOPNOTSUPP;
        dwr(MSG_DEBUG,"EOPNOTSUPP\n");
        return -1;
    }
    /* Check that we haven't hit the soft-limit file descriptors allowed */
    struct rlimit rl;
    getrlimit(RLIMIT_NOFILE, &rl);
    if(sockfd >= rl.rlim_cur){
        errno = EMFILE;
        dwr(MSG_DEBUG,"EMFILE\n");
        return -1;
    }
    /* Check address length */
    if(addrlen < 0) {
        errno = EINVAL;
        dwr(MSG_DEBUG,"EINVAL\n");
        return -1;
    }
    /* redirect calls for standard I/O descriptors to kernel */
    if(sockfd == 0 || sockfd == 1 || sockfd == 2){
        dwr(MSG_DEBUG,"realaccept():\n");
        return(realaccept(sockfd, addr, addrlen));
    }
    if(addr)
        addr->sa_family = AF_INET;
    
    int new_fd = get_new_fd(sockfd);
    if(new_fd > 0) {
        errno = ERR_OK;
        return new_fd;
    }
    errno = EAGAIN;
    return -EAGAIN;
}

/*------------------------------------------------------------------------------
 ------------------------------------- listen()----------------------------------
 ------------------------------------------------------------------------------*/

/* int sockfd, int backlog */
int listen(LISTEN_SIG)
{
    if (!set_up_intercept())
        return(reallisten(sockfd, backlog));
    
    dwr(MSG_DEBUG,"listen(%d):\n", sockfd);
    int sock_type;
    socklen_t sock_type_len = sizeof(sock_type);
    
    /* Check that this is a valid fd */
    if(fcntl(sockfd, F_GETFD) < 0) {
        errno = EBADF;
        return -1;
    }
    /* Check that it is a socket */
    if(getsockopt(sockfd, SOL_SOCKET, SO_TYPE, (void *) &sock_type, &sock_type_len) < 0) {
        errno = ENOTSOCK;
        return -1;
    }
    /* Check that this socket supports accept() */
    if(!(sock_type && (SOCK_STREAM | SOCK_SEQPACKET))) {
        errno = EOPNOTSUPP;
        return -1;
    }
    /* make sure we don't touch any standard outputs */
    if(sockfd == 0 || sockfd == 1 || sockfd == 2)
        return(reallisten(sockfd, backlog));
    
    if(!connected_to_service(sockfd)) {
        reallisten(sockfd, backlog);
    }
    /* Assemble and send RPC */
    struct listen_st rpc_st;
    rpc_st.sockfd = sockfd;
    rpc_st.backlog = backlog;
#if defined(__linux__)
    rpc_st.__tid = syscall(SYS_gettid);
#endif
    return rpc_send_command(netpath, RPC_LISTEN, sockfd, &rpc_st, sizeof(struct listen_st));
}

/*------------------------------------------------------------------------------
 ------------------------------------- close() ----------------------------------
 ------------------------------------------------------------------------------*/

/* int fd */
/*
int close(CLOSE_SIG)
{
    dwr(MSG_DEBUG, "close(%d)\n", fd);
    set_up_intercept();
    return realclose(fd);
}
 */

/*------------------------------------------------------------------------------
 -------------------------------- getsockname() ---------------------------------
 ------------------------------------------------------------------------------*/

/* int sockfd, struct sockaddr *addr, socklen_t *addrlen */
int getsockname(GETSOCKNAME_SIG)
{
    if (!set_up_intercept())
        return realgetsockname(sockfd, addr, addrlen);
    
    dwr(MSG_DEBUG,"getsockname(%d)\n", sockfd);
    if(!connected_to_service(sockfd)) {
        dwr(MSG_DEBUG,"getsockname(): not used by service\n");
        return realgetsockname(sockfd, addr, addrlen);
    }
    /* This is kind of a hack as it stands -- assumes sockaddr is sockaddr_in
     * and is an IPv4 address. */
    
    /* assemble and send command */
    struct getsockname_st rpc_st;
    rpc_st.sockfd = sockfd;
    //memcpy(&rpc_st.addr, addr, *addrlen);
    memcpy(&rpc_st.addrlen, &addrlen, sizeof(socklen_t));
    int rpcfd = rpc_send_command(netpath, RPC_GETSOCKNAME, sockfd, &rpc_st, sizeof(struct getsockname_st));
    /* read address info from service */
    char addrbuf[sizeof(struct sockaddr_storage)];
    memset(&addrbuf, 0, sizeof(struct sockaddr_storage));
    
    if(rpcfd > -1)
        if(read(rpcfd, &addrbuf, sizeof(struct sockaddr_storage)) > 0)
            close(rpcfd);
    
    struct sockaddr_storage sock_storage;
    memcpy(&sock_storage, addrbuf, sizeof(struct sockaddr_storage));
    *addrlen = sizeof(struct sockaddr_in);
    memcpy(addr, &sock_storage, (*addrlen > sizeof(sock_storage)) ? sizeof(sock_storage) : *addrlen);
    addr->sa_family = AF_INET;
    return 0;
}

/*------------------------------------------------------------------------------
 ------------------------------------ syscall() ---------------------------------
 ------------------------------------------------------------------------------*/

#if defined(__linux__)
long syscall(SYSCALL_SIG)
{
    va_list ap;
    uintptr_t a,b,c,d,e,f;
    va_start(ap, number);
    a=va_arg(ap, uintptr_t);
    b=va_arg(ap, uintptr_t);
    c=va_arg(ap, uintptr_t);
    d=va_arg(ap, uintptr_t);
    e=va_arg(ap, uintptr_t);
    f=va_arg(ap, uintptr_t);
    va_end(ap);
    
    if (!set_up_intercept())
        return realsyscall(number,a,b,c,d,e,f);
    
    dwr(MSG_DEBUG_EXTRA,"syscall(%u, ...):\n", number);
    
#if defined(__i386__)
    /* TODO: Implement for 32-bit systems: syscall(__NR_socketcall, 18, args);
     args[0] = (unsigned long) fd;
     args[1] = (unsigned long) addr;
     args[2] = (unsigned long) addrlen;
     args[3] = (unsigned long) flags;
     */
#else
    if(number == __NR_accept4) {
        int sockfd = a;
        struct sockaddr * addr = (struct sockaddr*)b;
        socklen_t * addrlen = (socklen_t*)c;
        int flags = d;
        int old_errno = errno;
        int err = accept4(sockfd, addr, addrlen, flags);
        errno = old_errno;
        err = err == -EBADF ? -EAGAIN : err;
        return err;
    }
#endif
    return realsyscall(number,a,b,c,d,e,f);
}
#endif


#ifdef __cplusplus
}
#endif