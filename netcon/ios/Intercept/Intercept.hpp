//
//  Intercept.hpp
//  ZTNC
//
//  Created by Joseph Henry on 1/28/16.
//  Copyright © 2016 ZeroTier. All rights reserved.
//

#ifndef Intercept_hpp
#define Intercept_hpp

#include <sys/socket.h>

int set_up_intercept();
//int connected_to_service();

#if defined(__linux__)
#define ACCEPT4_SIG int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags
#define SYSCALL_SIG	long number, ...
#endif

#define CLOSE_SIG int fd
#define READ_SIG int __fd, void *__buf, size_t __nbytes
#define BIND_SIG int sockfd, const struct sockaddr *addr, socklen_t addrlen
#define CONNECT_SIG int __fd, const struct sockaddr * __addr, socklen_t __len
#define WRITE_SIG int __fd, const void *__buf, size_t __n
#define LISTEN_SIG int sockfd, int backlog
#define SOCKET_SIG int socket_family, int socket_type, int protocol
#define ACCEPT_SIG int sockfd, struct sockaddr *addr, socklen_t *addrlen
#define SHUTDOWN_SIG int socket, int how
#define CONNECT_SOCKARG struct sockaddr *
#define IOCTL_SIG int __fd, unsigned long int __request, ...
#define FCNTL_SIG int __fd, int __cmd, ...
#define DAEMON_SIG int nochdir, int noclose
#define SETSOCKOPT_SIG int socket, int level, int option_name, const void *option_value, socklen_t option_len
#define GETSOCKOPT_SIG int sockfd, int level, int optname, void *optval, socklen_t *optlen
#define CLONE_SIG int (*fn)(void *), void *child_stack, int flags, void *arg, ...
#define GETSOCKNAME_SIG int sockfd, struct sockaddr *addr, socklen_t *addrlen
#define DUP2_SIG int oldfd, int newfd
#define DUP3_SIG int oldfd, int newfd, int flags


#if defined(__linux__)
int accept4(ACCEPT4_SIG);
long syscall(SYSCALL_SIG);
#endif

void my_init(void);
int connect(CONNECT_SIG);
int bind(BIND_SIG);
int accept(ACCEPT_SIG);
int listen(LISTEN_SIG);
int socket(SOCKET_SIG);
int setsockopt(SETSOCKOPT_SIG);
int getsockopt(GETSOCKOPT_SIG);
//int close(CLOSE_SIG);
int clone(CLONE_SIG);
int getsockname(GETSOCKNAME_SIG);

#if defined(__linux__)
static int (*realaccept4)(ACCEPT4_SIG) = 0;
static long (*realsyscall)(SYSCALL_SIG) = 0;
#endif

static int (*realconnect)(CONNECT_SIG) = 0;
static int (*realbind)(BIND_SIG) = 0;
static int (*realaccept)(ACCEPT_SIG) = 0;
static int (*reallisten)(LISTEN_SIG) = 0;
static int (*realsocket)(SOCKET_SIG) = 0;
static int (*realsetsockopt)(SETSOCKOPT_SIG) = 0;
static int (*realgetsockopt)(GETSOCKOPT_SIG) = 0;
static int (*realclose)(CLOSE_SIG) = 0;
static int (*realgetsockname)(GETSOCKNAME_SIG) = 0;

#endif /* Intercept_hpp */
