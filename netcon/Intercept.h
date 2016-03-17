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

#ifndef _INTERCEPT_H
#define _INTERCEPT_H	1

#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(__ANDROID__)    
	void set_thr_key(pthread_key_t key);
#endif
void setpath(const char * given_path);
int set_up_intercept();

#if defined(__linux__)
	#define ACCEPT4_SIG int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags
#endif

#define CLOSE_SIG int fd
#define READ_SIG int __fd, void *__buf, size_t __nbytes
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
//#define SEND_SIG int socket, const void *buffer, size_t length, int flags

#if defined(__linux__)
	int accept4(ACCEPT4_SIG);
#endif

void my_init(void);
int connect(CONNECT_SIG);
int accept(ACCEPT_SIG);
int listen(LISTEN_SIG);
int socket(SOCKET_SIG);
int setsockopt(SETSOCKOPT_SIG);
int getsockopt(GETSOCKOPT_SIG);
int close(CLOSE_SIG);
int clone(CLONE_SIG);
int dup2(DUP2_SIG);
int dup3(DUP3_SIG);
int getsockname(GETSOCKNAME_SIG);
    
#if defined(__ANDROID__)
	#if defined(_x86_64__)
 		//#define SYSCALL_SIG	int number, ...
	#else
		//#define SYSCALL_SIG long number, ...
	#endif
		//#define BIND_SIG int sockfd, const struct sockaddr *addr, int addrlen 
		//#define SENDMSG_SIG int socket, const struct msghdr *message, unsigned int flags
		//#define SENDTO_SIG int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t addr_len
		//#define RECV_SIG int socket, void *buffer, size_t length, int flags
		//#define RECVFROM_SIG int socket, void * buffer, size_t length, int flags, const struct sockaddr * address, socklen_t * address_len
		//#define RECVMSG_SIG int socket, struct msghdr *message, unsigned int flags
	#if defined(__x86_64__)
		//int syscall(SYSCALL_SIG);
	#else
		//long syscall(SYSCALL_SIG);
	#endif
		//int bind(BIND_SIG);
		//int sendmsg(SENDMSG_SIG);
		//ssize_t sendto(SENDTO_SIG);
		//ssize_t recvfrom(RECVFROM_SIG);
		//int recvmsg(RECVMSG_SIG);
#else
	#define SYSCALL_SIG	int number, ...
	#define BIND_SIG int sockfd, const struct sockaddr *addr, socklen_t addrlen
	#define SENDMSG_SIG int socket, const struct msghdr *message, int flags
	#define SENDTO_SIG int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t addr_len
	#define RECV_SIG int socket, void *buffer, size_t length, int flags
	#define RECVFROM_SIG int socket, void * buffer, size_t length, int flags, struct sockaddr * __restrict address, socklen_t * __restrict address_len
	#define RECVMSG_SIG int socket, struct msghdr *message,int flags

	int syscall(SYSCALL_SIG);
	int bind(BIND_SIG);
	ssize_t sendmsg(SENDMSG_SIG);
	ssize_t sendto(SENDTO_SIG);
	ssize_t recvfrom(RECVFROM_SIG);
	ssize_t recvmsg(RECVMSG_SIG);
#endif


#if defined(__linux__)
	static int (*realaccept4)(ACCEPT4_SIG) = 0;
	#if !defined(__ANDROID__)
		static int (*realsyscall)(SYSCALL_SIG) = 0;
	#endif
#endif

#if !defined(__ANDROID__)
	static int (*realbind)(BIND_SIG) = 0;
	static int (*realsendmsg)(SENDMSG_SIG) = 0;
	static ssize_t (*realsendto)(SENDTO_SIG) = 0;
	static int (*realrecvmsg)(RECVMSG_SIG) = 0;
	static int (*realrecvfrom)(RECVFROM_SIG) = 0;
#endif
	static int (*realconnect)(CONNECT_SIG) = 0;
	static int (*realaccept)(ACCEPT_SIG) = 0;
	static int (*reallisten)(LISTEN_SIG) = 0;
	static int (*realsocket)(SOCKET_SIG) = 0;
	static int (*realsetsockopt)(SETSOCKOPT_SIG) = 0;
	static int (*realgetsockopt)(GETSOCKOPT_SIG) = 0;
	static int (*realclose)(CLOSE_SIG) = 0;
	static int (*realgetsockname)(GETSOCKNAME_SIG) = 0;
#endif
#ifdef __cplusplus
}
#endif
