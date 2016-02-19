//
//  NetconWrapper.cpp
//  Netcon-iOS
//
//  Created by Joseph Henry on 2/14/16.
//  Copyright © 2016 ZeroTier. All rights reserved.
//

#include "NetconWrapper.hpp"

// Performs initial symbol interposing
#include "Intercept.h"
extern "C" int start_intercept() {
    init_intercept_no_spawn(111);
    //setpath("ZeroTier/One/nc_e5cd7a9e1c87bace");
    return 1;
}

// Starts a service at the specified path
#include "OneServiceSetup.hpp"
extern "C" int start_service(const char * path) {
    init_service(path);
    return 1;
}


/* ------------------------- SOCKET API TEST ------------------------ */

#include <string>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

extern "C" char * cpp_udp_socket_server_test(const char * addr_str, int port)
{
    printf("cpp_udp_socket_server_test():\n");
    ssize_t n_sent;
    int sock = -1;
    std::string data, reply;
    struct sockaddr_in server;
    char buf[80];
    
    if(sock == -1) {
        sock = socket(AF_INET , SOCK_DGRAM , 0);
        if (sock == -1) {
            return (char*)"could not create socket";
        }
    }
    socklen_t recv_addr_len;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(9997);
    
    printf("The server UDP port number is %d\n",ntohs(server.sin_port));

    if (bind(sock, (struct sockaddr *) &server, sizeof(server))<0) {
        printf("Problem binding\n");
        return (char*)"nothing";
    }
    
    socklen_t length = sizeof(server);
    printf("The server UDP port number is %d\n",ntohs(server.sin_port));

    if (getsockname(sock, (struct sockaddr *) &server, &length)<0) {
        printf("Error getsockname\n");
        return (char*)"nothing";
    }
    /* port number's are network byte order, we have to convert to
     host byte order before printing !
     */
    printf("The server UDP port number is %d\n",ntohs(server.sin_port));

    printf("Watching for UDP traffic on sock = %d...\n", sock);
    
    // Reset remote address info for RX
    //server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_addr.s_addr = inet_addr("");
    server.sin_port = htons(0);
    
    while (1) {
        n_sent=recvfrom(sock,buf,sizeof(buf),0,(struct sockaddr *)&server,&recv_addr_len);
        //n_sent = recv(sock,buf,sizeof(buf),0);
        if (n_sent<0)
            perror("Error receiving data");
        else
            printf("<%s : %d> --- %s\n", inet_ntoa(server.sin_addr), ntohs(server.sin_port), buf);
    }
    return (char*)"nothing";
}

extern "C" char * cpp_udp_socket_client_test(const char * addr_str, int port)
{
    printf("cpp_udp_socket_client_test():\n");
    ssize_t n_sent;
    int sock = -1;
    std::string data, reply;
    struct sockaddr_in server;
    
    if(sock == -1) {
        sock = socket(AF_INET , SOCK_DGRAM , 0);
        if (sock == -1) {
            return (char*)"could not create socket";
        }
    }
    server.sin_addr.s_addr = inet_addr(addr_str);
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    
    char *buf = (char*)"Testing UDP\n";
    //printf("sizeof(buf) = %d\n", sizeof(buf));
    
    /*
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0) {
        printf("api_test: error while connecting.\n");
        return (char*)"nothing";
    }
     */
    
    //n_sent = send(sock,buf,sizeof(buf),0);

    n_sent = sendto(sock,buf,strlen(buf),0, (struct sockaddr *)&server,sizeof(server));
    
    if (n_sent<0) {
        perror("Problem sending data");
        return (char*)"nothing";
    }
    if (n_sent!=sizeof(buf))
        printf("Sendto sent %d bytes\n",(int)n_sent);
    
    socklen_t recv_addr_len;
    // Clear address info for RX test
    server.sin_addr.s_addr = inet_addr("");
    server.sin_port = htons(-1);
    
    while (1) {
        n_sent=recvfrom(sock,buf,sizeof(buf),0,(struct sockaddr *)&server,&recv_addr_len);
        printf("Got a datagram from %s port %d\n", inet_ntoa(server.sin_addr), ntohs(server.sin_port));
        if (n_sent<0) {
            perror("Error receiving data");
        }
        else {
            printf("RXed: %s\n", buf);
        }
    }
    return (char*)"nothing";
}



extern "C" char * cpp_tcp_socket_server_test(const char * addr_str, int port)
{
    printf("cpp_tcp_socket_server_test():\n");
    return (char*)"nothing";
}

extern "C" char * cpp_tcp_socket_client_test(const char * addr_str, int port)
{
    printf("cpp_udp_sockecpp_tcp_socket_client_testt_server_test():\n");
    int sock = -1;
    std::string data, reply;
    struct sockaddr_in server;
    
    if(sock == -1) {
        sock = socket(AF_INET , SOCK_STREAM , 0);
        if (sock == -1) {
            return (char*)"could not create socket";
        }
    }
    if(inet_addr(addr_str) == -1)
    {
        struct hostent *he;
        struct in_addr **addr_list;
        
        //Cast the h_addr_list to in_addr , since h_addr_list also has the ip address in long format only
        addr_list = (struct in_addr **) he->h_addr_list;
        
        for(int i=0; addr_list[i] != NULL; i++) {
            server.sin_addr = *addr_list[i];
            printf("%s resolved to %s", addr_str, inet_ntoa(*addr_list[i]));
            break;
        }
    }
    else
        server.sin_addr.s_addr = inet_addr(addr_str);
    
    server.sin_family = AF_INET;
    server.sin_port = htons( port );
    
    //Connect to remote server
    if (connect(sock , (struct sockaddr *)&server , sizeof(server)) < 0)
        return (char*)"connect failed";
    
    // TX
    data = "GET / HTTP/1.1\r\n\r\n";
    if( send(sock , data.c_str() , strlen( data.c_str() ) , 0) < 0)
        return (char*)"send failed";
    
    char buffer[1024];
    
    // RX
    sleep(1);
    if( recv(sock , buffer , 26 , 0) < 0) {
        puts("recv failed");
    }
    reply = buffer;
    printf("\n\n\n\n------------------------------------------------------\n");
    printf("%s\n", reply.c_str());
    printf("\n------------------------------------------------------\n\n\n\n");
    
    return (char*)reply.c_str();
}