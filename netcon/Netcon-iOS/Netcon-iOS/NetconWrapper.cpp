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
    setpath("ZeroTier/One/nc_e5cd7a9e1c87bace");
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

extern "C" char * cpp_intercepted_socket_api_test(const char * addr_str, int port)
{
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
    else {
        server.sin_addr.s_addr = inet_addr(addr_str);
    }
    
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