//
//  Use this file to import your target's public headers that you would like to expose to Swift.
//

int start_intercept();
int start_service(const char * path);

// C++ socket api tests
char * cpp_tcp_socket_client_test(const char * addr_str, int port);
char * cpp_tcp_socket_server_test(const char * addr_str, int port);

char * cpp_udp_socket_client_test(const char * addr_str, int port);
char * cpp_udp_socket_server_test(const char * addr_str, int port);