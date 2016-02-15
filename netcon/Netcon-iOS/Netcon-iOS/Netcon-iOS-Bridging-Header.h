//
//  Use this file to import your target's public headers that you would like to expose to Swift.
//

int start_intercept();
int start_service(const char * path);
char * cpp_intercepted_socket_api_test(const char * addr_str, int port);
