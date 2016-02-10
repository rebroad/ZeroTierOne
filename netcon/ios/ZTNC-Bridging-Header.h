//
//  Use this file to import your target's public headers that you would like to expose to Swift.
//

int start_service();
int start_intercept();

// For demo
char * cpp_intercepted_socket_api_test(const char * addr_str, int port);