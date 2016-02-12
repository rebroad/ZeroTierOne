//
//  Use this file to import your target's public headers that you would like to expose to Swift.
//

int start_service(const char * path);
int start_intercept();

int fish_test_rebind();

// For demo
char * cpp_intercepted_socket_api_test(const char * addr_str, int port);
//const char * get_debug_msg_from_ztnc();