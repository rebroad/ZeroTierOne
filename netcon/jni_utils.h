#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

#if __ANDROID__
#include <android/log.h>
#define LOG_TAG "Netcon"

#define LOGV(...) ((void)__android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__))
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__))
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__))
#else
#define LOGV(...) fprintf(stdout, __VA_ARGS__)
#define LOGI(...) fprintf(stdout, __VA_ARGS__)
#define LOGD(...) fprintf(stdout, __VA_ARGS__)
#define LOGE(...) fprintf(stdout, __VA_ARGS__)
#endif

#ifdef __cplusplus
} // extern "C"
#endif