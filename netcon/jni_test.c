#include <jni.h>
#include "jni_test.h"

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT int JNICALL Java_Netcon_NetconWrapper_loadsymbols(JNIEnv *env, jobject thisObj)
{
	return 4;
}

#ifdef __cplusplus
} // extern "C"
#endif
