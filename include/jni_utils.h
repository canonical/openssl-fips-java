#include <jni.h>
#include "jssl.h"

byte *jbyteArray_to_byte_array(JNIEnv *env, jbyteArray keyBytes);

jbyteArray byte_array_to_jbyteArray(JNIEnv *env, byte *array, int length);

int array_length(JNIEnv *env, jbyteArray array);

long get_long_field(JNIEnv *env, jobject this, const char *field_name);