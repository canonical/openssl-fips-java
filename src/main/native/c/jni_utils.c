/*
 * Copyright (C) Canonical, Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <jni.h>
#include "jssl.h"

char *jstring_to_char_array(JNIEnv *env, jstring string) {
    // TODO: free this
    if (string == NULL) {
        return NULL;
    }
    return (char*)(*env)->GetStringUTFChars(env, string, 0);
}

byte *jbyteArray_to_byte_array(JNIEnv *env, jbyteArray bytes) {
    if (bytes == NULL)
        return NULL;
    return (byte *) (*env)->GetByteArrayElements(env, bytes, NULL);
}

char *jcharArray_to_char_array(JNIEnv *env, jcharArray chars) {
    if (chars == NULL) {
        return NULL;
    }
    return (char *) (*env)->GetCharArrayElements(env, chars, NULL);
}

jbyteArray byte_array_to_jbyteArray(JNIEnv *env, byte *array, int length) {
    jbyteArray ret_array = (*env)->NewByteArray(env, length);
    (*env)->SetByteArrayRegion(env, ret_array, 0, length, array);
    return ret_array;
}

int array_length(JNIEnv *env, jbyteArray array) {
    if (array == NULL)
        return 0;
    return (*env)->GetArrayLength(env, array);
}

long get_long_field(JNIEnv *env, jobject this, const char *field_name) {
    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID ctx_id = (*env)->GetFieldID(env, clazz, field_name, "J");
    return (*env)->GetLongField(env, this, ctx_id);
}

int get_int_field(JNIEnv *env, jobject this, const char *field_name) {
    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID id = (*env)->GetFieldID(env, clazz, field_name, "I");
    return (*env)->GetIntField(env, this, id);
}

jstring get_string_field(JNIEnv *env, jobject this, const char *field_name) {
    jclass clazz = (*env)->GetObjectClass(env, this);
    jfieldID id = (*env)->GetFieldID(env, clazz, field_name, "Ljava/lang/String;");
    return (jstring)((*env)->GetObjectField(env, this, id));
}

void copy_byte_array(JNIEnv *env, jbyteArray destination, byte *source, int length) {
    (*env)->SetByteArrayRegion(env, destination, 0, length, source);
}

void copy_byte_array_range(JNIEnv *env, jbyteArray source, int offset, int length, byte *destination) {
    (*env)->GetByteArrayRegion(env, source, offset, length, destination);
}

jbyteArray new_byteArray(JNIEnv *env, byte *source, int length) {
    jbyteArray retArray = (*env)->NewByteArray(env, length);
    (*env)->SetByteArrayRegion(env, retArray, 0, length, source);
    return retArray;
}

jlong invokeLongMethod(JNIEnv *env, jobject this, const char *name, const char *signature) {
    jclass class = (*env)->GetObjectClass(env, this);
    jmethodID methodID = (*env)->GetMethodID(env, class, name, signature);
    return (*env)->CallLongMethod(env, this, methodID);
}
