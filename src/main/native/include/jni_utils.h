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

byte *jbyteArray_to_byte_array(JNIEnv *env, jbyteArray keyBytes);

jbyteArray byte_array_to_jbyteArray(JNIEnv *env, byte *array, int length);

int array_length(JNIEnv *env, jbyteArray array);

long get_long_field(JNIEnv *env, jobject this, const char *field_name);

int get_int_field(JNIEnv *env, jobject this, const char *field_name);

jstring get_string_field(JNIEnv *env, jobject this, const char *field_name);

void copy_byte_array_range(JNIEnv *env, jbyteArray source, int offset, int length, byte *destination);

void copy_byte_array(JNIEnv *env, jbyteArray destination, byte *source, int length);

jbyteArray new_byteArray(JNIEnv *env, byte *source, int length);

char* jstring_to_char_array(JNIEnv *env, jstring string);

void release_jstring(JNIEnv *env, jstring string, const char *chars);

char *jcharArray_to_char_array(JNIEnv *env, jcharArray chars);

jlong invokeLongMethod(JNIEnv *env, jobject this, const char *name, const char *signature);
