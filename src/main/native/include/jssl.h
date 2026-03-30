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
#ifndef _INCLUDE_JSSL_H
#define _INCLUDE_JSSL_H

#include <openssl/provider.h>
#include <string.h>
#include <stdlib.h>

OSSL_LIB_CTX* load_openssl_fips_provider(const char*);

/* Utility function for string comparison */
static inline int str_equal(const char *str1, const char *str2) {
    return 0 == strcmp(str1, str2);
}

/* Lets use 'byte' instead of 'unsigned char' */
typedef unsigned char byte;
#endif
