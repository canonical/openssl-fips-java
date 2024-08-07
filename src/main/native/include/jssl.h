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
#include <openssl/provider.h>
#include <string.h>
#include <stdlib.h>

#if !defined _JSSL_

OSSL_LIB_CTX* load_openssl_fips_provider(const char*);

#define STR_EQUAL(a, b) (0 == strcmp(a, b))

#define MIN(a, b) (a > b ? b : a)
#define IS_NULL(a) (NULL == (void *)a)
#define RET_NULL_IF_NULL(a) { if(IS_NULL(a)) return NULL; }
#define RET_ZERO_IF_NULL(a) { if(IS_NULL(a)) return 0; }
#define RET_NULL_IF_NON_POSITIVE(a) { if (a <= 0) return NULL; }
#define RET_ZERO_IF_NON_POSITIVE(a) { if (a <= 0) return 0; }
#define FREE_IF_NON_NULL(a) { if (!IS_NULL(a)) free(a); }

/* Lets use 'byte' instead of 'unsigned char' */
typedef unsigned char byte;

#define _JSSL_
#endif
