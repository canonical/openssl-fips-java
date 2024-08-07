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
package com.canonical.openssl.drbg;

import java.security.SecureRandomParameters;

final public class DrbgAES256CTR extends OpenSSLDrbg {
    public DrbgAES256CTR() {
        super("CTR-DRBG");
    }

    public DrbgAES256CTR(SecureRandomParameters params) {
        super("CTR-DRBG", params);
    }

    @Override
    public String toString() {
        return "CTR-DRBG-with-AES-256";
    }
}
