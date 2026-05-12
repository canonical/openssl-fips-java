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
package com.canonical.openssl.keypairgenerator;

/* groupFromSpec is intentionally not overridden: the standard JCA DHParameterSpec
 * carries explicit (p, g) primes, and accepting those would let callers bypass
 * the FIPS-approved FFDHE named groups. Callers should use initialize(keysize). */
public final class DHKeyPairGenerator extends OpenSSLKeyPairGenerator {
    public DHKeyPairGenerator() {
        super("ffdhe2048");
    }

    @Override
    protected String getAlgorithmName() {
        return "DH";
    }

    @Override
    protected String mapKeysizeToGroup(int keysize) {
        switch (keysize) {
            case 2048: return "ffdhe2048";
            case 3072: return "ffdhe3072";
            case 4096: return "ffdhe4096";
            case 6144: return "ffdhe6144";
            case 8192: return "ffdhe8192";
            default:   return null;
        }
    }
}
