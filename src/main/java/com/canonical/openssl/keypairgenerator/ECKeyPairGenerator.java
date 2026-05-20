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

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;

public final class ECKeyPairGenerator extends OpenSSLKeyPairGenerator {
    public ECKeyPairGenerator() {
        super("prime256v1");
    }

    @Override
    protected String getAlgorithmName() {
        return "EC";
    }

    @Override
    protected String mapKeysizeToGroup(int keysize) {
        switch (keysize) {
            case 256: return "prime256v1";
            case 384: return "secp384r1";
            case 521: return "secp521r1";
            default:  return null;
        }
    }

    @Override
    protected String groupFromSpec(AlgorithmParameterSpec params) {
        if (!(params instanceof ECGenParameterSpec ec)) {
            return null;
        }
        String name = ec.getName();
        if (name == null) {
            return null;
        }
        switch (name) {
            case "prime256v1":
            case "secp256r1":
            case "P-256":
            case "NIST P-256":
                return "prime256v1";
            case "secp384r1":
            case "P-384":
            case "NIST P-384":
                return "secp384r1";
            case "secp521r1":
            case "P-521":
            case "NIST P-521":
                return "secp521r1";
            default:
                return null;
        }
    }
}
