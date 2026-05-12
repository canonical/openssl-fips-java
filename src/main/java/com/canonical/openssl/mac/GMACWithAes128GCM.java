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
package com.canonical.openssl.mac;

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public final class GMACWithAes128GCM extends OpenSSLMAC {

    private static final int NONCE_LEN = 12;

    protected String getAlgorithm() {
        return "GMAC";
    }

    protected String getCipherType() {
        return "AES-128-GCM";
    }

    protected String getDigestType() {
        return null;
    }

    protected byte[] getIV(AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException {
        byte[] iv;
        if (spec instanceof IvParameterSpec ivSpec) {
            iv = ivSpec.getIV();
        } else if (spec instanceof GCMParameterSpec gcmSpec) {
            iv = gcmSpec.getIV();
        } else {
            throw new InvalidAlgorithmParameterException(
                "GMAC requires an IvParameterSpec or GCMParameterSpec carrying a " + NONCE_LEN + "-byte nonce");
        }
        if (iv == null || iv.length != NONCE_LEN) {
            throw new InvalidAlgorithmParameterException(
                "GMAC nonce must be exactly " + NONCE_LEN + " bytes");
        }
        return iv.clone();
    }

    protected int getDefaultMacLength() {
        return 16;
    }
}
