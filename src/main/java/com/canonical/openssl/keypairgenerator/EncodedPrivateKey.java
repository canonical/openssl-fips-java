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

import java.security.PrivateKey;
import java.util.Arrays;
import javax.security.auth.Destroyable;

final class EncodedPrivateKey implements PrivateKey, Destroyable {
    private static final long serialVersionUID = 1L;

    private final String algorithm;
    private final byte[] encoded;
    private volatile boolean destroyed = false;

    EncodedPrivateKey(String algorithm, byte[] encoded) {
        this.algorithm = algorithm;
        this.encoded = encoded.clone();
    }

    private void checkDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("EncodedPrivateKey has been destroyed");
        }
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        checkDestroyed();
        return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
        checkDestroyed();
        return encoded.clone();
    }

    @Override
    public void destroy() {
        if (destroyed) {
            return;
        }
        Arrays.fill(encoded, (byte) 0);
        destroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }
}
