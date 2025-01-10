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
package com.canonical.openssl.cipher;

public abstract class CipherAes extends OpenSSLCipher {

    protected CipherAes(String nameKeySizeMode, String padding) {
        super(nameKeySizeMode, padding);
    }

    public String getCipherName() {
        return "AES";
    }

    public abstract int getKeySize();

    public abstract String getMode();

    public abstract String getPadding();

    @Override 
    protected int engineGetBlockSize() {
        return 16;
    }

    @Override
    protected int engineGetOutputSize(int inputSize) {
        if(getPadding().equals("NONE"))
            return inputSize;

        int blockSize = engineGetBlockSize();
        if(getMode().equals("CBC") || getMode().equals("ECB")) {
            int paddingLength = (blockSize - (inputSize % blockSize)) % blockSize;
            return inputSize + paddingLength;
        }

        return inputSize;
    }
}
