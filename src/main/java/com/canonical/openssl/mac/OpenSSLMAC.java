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

import com.canonical.openssl.util.NativeMemoryCleaner;
import com.canonical.openssl.util.NativeLibraryLoader;
import java.lang.ref.Cleaner;
import java.util.concurrent.atomic.AtomicLong;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.ProviderException;
import java.util.Arrays;
import javax.crypto.MacSpi;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import javax.xml.crypto.dsig.spec.HMACParameterSpec;

/* This implementation will be exercised by the user through the
 * javax.crypto.Mac API which isn't marked thread-safe.
 * This implementation is also NOT thread-safe and applications need
 * handle thread-safety concerns if need be.
 */

public abstract class OpenSSLMAC extends MacSpi {

    static {
        NativeLibraryLoader.load();
    }


    private static class MACState implements Runnable {
        private final AtomicLong nativeHandle;
        private volatile byte[] keyBytes;

        MACState(long handle) {
            this.nativeHandle = new AtomicLong(handle);
        }

        void setKeyBytes(byte[] keyBytes) {
            this.keyBytes = keyBytes;
        }

        @Override
        public void run() {
            long handle = nativeHandle.getAndSet(0);
            if (handle != 0) {
                cleanupNativeMemory(handle);
            }
            byte[] local = keyBytes;
            if (local != null) {
                Arrays.fill(local, (byte)0);
                this.keyBytes = null;
            }
        }
    }

    long nativeHandle;
    String cipherType;
    String digestType;
    byte[] initVector;

    protected abstract String getAlgorithm();
    protected abstract String getCipherType();
    protected abstract String getDigestType();
    protected abstract byte[] getIV(AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException;
    protected abstract int getDefaultMacLength();

    private static Cleaner cleaner = NativeMemoryCleaner.cleaner;
    private MACState macState;
    private Cleaner.Cleanable cleanable;
    private int outputLength = -1;
    private byte[] keyBytes;
    private byte[] cachedIV;

    @Override
    protected byte[] engineDoFinal() {
        if (nativeHandle == 0) {
            throw new IllegalStateException("MAC not initialized");
        }
        return doFinal0();
    }

    @Override
    protected int engineGetMacLength() {
        if (nativeHandle == 0) {
            return outputLength > 0 ? outputLength : getDefaultMacLength();
        }
        return getMacLength();
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec spec) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (key == null) {
            throw new InvalidKeyException("Key must not be null");
        }
        if (spec != null && isHMAC(this) && spec instanceof HMACParameterSpec hmacSpec) {
            this.outputLength = hmacSpec.getOutputLength();
        }
        byte[] newKeyBytes = key.getEncoded();
        if (newKeyBytes == null) {
            throw new InvalidKeyException("Key does not support encoding");
        }
        byte[] iv = getIV(spec);
        // clean() zeros the old keyBytes array (held by the old MACState) and frees the old handle
        if (cleanable != null) {
            cleanable.clean();
        }
        this.keyBytes = newKeyBytes;
        this.cachedIV = iv;
        nativeHandle = doInit0(getAlgorithm(), getCipherType(), getDigestType(), iv, outputLength, keyBytes);
        if (nativeHandle == 0) {
            Arrays.fill(keyBytes, (byte) 0);
            this.keyBytes = null;
            throw new InvalidKeyException("Failed to initialize MAC");
        }
        macState = new MACState(nativeHandle);
        macState.setKeyBytes(keyBytes);
        cleanable = cleaner.register(this, macState);
    }

    @Override
    protected void engineReset() {
        if (keyBytes == null) {
            throw new IllegalStateException("MAC not initialized");
        }
        if (cleanable != null) {
            // Suppress keyBytes zeroing: we still need them for the doInit0 call below
            macState.setKeyBytes(null);
            cleanable.clean();
        }
        nativeHandle = doInit0(getAlgorithm(), getCipherType(), getDigestType(), this.cachedIV, this.outputLength, keyBytes);
        if (nativeHandle == 0) {
            throw new ProviderException("Failed to reset MAC");
        }
        macState = new MACState(nativeHandle);
        macState.setKeyBytes(keyBytes);
        cleanable = cleaner.register(this, macState);
    }

    @Override
    protected void engineUpdate(byte input) {
        engineUpdate(new byte[] { input });
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int length) {
        engineUpdate(Arrays.copyOfRange(input, offset, offset + length));
    }

    @Override
    protected void engineUpdate(ByteBuffer buffer) {
        int remaining = buffer.remaining();
        if (remaining <= 0) {
            return;
        }
        byte[] chunk = new byte[remaining];
        buffer.get(chunk);
        engineUpdate(chunk);
    }

    private void engineUpdate(byte[] input) {
        if (nativeHandle == 0) {
            throw new IllegalStateException("MAC not initialized");
        }
        doUpdate0(input);
    }

    private boolean isHMAC(OpenSSLMAC object) {
        return object instanceof HMACwithSHA1
            || object instanceof HMACwithSHA3_512; 
    }

    private static void cleanupNativeMemory(long handle) {
        cleanupNativeMemory0(handle);
    }

    private static native void cleanupNativeMemory0(long handle);
    native long doInit0(String algo, String cipher, String digest, byte[] iv, int outLen, byte[] key);
    native int getMacLength();
    native void doUpdate0(byte[] input);
    native byte[] doFinal0();
}
