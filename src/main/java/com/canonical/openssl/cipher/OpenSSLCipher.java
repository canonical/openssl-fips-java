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

import com.canonical.openssl.util.NativeMemoryCleaner;
import com.canonical.openssl.util.NativeLibraryLoader;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;
import java.lang.ref.Cleaner;
import java.nio.ByteBuffer;
import javax.crypto.CipherSpi;
import javax.crypto.Cipher;
import java.security.Key;
import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import javax.crypto.ShortBufferException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;

/* This implementation will be exercised by the user through the
 * javax.crypto.Cipher API which isn't marked thread-safe.
 * This implementation is also NOT thread-safe and applications need
 * handle thread-safety concerns if need be.
 */

abstract public class OpenSSLCipher extends CipherSpi {

    static {
        NativeLibraryLoader.load();
    }

    static final int UNDECIDED = -1;
    static final int DECRYPT = 0;
    static final int ENCRYPT = 1;

    String name;
    String mode;
    String padding;
    long cipherContext;
    byte []keyBytes;
    byte []iv;
    int inputSize;
    int outputSize;
    int opmode = UNDECIDED;
    boolean firstUpdate = true;

    private static class CipherState implements Runnable {
        private final AtomicLong nativeHandle;
        private volatile byte[] iv;

        CipherState(long handle) {
            this.nativeHandle = new AtomicLong(handle);
        }

        void setIV(byte[] iv) {
            this.iv = iv;
        }

        @Override
        public void run() {
            long handle = nativeHandle.getAndSet(0);
            if (handle != 0) {
                cleanupNativeMemory(handle);
            }
            byte[] localIv = iv;
            if (localIv != null) {
                Arrays.fill(localIv, (byte)0);
                this.iv = null;
            }
        }
    }

    private final CipherState cipherState;
    private Cleaner cleaner = NativeMemoryCleaner.cleaner;
    private Cleaner.Cleanable cleanable;

    protected OpenSSLCipher(String nameKeySizeAndMode, String padding) {
        String[] parts = nameKeySizeAndMode.split("-");
        if (parts.length < 3) {
            throw new IllegalArgumentException("Cipher name must follow the format <alg>-<keysize>-<mode>, got: " + nameKeySizeAndMode);
        }
        this.name = nameKeySizeAndMode;
        this.mode = parts[2];
        this.padding = padding;
        this.cipherContext = createContext0(nameKeySizeAndMode, padding);
        this.cipherState = new CipherState(this.cipherContext);
        cleanable = cleaner.register(this, cipherState);
    }

    static final int GCM_TAG_LEN = 16;

    private boolean isModeCCM() {
        return mode.equals("CCM");
    }

    private boolean isModeGCM() {
        return mode.equals("GCM");
    }

    private boolean isAADSupported() {
        // Among FIPS approved Ciphers, only -CCM and -GCM mode ciphers support AAD
        return mode.equals("CCM") || mode.equals("GCM");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) {
        // Note: AlgorithmParameters support not yet implemented
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) {
        throw new UnsupportedOperationException ("The prototype supports only symmetric-key encrypt/decrypt with IVs");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) {
        if (!(params instanceof IvParameterSpec)) {
            throw new UnsupportedOperationException ("The prototype supports only symmetric-key encrypt/decrypt with an IV");
        }
        this.firstUpdate = true;
        this.inputSize = this.outputSize = 0;
        this.opmode = ((opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE)? ENCRYPT : DECRYPT);
        // Zero any key/IV material left over from a previous init before overwriting
        if (this.keyBytes != null) {
            Arrays.fill(this.keyBytes, (byte)0);
            this.keyBytes = null;
        }
        if (this.iv != null) {
            Arrays.fill(this.iv, (byte)0);
            this.iv = null;
        }
        this.keyBytes = key.getEncoded();
        this.iv = ((IvParameterSpec)params).getIV();
        cipherState.setIV(this.iv);
        if (!isModeCCM()) {
            doInit0(null, 0, 0, keyBytes, iv, this.opmode);
            Arrays.fill(keyBytes, (byte)0);
            this.keyBytes = null;
        }
    }

    @Override
    protected void engineSetMode(String mode) {
        this.mode = mode;
    }

    @Override
    protected void engineSetPadding(String padding) {
        this.padding = padding;
    }

    @Override
    protected byte[] engineUpdate(byte[] bytes, int offset, int length) {
        if (offset + length > bytes.length) {
            throw new IllegalArgumentException("Invalid offset and/or length");
        }
        if (isModeCCM() && firstUpdate) {
            doInit0(bytes, offset, length, keyBytes, iv, opmode);
            Arrays.fill(keyBytes, (byte)0);
            this.keyBytes = null;
        }
        firstUpdate = false;
        inputSize += length; 
        byte[] ret = doUpdate0(bytes, offset, length);
        outputSize += ret.length;
        return ret;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        throw new UnsupportedOperationException("Unimplemented");
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        throw new UnsupportedOperationException("The prototype ignores AlgorithmParameters");
    }

    @Override
    protected byte[] engineGetIV() {
        return iv;
    }

    protected abstract int engineGetOutputSize(int inputLen);

    protected abstract int engineGetBlockSize();

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, 
                                   IllegalBlockSizeException, BadPaddingException {
        throw new UnsupportedOperationException("Not implmenented");
    }

    @Override
    protected byte[] engineDoFinal(byte[] bytes, int offset, int length) throws IllegalBlockSizeException, BadPaddingException {
        if (isModeCCM() && firstUpdate) {
            firstUpdate = false;
            doInit0(bytes, offset, length, keyBytes, iv, opmode);
            Arrays.fill(keyBytes, (byte)0);
            this.keyBytes = null;
        }
        int ciphertextLen = length;
        if (isModeGCM() && opmode == DECRYPT) {
            ciphertextLen = length - GCM_TAG_LEN;
            setGCMTag0(bytes, offset + ciphertextLen, GCM_TAG_LEN);
        }
        byte[] transformed = doUpdate0(bytes, offset, ciphertextLen);
        return doFinal0(transformed, transformed.length);
    }

    @Override
    protected void engineUpdateAAD(byte[] aad, int offset, int len) {
        if (!firstUpdate) {
            throw new IllegalStateException("An update() method has already been called");
        }

        if (!isAADSupported()) {
            throw new IllegalStateException("Cipher: " + name + "-" + mode + " does not support Additional Authentication Data");
        }

        updateAAD0(aad, offset, len);

    }

    @Override
    protected void engineUpdateAAD(ByteBuffer src) {
        int remaining = src.remaining();
        byte[] aad = new byte[remaining];
        src.get(aad);
        updateAAD0(aad, 0, remaining);
    }

    @Override
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
        byte[] encoded = key.getEncoded();
        if ((encoded == null) || (encoded.length == 0)) {
            throw new InvalidKeyException("Could not obtain encoded key");
        }

        try {
            return engineDoFinal(encoded, 0, encoded.length);
        } catch (BadPaddingException e) {
            throw new InvalidKeyException("Wrapping failed", e);
        }
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
                    throws InvalidKeyException, NoSuchAlgorithmException {

        if (wrappedKeyType == Cipher.PUBLIC_KEY || wrappedKeyType == Cipher.PRIVATE_KEY) {
            throw new UnsupportedOperationException("No KeyFactory for public/private key pairs in the provider yet");
        }

        byte[] keyMaterial = null;

        try {
            keyMaterial = engineDoFinal(wrappedKey, 0, wrappedKey.length);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new InvalidKeyException("Unwrapping failed", e);
        }

        return createKey(keyMaterial, wrappedKeyAlgorithm, wrappedKeyType);
    }

    // TODO: might need to move to its own helper class
    private Key createKey(byte[] keyMaterial, String algo, int keyType) throws NoSuchAlgorithmException {
        // TODO: keyType is only SECRET_KEY for now
        return new SecretKeySpec(keyMaterial, 0, keyMaterial.length, algo);
    }

    private static void cleanupNativeMemory(long handle) {
        cleanupNativeMemory0(handle);
    }

    private static native void cleanupNativeMemory0(long handle);

    native long createContext0(String nameAndMode, String padding);
    native void doInit0(byte[] input, int offset, int length, byte[] key, byte[] iv, int opmode);
    native byte[] doUpdate0(byte[] input, int offset, int length);
    native byte[] updateAAD0(byte[] aad, int offset, int len);
    native byte[] doFinal0(byte[] output, int length);
    native void setGCMTag0(byte[] tag, int offset, int len);
}
