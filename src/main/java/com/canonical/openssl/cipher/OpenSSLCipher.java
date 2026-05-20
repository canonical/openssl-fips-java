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
import javax.crypto.spec.GCMParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import javax.crypto.ShortBufferException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.ProviderException;
import java.security.spec.InvalidParameterSpecException;
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
    private ClearableBuffer aeadDecryptBuffer;

    private static final class ClearableBuffer {
        private byte[] buf = new byte[256];
        private int count;

        void write(byte[] src, int offset, int len) {
            ensure(count + len);
            System.arraycopy(src, offset, buf, count, len);
            count += len;
        }

        private void ensure(int min) {
            if (min <= buf.length) {
                return;
            }
            int newCap = buf.length;
            while (newCap < min) {
                newCap <<= 1;
            }
            byte[] old = buf;
            buf = new byte[newCap];
            System.arraycopy(old, 0, buf, 0, count);
            Arrays.fill(old, (byte) 0);
        }

        byte[] takeAndClear() {
            byte[] out = new byte[count];
            System.arraycopy(buf, 0, out, 0, count);
            Arrays.fill(buf, 0, count, (byte) 0);
            count = 0;
            return out;
        }

        void clear() {
            Arrays.fill(buf, 0, count, (byte) 0);
            count = 0;
        }
    }

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
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params == null) {
            engineInit(opmode, key, random);
            return;
        }
        AlgorithmParameterSpec spec;
        try {
            if (isModeGCM() || isModeCCM()) {
                spec = params.getParameterSpec(GCMParameterSpec.class);
            } else {
                spec = params.getParameterSpec(IvParameterSpec.class);
            }
        } catch (InvalidParameterSpecException e) {
            throw new InvalidAlgorithmParameterException("Could not decode AlgorithmParameters for mode " + mode, e);
        }
        engineInit(opmode, key, spec, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key must not be null");
        }

        if ("ECB".equals(mode)) {
            byte[] newKeyBytes = key.getEncoded();
            if (newKeyBytes == null) {
                throw new InvalidKeyException("Key does not support encoding");
            }
            resetStateForInit(opmode);
            this.keyBytes = newKeyBytes;
            cipherState.setIV(null);
            doInit0(null, 0, 0, keyBytes, null, this.opmode);
            Arrays.fill(keyBytes, (byte)0);
            this.keyBytes = null;
            return;
        }

        if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE) {
            throw new InvalidKeyException("Mode " + mode + " requires an IV for decrypt/unwrap; use init with an IvParameterSpec");
        }

        byte[] generatedIv = new byte[ivLengthForMode()];
        SecureRandom rng = (random != null) ? random : new SecureRandom();
        rng.nextBytes(generatedIv);
        try {
            engineInit(opmode, key, new IvParameterSpec(generatedIv), random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException("Failed to initialize with generated IV", e);
        }
    }

    private void resetStateForInit(int opmode) {
        this.firstUpdate = true;
        this.inputSize = this.outputSize = 0;
        if (this.aeadDecryptBuffer != null) {
            this.aeadDecryptBuffer.clear();
            this.aeadDecryptBuffer = null;
        }
        this.opmode = ((opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) ? ENCRYPT : DECRYPT);
        if (this.keyBytes != null) {
            Arrays.fill(this.keyBytes, (byte) 0);
            this.keyBytes = null;
        }
        if (this.iv != null) {
            Arrays.fill(this.iv, (byte) 0);
            this.iv = null;
        }
    }

    private int ivLengthForMode() {
        switch (mode) {
            case "GCM":
            case "CCM":
                return 12;
            default:
                return 16;
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (key == null) {
            throw new InvalidKeyException("Key must not be null");
        }
        byte[] specIv;
        if (params instanceof IvParameterSpec ivSpec) {
            specIv = ivSpec.getIV();
        } else if (params instanceof GCMParameterSpec gcmSpec) {
            if (gcmSpec.getTLen() != GCM_TAG_LEN * 8) {
                throw new InvalidAlgorithmParameterException("Only " + (GCM_TAG_LEN * 8) + "-bit GCM tag length is supported, got: " + gcmSpec.getTLen());
            }
            specIv = gcmSpec.getIV();
        } else {
            throw new InvalidAlgorithmParameterException("Unsupported AlgorithmParameterSpec: " + (params == null ? "null" : params.getClass().getName()));
        }
        byte[] newKeyBytes = key.getEncoded();
        if (newKeyBytes == null) {
            throw new InvalidKeyException("Key does not support encoding");
        }
        resetStateForInit(opmode);
        this.keyBytes = newKeyBytes;
        this.iv = specIv;
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
        if (bytes == null) {
            throw new NullPointerException("input array must not be null");
        }
        if (offset < 0 || length < 0 || offset > bytes.length - length) {
            throw new IllegalArgumentException("Invalid offset and/or length");
        }
        if (isAADSupported() && opmode == DECRYPT) {
            if (aeadDecryptBuffer == null) {
                aeadDecryptBuffer = new ClearableBuffer();
            }
            aeadDecryptBuffer.write(bytes, offset, length);
            inputSize += length;
            return new byte[0];
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
        byte[] result = engineUpdate(input, inputOffset, inputLen);
        try {
            if (result == null || result.length == 0) {
                return 0;
            }
            if (output == null || output.length - outputOffset < result.length) {
                throw new ShortBufferException("Output buffer too small: need " + result.length + " bytes");
            }
            System.arraycopy(result, 0, output, outputOffset, result.length);
            return result.length;
        } finally {
            if (result != null) {
                Arrays.fill(result, (byte) 0);
            }
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        if (iv == null) {
            return null;
        }
        String name;
        AlgorithmParameterSpec spec;
        if (isModeGCM()) {
            name = "GCM";
            spec = new GCMParameterSpec(GCM_TAG_LEN * 8, iv);
        } else if (isModeCCM()) {
            name = "CCM";
            spec = new GCMParameterSpec(GCM_TAG_LEN * 8, iv);
        } else {
            name = "AES";
            spec = new IvParameterSpec(iv);
        }
        AlgorithmParameters ap;
        try {
            ap = AlgorithmParameters.getInstance(name);
        } catch (NoSuchAlgorithmException e) {
            /* No JCA-registered AlgorithmParameters for this mode (e.g. CCM on stock JDK);
             * SPI contract allows returning null. */
            return null;
        }
        try {
            ap.init(spec);
        } catch (InvalidParameterSpecException e) {
            throw new ProviderException("Could not encode AlgorithmParameters", e);
        }
        return ap;
    }

    @Override
    protected byte[] engineGetIV() {
        return iv == null ? null : iv.clone();
    }

    protected abstract int engineGetOutputSize(int inputLen);

    protected abstract int engineGetBlockSize();

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException,
                                   IllegalBlockSizeException, BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        try {
            if (result == null || result.length == 0) {
                return 0;
            }
            if (output == null || output.length - outputOffset < result.length) {
                throw new ShortBufferException("Output buffer too small: need " + result.length + " bytes");
            }
            System.arraycopy(result, 0, output, outputOffset, result.length);
            return result.length;
        } finally {
            if (result != null) {
                Arrays.fill(result, (byte) 0);
            }
        }
    }

    @Override
    protected byte[] engineDoFinal(byte[] bytes, int offset, int length) throws IllegalBlockSizeException, BadPaddingException {
        if (bytes == null && length == 0) {
            bytes = new byte[0];
            offset = 0;
        }
        if (bytes == null) {
            throw new NullPointerException("input array must not be null");
        }
        if (offset < 0 || length < 0 || offset > bytes.length - length) {
            throw new IllegalArgumentException("Invalid offset and/or length");
        }
        byte[] accumulated = null;
        try {
            if (isAADSupported() && opmode == DECRYPT && aeadDecryptBuffer != null) {
                aeadDecryptBuffer.write(bytes, offset, length);
                accumulated = aeadDecryptBuffer.takeAndClear();
                aeadDecryptBuffer = null;
                bytes = accumulated;
                offset = 0;
                length = accumulated.length;
            }
            if (isModeCCM() && firstUpdate) {
                firstUpdate = false;
                doInit0(bytes, offset, length, keyBytes, iv, opmode);
                Arrays.fill(keyBytes, (byte)0);
                this.keyBytes = null;
            }
            int ciphertextLen = length;
            if (isModeGCM() && opmode == DECRYPT) {
                if (length < GCM_TAG_LEN) {
                    throw new BadPaddingException("GCM ciphertext shorter than tag");
                }
                ciphertextLen = length - GCM_TAG_LEN;
                setGCMTag0(bytes, offset + ciphertextLen, GCM_TAG_LEN);
            }
            byte[] transformed = doUpdate0(bytes, offset, ciphertextLen);
            try {
                return doFinal0(transformed, transformed.length);
            } finally {
                if (transformed != null) {
                    Arrays.fill(transformed, (byte) 0);
                }
            }
        } finally {
            if (accumulated != null) {
                Arrays.fill(accumulated, (byte) 0);
            }
            if (aeadDecryptBuffer != null) {
                aeadDecryptBuffer.clear();
                aeadDecryptBuffer = null;
            }
        }
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
        } finally {
            Arrays.fill(encoded, (byte)0);
        }
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm, int wrappedKeyType)
                    throws InvalidKeyException, NoSuchAlgorithmException {

        byte[] keyMaterial = null;

        try {
            keyMaterial = engineDoFinal(wrappedKey, 0, wrappedKey.length);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new InvalidKeyException("Unwrapping failed", e);
        }

        try {
            return createKey(keyMaterial, wrappedKeyAlgorithm, wrappedKeyType);
        } finally {
            if (keyMaterial != null) Arrays.fill(keyMaterial, (byte)0);
        }
    }

    private static KeyFactory keyFactoryForAlgo(String algo) throws NoSuchAlgorithmException {
        // TODO: OpenSSLFIPSProvider does not yet register any KeyFactory implementations,
        // so PUBLIC_KEY / PRIVATE_KEY unwrapping currently always falls back to the
        // system-default provider.
        try {
            return KeyFactory.getInstance(algo, "OpenSSLFIPSProvider");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            // Algorithm not registered in OpenSSLFIPSProvider; fall back to system-default provider.
            return KeyFactory.getInstance(algo);
        }
    }

    private Key createKey(byte[] keyMaterial, String algo, int keyType) throws NoSuchAlgorithmException, InvalidKeyException {
        switch (keyType) {
            case Cipher.SECRET_KEY:
                return new SecretKeySpec(keyMaterial, 0, keyMaterial.length, algo);
            case Cipher.PUBLIC_KEY:
                try {
                    return keyFactoryForAlgo(algo).generatePublic(new X509EncodedKeySpec(keyMaterial));
                } catch (InvalidKeySpecException e) {
                    throw new InvalidKeyException("Failed to decode public key for algorithm " + algo, e);
                }
            case Cipher.PRIVATE_KEY:
                try {
                    return keyFactoryForAlgo(algo).generatePrivate(new PKCS8EncodedKeySpec(keyMaterial));
                } catch (InvalidKeySpecException e) {
                    throw new InvalidKeyException("Failed to decode private key for algorithm " + algo, e);
                }
            default:
                throw new InvalidKeyException("Unsupported wrapped key type: " + keyType);
        }
    }

    private static void cleanupNativeMemory(long handle) {
        cleanupNativeMemory0(handle);
    }

    private static native void cleanupNativeMemory0(long handle);

    native long createContext0(String nameAndMode, String padding);
    native void doInit0(byte[] input, int offset, int length, byte[] key, byte[] iv, int opmode);
    native byte[] doUpdate0(byte[] input, int offset, int length);
    native void updateAAD0(byte[] aad, int offset, int len);
    native byte[] doFinal0(byte[] output, int length);
    native void setGCMTag0(byte[] tag, int offset, int len);
}
