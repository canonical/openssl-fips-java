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
package com.canonical.openssl.keyagreement;

import com.canonical.openssl.util.NativeMemoryCleaner;
import com.canonical.openssl.util.NativeLibraryLoader;
import java.lang.ref.Cleaner;
import java.util.concurrent.atomic.AtomicLong;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/* This implementation will be exercised by the user through the
 * javax.crypto.KeyAgreement API which isn't marked thread-safe.
 * This implementation is also NOT thread-safe and applications need
 * handle thread-safety concerns if need be.
 */

abstract public class OpenSSLKeyAgreement extends KeyAgreementSpi {
    static {
        NativeLibraryLoader.load();
    }

    public static final int AGREEMENT_DH = 0;
    public static final int AGREEMENT_ECDH = 1;

    enum State { UNINITIALIZED, INITIALIZED, PEER_KEY_ADDED };
    private State state = State.UNINITIALIZED;

    private long nativeHandle = 0;

    private static class KeyAgreementState implements Runnable {
        private final AtomicLong nativeHandle;

        KeyAgreementState(long handle) {
            this.nativeHandle = new AtomicLong(handle);
        }

        @Override
        public void run() {
            long handle = nativeHandle.getAndSet(0);
            if (handle != 0) cleanupNativeMemory(handle);
        }
    }

    private static Cleaner cleaner = NativeMemoryCleaner.cleaner;
    private Cleaner.Cleanable cleanable;

    protected Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException {
        if (state == State.UNINITIALIZED) {
            throw new IllegalStateException("The KeyAgreement is not initialized yet");
        }
        if (key == null) {
            throw new InvalidKeyException("Key must not be null");
        }
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new InvalidKeyException("Key does not support encoding");
        }
        try {
            engineDoPhase0(encoded);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
        state = State.PEER_KEY_ADDED;
        return null;
    }

    protected byte[] engineGenerateSecret() {
        if (state != State.PEER_KEY_ADDED)
            throw new IllegalStateException("The peer key hasn't been added yet");
        return engineGenerateSecret0();
    }

    protected int engineGenerateSecret(byte[] sharedSecret, int offset) {
        byte[] secret = engineGenerateSecret();
        try {
            System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
            return secret.length;
        } finally {
            Arrays.fill(secret, (byte)0);
        }
    }

    protected SecretKey engineGenerateSecret(String algorithm) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] secret = engineGenerateSecret();
        try {
            return new SecretKeySpec(secret, algorithm);
        } finally {
            Arrays.fill(secret, (byte)0);
        }
    }

    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException(
                "AlgorithmParameterSpec is not supported; the key's own parameters are used");
        }
        engineInit(key, random);
    }

    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key must not be null");
        }
	// This is needed if the KeyAgreement is reused.
        if (cleanable != null) {
            cleanable.clean();
        }
        nativeHandle = initialize(key);
        cleanable = cleaner.register(this, new KeyAgreementState(nativeHandle));
        state = State.INITIALIZED;
    }

    protected abstract long initialize(Key key);

    private static void cleanupNativeMemory(long handle) {
        cleanupNativeMemory0(handle);
    }

    private static native void cleanupNativeMemory0(long handle);
    protected native long engineInit0(int type, byte[] privateKey);
    native void engineDoPhase0(byte[] publicKey);
    native byte[] engineGenerateSecret0();
}
