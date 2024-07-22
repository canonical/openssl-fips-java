package com.canonical.openssl.keyagreement;

import com.canonical.openssl.util.NativeMemoryCleaner;
import java.lang.ref.Cleaner;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import java.util.Base64;

abstract public class OpenSSLKeyAgreement extends KeyAgreementSpi {
    static {
        System.loadLibrary("jssl");
    }

    public static int AGREEMENT_DH = 0;
    public static int AGREEMENT_ECDH = 1;

    enum State { UNINITIALIZED, INITIALIZED, PEER_KEY_ADDED };
    private State state = State.UNINITIALIZED;

    private long nativeHandle = 0;

    private static class KeyAgreementState implements Runnable {
        private long nativeHandle;

        KeyAgreementState(long handle) {
            this.nativeHandle = handle;
        }

        @Override
        public void run() {
            cleanupNativeMemory(nativeHandle);
        }
    }

    private static Cleaner cleaner = NativeMemoryCleaner.cleaner;
    private Cleaner.Cleanable cleanable;

    protected Key engineDoPhase(Key key, boolean lastPhase) {
        if (state == State.UNINITIALIZED) {
            throw new IllegalStateException("The KeyAgreement is not initialized yet");
        }
        engineDoPhase0(key.getEncoded());
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
        System.arraycopy(secret, 0, sharedSecret, offset, secret.length);
        return secret.length;
    }

    protected SecretKey engineGenerateSecret(String algorithm) {
        return null;
    }

    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random) {
        // TODO: ignore random for now, does DH or ECDH use any kind of randomness?
        throw new UnsupportedOperationException ("prototype: KeyAgreement.init() with AlgorithmParameterSpec is unsupported");
    }

    protected void engineInit(Key key, SecureRandom random) {
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
