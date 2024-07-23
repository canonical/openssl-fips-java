package com.canonical.openssl.signature;

import com.canonical.openssl.key.*;
import com.canonical.openssl.util.NativeMemoryCleaner;
import com.canonical.openssl.util.NativeLibraryLoader;

import java.lang.ref.Cleaner;
import java.nio.ByteBuffer;
import java.security.spec.AlgorithmParameterSpec;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;

public abstract class OpenSSLSignature extends SignatureSpi {

    static {
        NativeLibraryLoader.load();    
    }

    private static class SignatureState implements Runnable {
        private long nativeHandle;

        SignatureState(long handle) {
            this.nativeHandle = handle;
        }

        @Override
        public void run() {
            cleanupNativeMemory(nativeHandle);
        }
    }
    private long nativeHandle = 0L;

    private static Cleaner cleaner = NativeMemoryCleaner.cleaner;
    private Cleaner.Cleanable cleanable;

    private Params params = new Params(null, -1, Padding.NONE, null);;

    enum Padding { NONE, PSS };

    class Params {

        static final int NO_PADDING = 0;
        static final int PSS_PADDING = 1;

        String digest;
        int saltLength;
        int padding;
        String mgf1Digest;

        public Params(String digest, int saltLength, Padding padding, String mgf1Digest) {
            this.digest = digest;
            this.saltLength = saltLength;
            this.padding = (padding == Padding.NONE ? NO_PADDING : PSS_PADDING); 
            this.mgf1Digest = mgf1Digest;
        }

        public String getDigest() {
            return this.digest;
        }

        public int getSaltLength() {
            return this.saltLength;
        }

        public String getMgf1Digest() {
            return this.mgf1Digest;
        }

        public int getPadding() {
            return padding;
        }
    }

    protected abstract String getSignatureName();

    @Override
    protected Object engineGetParameter(String param) {
        // TODO
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineSetParameter(String param, Object value) {
        // supporting only "digest" for now
        // mgf1digest and saltlen are relevant only with PSS padding, but there's
        // issue: https://github.com/pushkarnk/openssl-fips-jni-wrapper/issues/2
        if (param.equals("digest") && value instanceof String digestName) {
            this.params = new Params(digestName, -1, Padding.NONE, null);  
        } 
    }

    @Override
    protected void engineInitSign(PrivateKey key) throws InvalidKeyException {
       if (key instanceof OpenSSLPrivateKey privKey) {
           nativeHandle = engineInitSign0(getSignatureName(), privKey, params);
           cleanable = cleaner.register(this, new SignatureState(nativeHandle));
       } else {
           throw new InvalidKeyException ("Supplied PrivateKey is of type: " + key.getClass());
       }
    }

    @Override
    protected void engineInitSign(PrivateKey key, SecureRandom random) throws InvalidKeyException {
        // TODO: how does one use the SecureRandom?
        engineInitSign(key);
    }

    @Override
    protected void engineInitVerify(PublicKey key) throws InvalidKeyException {
        if (key instanceof OpenSSLPublicKey pubKey) {
            nativeHandle = engineInitVerify0(getSignatureName(), pubKey, params);
            cleanable = cleaner.register(this, new SignatureState(nativeHandle));
        } else {
            throw new InvalidKeyException ("Supplied PublicKey is not OpenSSL-based");
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        // TODO
        throw new UnsupportedOperationException();
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) {
        // TODO
        throw new UnsupportedOperationException();
    }

    @Override
    protected byte[] engineSign() {
        return engineSign0();
    }

    @Override
    protected int engineSign(byte[] outbuf, int offset, int len) {
        byte[] sign = engineSign();
        int copyLength = len < sign.length ? len : sign.length;
        System.arraycopy(sign, 0, outbuf, offset, copyLength);
        return copyLength; 
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        engineUpdate(new byte[] { b }, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        engineUpdate0(b, off, len);
    }

    @Override
    protected void engineUpdate(ByteBuffer input) {
        byte[] array = input.array();
        try {
            engineUpdate(array, 0, array.length);
        } catch (SignatureException se) {
            System.out.println("[WARNING] engineUpdate(ByteBuffer) failed with " + se);
            se.printStackTrace();
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) {
        return engineVerify(sigBytes, 0, sigBytes.length);
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes, int offset, int length) {
        return engineVerify0(sigBytes, offset, length);
    }

    private static void cleanupNativeMemory(long handle) {
        cleanupNativeMemory0(handle);
    }

    private static native void cleanupNativeMemory0(long handle);
    private native long engineInitSign0(String signatureType, OpenSSLPrivateKey privateKey, Params params);
    private native long engineInitVerify0(String signatureType, OpenSSLPublicKey publicKey, Params params);
    private native byte[] engineSign0();
    private native void engineUpdate0(byte[] input, int offset, int length);
    private native boolean engineVerify0(byte[] sigBytes, int offset, int length);
}
