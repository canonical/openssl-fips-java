package com.canonical.openssl.mac;

import com.canonical.openssl.util.NativeMemoryCleaner;
import com.canonical.openssl.util.NativeLibraryLoader;
import java.lang.ref.Cleaner;
import java.nio.ByteBuffer;
import java.security.Key;
import java.util.Arrays;
import javax.crypto.MacSpi;
import java.security.spec.AlgorithmParameterSpec;
import javax.xml.crypto.dsig.spec.HMACParameterSpec;

public abstract class OpenSSLMAC extends MacSpi {

    static {
        NativeLibraryLoader.load();
    }


    private static class MACState implements Runnable {
        private long nativeHandle;

        MACState(long handle) {
            this.nativeHandle = handle;
        }

        @Override
        public void run() {
            cleanupNativeMemory(nativeHandle);
        }
    }

    long nativeHandle;
    String cipherType;
    String digestType;
    byte[] initVector;

    protected abstract String getAlgorithm();
    protected abstract String getCipherType();
    protected abstract String getDigestType();
    protected abstract byte[] getIV();

    private static Cleaner cleaner = NativeMemoryCleaner.cleaner;
    private Cleaner.Cleanable cleanable;

    @Override
    protected byte[] engineDoFinal() {
        return doFinal0();
    }

    @Override
    protected int engineGetMacLength() {
        return getMacLength();
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec spec) {
        var outputLength = -1;
        if (spec != null && isHMAC(this) && spec instanceof HMACParameterSpec hmacSpec) {
            outputLength = hmacSpec.getOutputLength();
        }
        nativeHandle = doInit0(getAlgorithm(), getCipherType(), getDigestType(), getIV(), outputLength, key.getEncoded());
        cleanable = cleaner.register(this, new MACState(nativeHandle));
    }

    @Override
    protected void engineReset() {
        // TODO
    }

    @Override
    protected void engineUpdate(byte input) {
        engineUpdate(new byte[] { input });
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int length) {
        engineUpdate(Arrays.copyOfRange(input, offset, length));
    }

    @Override
    protected void engineUpdate(ByteBuffer buffer) {
        engineUpdate(buffer.array());
    }

    private void engineUpdate(byte[] input) {
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
