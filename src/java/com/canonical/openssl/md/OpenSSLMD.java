package com.canonical.openssl.md;

import com.canonical.openssl.util.NativeMemoryCleaner;
import com.canonical.openssl.util.NativeLibraryLoader;

import java.lang.ref.Cleaner;
import java.nio.ByteBuffer;
import java.security.DigestException;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Set;

public abstract class OpenSSLMD extends MessageDigestSpi {

    static {
        NativeLibraryLoader.load(); 
    }

    private static class MDState implements Runnable {
        private long nativeHandle;

        MDState(long handle) {
            this.nativeHandle = handle;
        }

        @Override
        public void run() {
            cleanupNativeMemory(nativeHandle);
        }
    }

    private String mdName;
    private long nativeHandle;
    private boolean initialized = false;

    private static Cleaner cleaner = NativeMemoryCleaner.cleaner;
    private Cleaner.Cleanable cleanable;

    protected OpenSSLMD(String algorithm) {
        this.mdName = algorithm;
    }

    @Override
    protected byte[] engineDigest() {
       return doFinal0();
    }

    @Override
    protected int engineDigest(byte[] buf, int offset, int len) throws DigestException {
        byte[] digest = engineDigest();
        if (len < digest.length) {
            throw new DigestException("Digest length = " + digest.length  + " is greater than len = " + len);
        }
        System.arraycopy(digest, 0, buf, offset, len);
        return len;
    }

    abstract protected int engineGetDigestLength();

    @Override
    protected void engineReset() {
        // TODO
    }

    @Override
    protected void engineUpdate(byte input) {
        engineUpdate(new byte[] { input });
    }
    
    @Override
    protected void engineUpdate(byte []input, int offset, int len) {
        engineUpdate(Arrays.copyOfRange(input, offset, len));
    }

    @Override
    protected void engineUpdate(ByteBuffer data) {
        engineUpdate(data.array());
    }

    private void engineUpdate(byte[] data) {
        synchronized(this) {
           if (!this.initialized) {
               nativeHandle = doInit0(mdName);
               cleanable = cleaner.register(nativeHandle, new MDState(nativeHandle));
               this.initialized = true;
           }
        }
        doUpdate0(data);
    }

    public String getMDName() {
        return mdName;
    }

    private static void cleanupNativeMemory(long handle) {
        cleanupNativeMemory0(handle);
    }

    private static native void cleanupNativeMemory0(long handle);
    private native long doInit0(String name);
    private native void doUpdate0(byte[] data);
    private native byte[] doFinal0();
}
