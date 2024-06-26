package com.canonical.openssl.md;

import java.nio.ByteBuffer;
import java.security.DigestException;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Set;

public abstract class OpenSSLMD extends MessageDigestSpi {

    static {
        System.loadLibrary("jssl");
    }

    private String mdName;
    private long nativeHandle;
    private boolean initialized = false;

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
               this.initialized = true;
           }
        }
        doUpdate0(data);
    }

    public String getMDName() {
        return mdName;
    }

    private native long doInit0(String name);
    private native void doUpdate0(byte[] data);
    private native byte[] doFinal0();
}
