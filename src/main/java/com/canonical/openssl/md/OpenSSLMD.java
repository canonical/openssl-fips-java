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

/* This implementation will be exercised by the user through the
 * java.security.MessageDigest API which isn't marked thread-safe.
 * This implementation is also NOT thread-safe and applications need
 * handle thread-safety concerns if need be.
 */
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
        nativeHandle = doInit0(mdName);
        cleanable = cleaner.register(nativeHandle, new MDState(nativeHandle));
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
