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
import java.util.concurrent.atomic.AtomicLong;
import java.nio.ByteBuffer;
import java.security.DigestException;
import java.security.MessageDigestSpi;
import java.security.ProviderException;
import java.util.Arrays;

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
        private final AtomicLong nativeHandle;

        MDState(long handle) {
            this.nativeHandle = new AtomicLong(handle);
        }

        @Override
        public void run() {
            long handle = nativeHandle.getAndSet(0);
            if (handle != 0) cleanupNativeMemory(handle);
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

    private void ensureInitialized() {
        if (!initialized) {
            nativeHandle = doInit0(mdName);
            if (nativeHandle == 0) {
                throw new ProviderException("Failed to initialize message digest " + mdName);
            }
            cleanable = cleaner.register(this, new MDState(nativeHandle));
            initialized = true;
        }
    }

    @Override
    protected byte[] engineDigest() {
        ensureInitialized();
        return doFinal0();
    }

    @Override
    protected int engineDigest(byte[] buf, int offset, int len) throws DigestException {
        byte[] digest = engineDigest();
        if (len < digest.length) {
            throw new DigestException("Digest length = " + digest.length  + " is greater than len = " + len);
        }
        System.arraycopy(digest, 0, buf, offset, digest.length);
        return digest.length;
    }

    abstract protected int engineGetDigestLength();

    @Override
    protected void engineReset() {
        if (cleanable != null) {
            cleanable.clean();
        }
        nativeHandle = doInit0(mdName);
        if (nativeHandle == 0) {
            throw new ProviderException("Failed to initialize message digest " + mdName);
        }
        cleanable = cleaner.register(this, new MDState(nativeHandle));
        initialized = true;
    }

    @Override
    protected void engineUpdate(byte input) {
        engineUpdate(new byte[] { input });
    }
    
    @Override
    protected void engineUpdate(byte []input, int offset, int len) {
        engineUpdate(Arrays.copyOfRange(input, offset, offset + len));
    }

    @Override
    protected void engineUpdate(ByteBuffer data) {
        int remaining = data.remaining();
        if (remaining <= 0) {
            return;
        }
        byte[] chunk = new byte[remaining];
        data.get(chunk);
        engineUpdate(chunk);
    }

    private void engineUpdate(byte[] data) {
        ensureInitialized();
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
