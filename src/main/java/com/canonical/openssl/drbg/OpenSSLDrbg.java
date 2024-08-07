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
package com.canonical.openssl.drbg;

import com.canonical.openssl.util.NativeMemoryCleaner;
import com.canonical.openssl.util.NativeLibraryLoader;
import java.lang.ref.Cleaner;
import java.security.SecureRandomSpi;
import java.security.SecureRandomParameters;
import java.security.DrbgParameters;
import java.security.Provider;

public class OpenSSLDrbg extends SecureRandomSpi {

    public static int DEFAULT_STRENGTH = 128;
    static {
        NativeLibraryLoader.load();
    }

    long drbgContext;
    SecureRandomParameters params;

    private static class DRBGState implements Runnable {
        private long nativeHandle;

        DRBGState(long handle) {
            this.nativeHandle = handle;
        }

        @Override
        public void run() {
            cleanupNativeMemory(nativeHandle);
        }
    }

    private Cleaner cleaner = NativeMemoryCleaner.cleaner;
    private Cleaner.Cleanable cleanable;

    private OpenSSLDrbg() { }

    protected OpenSSLDrbg(String name) {
        drbgContext = init(name, DEFAULT_STRENGTH, false, false, null);
        cleanable = cleaner.register(this, new DRBGState(drbgContext));
    }

    protected OpenSSLDrbg(String name, SecureRandomParameters params) throws IllegalArgumentException {
        if(params != null && !(params instanceof DrbgParameters.Instantiation)) {
            throw new IllegalArgumentException("Parameters of type DrbgParameters.Instantiation expected, passed " + params.getClass());
        }

        if (params != null) {
            this.params = params;
            DrbgParameters.Instantiation ins = (DrbgParameters.Instantiation)params; 
            this.drbgContext = init(name, ins.getStrength(), ins.getCapability().supportsPredictionResistance(),
                                 ins.getCapability().supportsReseeding(), ins.getPersonalizationString());
        } else {
            this.drbgContext = init(name, DEFAULT_STRENGTH, false, false, null);
        }
        cleanable = cleaner.register(this, new DRBGState(drbgContext));
    }

    boolean isInitialized() {
        return drbgContext != 0L;
    }
    
    @Override 
    protected SecureRandomParameters engineGetParameters() {
        return this.params;
    }

    @Override
    protected byte[] engineGenerateSeed(int numBytes) {
        return generateSeed0(numBytes);
    }

    @Override
    protected void engineNextBytes(byte[] bytes) {
        nextBytes0(bytes, DEFAULT_STRENGTH, false, null);
    }

    protected void engineNextBytes(byte[] bytes, SecureRandomParameters params) throws IllegalArgumentException {
        if (params == null) {
            engineNextBytes(bytes);
            return;
        }

        if (!(params instanceof DrbgParameters.NextBytes)) {
            throw new IllegalArgumentException("Parameters of type DrbgParameters.NextByte expected, passed " + params.getClass());
        }

        DrbgParameters.NextBytes nb = (DrbgParameters.NextBytes)params;
        nextBytes0(bytes, nb.getStrength(), nb.getPredictionResistance(), nb.getAdditionalInput());
    }

    protected void engineReseed() {
        reseed0(null, false, null);
    }

    @Override
    protected void engineReseed(SecureRandomParameters params) throws IllegalArgumentException {
        if (params == null) {
            engineReseed();
            return;
        }
        
        if (!(params instanceof DrbgParameters.Reseed)) {
            throw new IllegalArgumentException("Parameters of type DrbgParameters.Reseed expected, passed " + params.getClass());    
        }
        DrbgParameters.Reseed rs = (DrbgParameters.Reseed)params;
        reseed0(null, rs.getPredictionResistance(), rs.getAdditionalInput());
    }

    protected void engineSetSeed(byte[] seed) {
        reseed0(seed, false, null);
    }

    protected void engineSetSeed(long seed) {
        byte [] seedBytes = new byte[8];
        for (int i = 0; i < 8; i++) {
             seedBytes[i] = (byte)(seed & (long)0xff);
             seed = seed >> 8; 
        }

        engineSetSeed(seedBytes);
    }

    private static void cleanupNativeMemory(long handle) {
        cleanupNativeMemory0(handle);
    }

    private static native void cleanupNativeMemory0(long handle);
    private native long init(String name, int strength, boolean supportsPredictionResistance, boolean supportsReseeding, byte[] personalizationString);
    private native void nextBytes0(byte[] bytes, int strength, boolean supportsPredictionResistance, byte[] additionalInput);
    private native void reseed0(byte[] bytes, boolean supportsPredictionResistance, byte[] additionalInput);
    private native byte[] generateSeed0(int numBytes);
}
