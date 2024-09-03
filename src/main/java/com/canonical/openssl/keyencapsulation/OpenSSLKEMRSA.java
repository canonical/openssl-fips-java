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
package com.canonical.openssl.keyencapsulation;

import com.canonical.openssl.util.NativeMemoryCleaner;
import com.canonical.openssl.util.NativeLibraryLoader;
import java.lang.ref.Cleaner;
import javax.crypto.DecapsulateException;
import javax.crypto.KEM;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.KEMSpi;
import javax.crypto.KEMSpi.EncapsulatorSpi;
import javax.crypto.KEMSpi.DecapsulatorSpi;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.spec.SecretKeySpec;

/* This implementation will be exercised by the user through the
 * javax.crypto.KEM API which isn't marked thread-safe.
 * This implementation is also NOT thread-safe and applications need
 * handle thread-safety concerns if need be.
 */

final public class OpenSSLKEMRSA implements KEMSpi {

    static {
        NativeLibraryLoader.load();
    }

    @Override
    public String toString() {
        return "RSA Key Encapsulation Mechanism";
    }

    public EncapsulatorSpi engineNewEncapsulator(PublicKey publicKey,
            AlgorithmParameterSpec spec, SecureRandom secureRandom)
                    throws InvalidAlgorithmParameterException, InvalidKeyException {
        // TODO: spec, secureRandom are ignored, we could use RSAKeyGenParameterSpec
        if (publicKey instanceof RSAPublicKey rsaPublicKey)
            return new RSAKEMEncapsulator(rsaPublicKey);
        else
            throw new InvalidKeyException("Public key is not an RSAPublicKey");
    }

    public DecapsulatorSpi engineNewDecapsulator(PrivateKey privateKey, AlgorithmParameterSpec spec)
            throws InvalidAlgorithmParameterException, InvalidKeyException {
        // TODO: spec, secureRandom are ignored, we could use RSAKeyGenParameterSpec
        if (privateKey instanceof RSAPrivateKey rsaPrivateKey)
            return new RSAKEMDecapsulator(rsaPrivateKey);
        else
            throw new InvalidKeyException("Private key is not an RSAPrivateKey"); 
    }

    final public class RSAKEMEncapsulator implements KEMSpi.EncapsulatorSpi {
        long nativeHandle = 0;

        private static class EncapsulatorState implements Runnable {
            private long nativeHandle;

            EncapsulatorState(long handle) {
                this.nativeHandle = handle;
            }

            @Override
            public void run() {
                cleanupNativeMemory(nativeHandle);
            }
        }

        private static Cleaner cleaner = NativeMemoryCleaner.cleaner;
        private final Cleaner.Cleanable cleanable;

        public RSAKEMEncapsulator(PublicKey key) {
            nativeHandle = encapsulatorInit0(key.getEncoded());
            cleanable = cleaner.register(this, new EncapsulatorState(nativeHandle));
        }

        public KEM.Encapsulated engineEncapsulate(int from, int to, String algorithm) {
            // TODO: ignoring from, to in the prototype
            int secretSize = engineSecretSize();
            byte[] secretBytes = new byte[secretSize];

            int encapsulationSize = engineEncapsulationSize();
            byte[] encapsulatedBytes = new byte[encapsulationSize];

            engineEncapsulate0(secretBytes, encapsulatedBytes);
            SecretKey secretKey = new SecretKeySpec(secretBytes, algorithm);
            return new KEM.Encapsulated(secretKey, encapsulatedBytes, null);
        }

        public int engineSecretSize() {
            return engineSecretSize0(); 
        }

        public int engineEncapsulationSize() {
            return engineEncapsulationSize0();
        }

        private static void cleanupNativeMemory(long handle) {
            cleanupNativeMemory0(handle);
        }

        private static native void cleanupNativeMemory0(long handle);
        private native long encapsulatorInit0(byte[] publicKeyBytes);
        private native void engineEncapsulate0(byte[] secretBytes, byte[] encapsulatedBytes);
        private native int engineSecretSize0();
        private native int engineEncapsulationSize0();
    }

    final public class RSAKEMDecapsulator implements KEMSpi.DecapsulatorSpi {
        long nativeHandle = 0;

        private static class DecapsulatorState implements Runnable {
            private long nativeHandle;

            DecapsulatorState(long handle) {
                this.nativeHandle = handle;
            }

            @Override
            public void run() {
                cleanupNativeMemory(nativeHandle);
            }
        }

        private static Cleaner cleaner = NativeMemoryCleaner.cleaner;
        private final Cleaner.Cleanable cleanable;

        public RSAKEMDecapsulator(PrivateKey key) {
            nativeHandle = decapsulatorInit0(key.getEncoded());
            cleanable = cleaner.register(this, new DecapsulatorState(nativeHandle));
        }

        public SecretKey engineDecapsulate(byte[] encapsulation, int from, int to, String algorithm)
                throws DecapsulateException {
            byte[] secretBytes = engineDecapsulate0(encapsulation);
            return new SecretKeySpec(secretBytes, algorithm);
        }

        public int engineSecretSize() {
            return engineSecretSize0();
        }

        public int engineEncapsulationSize() {
            return engineEncapsulationSize0();
        }

        private static void cleanupNativeMemory(long handle) {
            cleanupNativeMemory0(handle);
        }

        private static native void cleanupNativeMemory0(long handle);
        private native long decapsulatorInit0(byte[] key);
        private native byte[] engineDecapsulate0(byte[] encapsulateArray);
        private native int engineSecretSize0();
        private native int engineEncapsulationSize0();
    }
}

