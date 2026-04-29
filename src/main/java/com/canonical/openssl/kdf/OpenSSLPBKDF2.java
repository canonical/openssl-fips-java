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
package com.canonical.openssl.kdf;

import com.canonical.openssl.util.NativeLibraryLoader;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.SecretKeyFactorySpi;

/* Source: BouncyCastle User Guide
 * URL: https://downloads.bouncycastle.org/fips-java/docs/BC-FJA-UserGuide-1.0.2.pdf
 * Quote:
 *  "KDFs are currently not directly exposed in the JCE/JCA layer,
 *   although they are made use of internally by algorithms like
 *   Diffe-Hellman and also by the JSSE. They can be invoked directly
 *   using the low-level API."
 */

/* At the C level, the prototype implements PBKDF2 and HKDF. The latter
 * HMAC-based KDF does not fit into any JCE/JCA API. The former, PBKDF2,
 * could be provided using the SecretKeyFactory API because its key spec
 * can be represented by class PBEKeySpec. As a result, only PBKDF2
 * is implemented in this prototype.
 */

/* This implementation will be exercised by the user through the
 * javax.crypto.SecretKeyFactory API which isn't marked thread-safe.
 * This implementation is also NOT thread-safe and applications need
 * handle any concerns regarding the same.
 */
public class OpenSSLPBKDF2 extends SecretKeyFactorySpi {

    static {
        NativeLibraryLoader.load();
    }

    public class PBKDF2SecretKey implements PBEKey {
        char[] password;
        byte[] salt;
        int iterationCount;

        byte[] keyBytes;
        private volatile boolean destroyed = false;

        public PBKDF2SecretKey(char[] password, byte[] salt, int iterationCount) {
            this.password = password.clone();
            this.salt = salt;
            this.iterationCount = iterationCount;
        }

        private void checkDestroyed() {
            if (destroyed) {
                throw new IllegalStateException("PBKDF2SecretKey has been destroyed");
            }
        }

        public int getIterationCount() {
            checkDestroyed();
            return iterationCount;
        }

        public char[] getPassword() {
            checkDestroyed();
            return password.clone();
        }

        public byte[] getSalt() {
            checkDestroyed();
            return salt;
        }

        public void setEncoded(byte[] keyBytes) {
            checkDestroyed();
            this.keyBytes = keyBytes;
        }

        public byte[] getEncoded() {
            checkDestroyed();
            return keyBytes;
        }

        public String getFormat() {
            return "RAW";
        }

        public String getAlgorithm() {
            return "PBKDF2-SHA512";
        }

        @Override
        public void destroy() {
            if (destroyed) {
                return;
            }
            if (password != null) {
                Arrays.fill(password, '\0');
            }
            if (keyBytes != null) {
                Arrays.fill(keyBytes, (byte) 0);
            }
            destroyed = true;
        }

        @Override
        public boolean isDestroyed() {
            return destroyed;
        }
    }

    protected SecretKey engineGenerateSecret(KeySpec keyspec) throws InvalidKeySpecException {
        if (keyspec instanceof PBEKeySpec pbeKeySpec) {
            PBKDF2SecretKey secretKey = new PBKDF2SecretKey(pbeKeySpec.getPassword(),
                                    pbeKeySpec.getSalt(), pbeKeySpec.getIterationCount());
            byte[] secretBytes = generateSecret0(pbeKeySpec.getPassword(), pbeKeySpec.getSalt(),
                                                pbeKeySpec.getIterationCount());
            if (secretBytes == null) {
                throw new InvalidKeySpecException("PBKDF2 derivation failed");
            }
            secretKey.setEncoded(secretBytes);
            return secretKey;
        } else {
            throw new InvalidKeySpecException("Invalid KeySpec type, should be PBEKeySpec");
        }
    }

    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException {
        // TODO: this is quite half-hearted :-/
        if (keySpec.isAssignableFrom(PBEKeySpec.class) && key instanceof PBEKey pbeKey) {
            return new PBEKeySpec(pbeKey.getPassword(), pbeKey.getSalt(), pbeKey.getIterationCount());
        }
        throw new InvalidKeySpecException("Given key is not representable by " + keySpec);
    }

    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        if (key instanceof PBEKey pbeKey) {
            PBKDF2SecretKey secretKey = new PBKDF2SecretKey(pbeKey.getPassword(), pbeKey.getSalt(),
                                                            pbeKey.getIterationCount());
            byte[] secretBytes = generateSecret0(pbeKey.getPassword(), pbeKey.getSalt(), pbeKey.getIterationCount());
            if (secretBytes == null) {
                throw new InvalidKeyException("PBKDF2 derivation failed");
            }
            secretKey.setEncoded(secretBytes);
            return secretKey;
        } else {
            throw new InvalidKeyException("A key of type PBEKey is expected, given " + key.getClass());
        }
    }

    private native byte[] generateSecret0(char[] password, byte[] salt, int iterationCount); 
}
