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
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
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

    private static final int FIPS_MIN_ITERATIONS = 1000;
    private static final int DEFAULT_KEY_LENGTH_BYTES = 64;
    private static final int MAX_KEY_LENGTH_BYTES;

    static {
        NativeLibraryLoader.load();
        MAX_KEY_LENGTH_BYTES = getMaxKeyLengthBytes0();
    }

    public class PBKDF2SecretKey implements PBEKey {
        char[] password;
        byte[] salt;
        int iterationCount;

        byte[] keyBytes;
        private volatile boolean destroyed = false;

        public PBKDF2SecretKey(char[] password, byte[] salt, int iterationCount) {
            this.password = password.clone();
            this.salt = salt == null ? null : salt.clone();
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
            return salt == null ? null : salt.clone();
        }

        public void setEncoded(byte[] keyBytes) {
            checkDestroyed();
            this.keyBytes = keyBytes == null ? null : keyBytes.clone();
        }

        public byte[] getEncoded() {
            checkDestroyed();
            return keyBytes == null ? null : keyBytes.clone();
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
            if (salt != null) {
                Arrays.fill(salt, (byte) 0);
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
            if (pbeKeySpec.getIterationCount() < FIPS_MIN_ITERATIONS) {
                throw new InvalidKeySpecException(
                    "PBKDF2 iteration count must be at least " + FIPS_MIN_ITERATIONS
                    + " (FIPS SP 800-132)");
            }
            int keyLengthBytes = resolveKeyLengthBytes(pbeKeySpec.getKeyLength());
            char[] password = pbeKeySpec.getPassword();
            PBKDF2SecretKey secretKey = new PBKDF2SecretKey(password,
                                    pbeKeySpec.getSalt(), pbeKeySpec.getIterationCount());
            byte[] passwordBytes = encodePassword(password);
            byte[] secretBytes;
            try {
                secretBytes = generateSecret0(passwordBytes, pbeKeySpec.getSalt(),
                                                pbeKeySpec.getIterationCount(), keyLengthBytes);
            } finally {
                Arrays.fill(passwordBytes, (byte) 0);
                Arrays.fill(password, '\0');
            }
            if (secretBytes == null) {
                throw new InvalidKeySpecException("PBKDF2 derivation failed");
            }
            try {
                secretKey.setEncoded(secretBytes);
            } finally {
                Arrays.fill(secretBytes, (byte) 0);
            }
            return secretKey;
        } else {
            throw new InvalidKeySpecException("Invalid KeySpec type, should be PBEKeySpec");
        }
    }

    private static int resolveKeyLengthBytes(int keyLengthBits) throws InvalidKeySpecException {
        if (keyLengthBits == 0) {
            return DEFAULT_KEY_LENGTH_BYTES;
        }
        if (keyLengthBits < 0) {
            throw new InvalidKeySpecException("Negative key length: " + keyLengthBits);
        }
        int bytes = (keyLengthBits + 7) / 8;
        if (bytes > MAX_KEY_LENGTH_BYTES) {
            throw new InvalidKeySpecException(
                "Requested key length " + keyLengthBits + " bits exceeds the maximum supported "
                + (MAX_KEY_LENGTH_BYTES * 8) + " bits");
        }
        return bytes;
    }

    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException {
        // TODO: this is quite half-hearted :-/
        if (keySpec.isAssignableFrom(PBEKeySpec.class) && key instanceof PBEKey pbeKey) {
            return new PBEKeySpec(pbeKey.getPassword(), pbeKey.getSalt(), pbeKey.getIterationCount());
        }
        throw new InvalidKeySpecException("Given key is not representable by " + keySpec);
    }

    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key must not be null");
        }
        if (key instanceof PBKDF2SecretKey) {
            return key;
        }
        if (!(key instanceof PBEKey pbeKey)) {
            throw new InvalidKeyException("A key of type PBEKey is expected, given " + key.getClass());
        }
        String algorithm = pbeKey.getAlgorithm();
        if (algorithm == null || !algorithm.regionMatches(true, 0, "PBKDF2", 0, 6)) {
            throw new InvalidKeyException("Cannot translate non-PBKDF2 key, algorithm: " + algorithm);
        }
        if (!"RAW".equalsIgnoreCase(pbeKey.getFormat())) {
            throw new InvalidKeyException("Cannot translate key with format: " + pbeKey.getFormat());
        }
        if (pbeKey.getIterationCount() < FIPS_MIN_ITERATIONS) {
            throw new InvalidKeyException(
                "PBKDF2 iteration count must be at least " + FIPS_MIN_ITERATIONS
                + " (FIPS SP 800-132)");
        }
        // For RAW keys, getEncoded().length is the key length; preserve it.
        byte[] existing = pbeKey.getEncoded();
        int keyLengthBytes;
        try {
            keyLengthBytes = (existing != null && existing.length > 0)
                ? existing.length : DEFAULT_KEY_LENGTH_BYTES;
        } finally {
            if (existing != null) {
                Arrays.fill(existing, (byte) 0);
            }
        }
        if (keyLengthBytes > MAX_KEY_LENGTH_BYTES) {
            throw new InvalidKeyException(
                "Key length " + (keyLengthBytes * 8) + " bits exceeds the maximum supported "
                + (MAX_KEY_LENGTH_BYTES * 8) + " bits");
        }
        char[] password = pbeKey.getPassword();
        PBKDF2SecretKey secretKey = new PBKDF2SecretKey(password, pbeKey.getSalt(),
                                                        pbeKey.getIterationCount());
        byte[] passwordBytes = encodePassword(password);
        byte[] secretBytes;
        try {
            secretBytes = generateSecret0(passwordBytes, pbeKey.getSalt(),
                                             pbeKey.getIterationCount(), keyLengthBytes);
        } finally {
            Arrays.fill(passwordBytes, (byte) 0);
            Arrays.fill(password, '\0');
        }
        if (secretBytes == null) {
            throw new InvalidKeyException("PBKDF2 derivation failed");
        }
        try {
            secretKey.setEncoded(secretBytes);
        } finally {
            Arrays.fill(secretBytes, (byte) 0);
        }
        return secretKey;
    }

    // UTF-8 encode the password for portability
    private static byte[] encodePassword(char[] password) {
        ByteBuffer bb = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
        byte[] bytes = new byte[bb.remaining()];
        bb.get(bytes);
        if (bb.hasArray()) {
            Arrays.fill(bb.array(), (byte) 0);
        }
        return bytes;
    }

    private native byte[] generateSecret0(byte[] password, byte[] salt, int iterationCount, int keyLength);
    private static native int getMaxKeyLengthBytes0();
}
