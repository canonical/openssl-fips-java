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
package com.canonical.openssl.keypairgenerator;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

/* RSA key generation runs entirely inside OpenSSL's FIPS-validated module: the
 * native generateRSAKeyPair0 builds the key with EVP_PKEY_keygen against the
 * FIPS library context, so the approved DRBG is used and the mandated pairwise
 * consistency self-test runs within the module boundary.
 *
 * Unlike EC/DH this generator is parameterised by modulus size and public
 * exponent rather than a named group, so it overrides initialize() and the
 * generateEncodedKeyPair() hook; the shared key-wrapping/zeroization stays in
 * OpenSSLKeyPairGenerator.generateKeyPair(). The SPI is not thread-safe; the
 * JCA contract does not require it to be.
 */
public final class RSAKeyPairGenerator extends OpenSSLKeyPairGenerator {

    private static final int DEFAULT_KEY_SIZE = 2048;

    // FIPS 186-5 (B.3): the public exponent e must be odd with
    // 2^16 < e < 2^256, i.e. 65537 <= e < 2^256. F4 (65537) is the standard.
    private static final BigInteger MIN_PUBLIC_EXPONENT = BigInteger.valueOf(65537);
    private static final BigInteger MAX_PUBLIC_EXPONENT = BigInteger.ONE.shiftLeft(256);

    private int keysize = DEFAULT_KEY_SIZE;
    private BigInteger publicExponent = RSAKeyGenParameterSpec.F4;

    public RSAKeyPairGenerator() {
        // RSA is not parameterised by a named group.
        super(null);
    }

    @Override
    protected String getAlgorithmName() {
        return "RSA";
    }

    // FIPS 186-5 approves RSA key generation for these modulus sizes only.
    private static boolean isApprovedKeySize(int keysize) {
        return keysize == 2048 || keysize == 3072 || keysize == 4096;
    }

    private static void validatePublicExponent(BigInteger e)
            throws InvalidAlgorithmParameterException {
        if (e == null
                || !e.testBit(0)                            // must be odd
                || e.compareTo(MIN_PUBLIC_EXPONENT) < 0     // >= 65537
                || e.compareTo(MAX_PUBLIC_EXPONENT) >= 0) { // < 2^256
            throw new InvalidAlgorithmParameterException(
                "RSA public exponent must be an odd integer in [65537, 2^256) (FIPS 186-5)");
        }
    }

    /**
     * The {@code random} argument is ignored. Key generation uses OpenSSL's
     * FIPS-validated DRBG; a caller-supplied {@link SecureRandom} cannot be
     * substituted without violating the FIPS boundary.
     */
    @Override
    public void initialize(int keysize, SecureRandom random) {
        if (!isApprovedKeySize(keysize)) {
            throw new IllegalArgumentException(
                "Unsupported RSA key size " + keysize
                + "; FIPS 186-5 approves 2048, 3072 and 4096 bits");
        }
        this.keysize = keysize;
        this.publicExponent = RSAKeyGenParameterSpec.F4;
    }

    /**
     * Accepts an {@link RSAKeyGenParameterSpec} whose key size and public
     * exponent are both FIPS-approved. The {@code random} argument is ignored;
     * see {@link #initialize(int, SecureRandom)}.
     */
    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        if (!(params instanceof RSAKeyGenParameterSpec rsaSpec)) {
            throw new InvalidAlgorithmParameterException(
                "Unsupported AlgorithmParameterSpec for RSA; expected RSAKeyGenParameterSpec");
        }
        if (!isApprovedKeySize(rsaSpec.getKeysize())) {
            throw new InvalidAlgorithmParameterException(
                "Unsupported RSA key size " + rsaSpec.getKeysize()
                + "; FIPS 186-5 approves 2048, 3072 and 4096 bits");
        }
        BigInteger e = rsaSpec.getPublicExponent();
        validatePublicExponent(e);
        this.keysize = rsaSpec.getKeysize();
        this.publicExponent = e;
    }

    @Override
    protected byte[][] generateEncodedKeyPair() {
        // publicExponent.toByteArray() is a big-endian two's-complement encoding;
        // it is positive, so the native side reads it as an unsigned big-endian
        // integer (a leading 0x00 sign byte, if present, is harmless).
        return generateRSAKeyPair0(keysize, publicExponent.toByteArray());
    }

    private static native byte[][] generateRSAKeyPair0(int keysize, byte[] publicExponent);
}
