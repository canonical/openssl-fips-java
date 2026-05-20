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

import com.canonical.openssl.util.NativeLibraryLoader;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

abstract public class OpenSSLKeyPairGenerator extends KeyPairGeneratorSpi {
    static {
        NativeLibraryLoader.load();
    }

    private String group;

    protected OpenSSLKeyPairGenerator(String defaultGroup) {
        this.group = defaultGroup;
    }

    /**
     * The {@code random} argument is ignored. Key generation uses OpenSSL's
     * FIPS-validated DRBG; a caller-supplied {@link SecureRandom} cannot be
     * substituted without violating the FIPS boundary.
     */
    @Override
    public void initialize(int keysize, SecureRandom random) {
        String mapped = mapKeysizeToGroup(keysize);
        if (mapped == null) {
            throw new IllegalArgumentException(
                "Unsupported key size " + keysize + " for " + getAlgorithmName());
        }
        this.group = mapped;
    }

    /**
     * Accepts only specs that resolve to a FIPS-approved named group. The
     * {@code random} argument is ignored; see {@link #initialize(int, SecureRandom)}.
     */
    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random)
            throws InvalidAlgorithmParameterException {
        String mapped = groupFromSpec(params);
        if (mapped == null) {
            throw new InvalidAlgorithmParameterException(
                "Unsupported AlgorithmParameterSpec for " + getAlgorithmName()
                + "; use initialize(keysize) or a FIPS-approved named-group spec");
        }
        this.group = mapped;
    }

    @Override
    public KeyPair generateKeyPair() {
        byte[][] encoded = generateKeyPair0(getAlgorithmName(), group);
        if (encoded == null || encoded.length != 2
                || encoded[0] == null || encoded[1] == null) {
            throw new ProviderException(
                "Provider failed to generate " + getAlgorithmName() + " key pair");
        }
        PrivateKey priv = new EncodedPrivateKey(getAlgorithmName(), encoded[0]);
        Arrays.fill(encoded[0], (byte) 0);
        PublicKey  pub  = new EncodedPublicKey(getAlgorithmName(),  encoded[1]);
        return new KeyPair(pub, priv);
    }

    protected abstract String getAlgorithmName();

    /** Returns the named group for the given keysize, or null if unsupported. */
    protected abstract String mapKeysizeToGroup(int keysize);

    /** Returns the named group for the given spec, or null if unsupported. */
    protected String groupFromSpec(AlgorithmParameterSpec params) {
        return null;
    }

    private static native byte[][] generateKeyPair0(String algorithm, String group);
}
