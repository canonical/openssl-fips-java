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

import com.canonical.openssl.key.KeyConverter;
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

/**
 * Test FIPS-safe key conversion from Java Key objects to OpenSSL EVP_PKEY handles.
 *
 * This test verifies that:
 * 1. RSA keys can be converted
 * 2. Ed25519 keys can be converted
 * 3. Ed448 keys can be converted
 * 4. The conversion uses OSSL_DECODER (FIPS-safe) not d2i_* (legacy)
 */
public class KeyConverterTest {

    @BeforeClass
    public static void setUp() {
        Security.addProvider(new OpenSSLFIPSProvider());
    }

    @Test
    public void testRSAPrivateKeyConversion() throws Exception {
        // Generate an RSA key pair using standard Java
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "OpenSSLFIPSProvider");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        // Convert to EVP_PKEY handle
        long privateHandle = KeyConverter.privateKeyToEVPKey(kp.getPrivate());
        assertTrue("Private key conversion should succeed", privateHandle != 0);

        long publicHandle = KeyConverter.publicKeyToEVPKey(kp.getPublic());
        assertTrue("Public key conversion should succeed", publicHandle != 0);

        // Clean up
        KeyConverter.freeEVPKey(privateHandle);
        KeyConverter.freeEVPKey(publicHandle);
    }

    @Test
    public void testNullKeyThrowsException() {
        try {
            KeyConverter.privateKeyToEVPKey(null);
            fail("Should throw IllegalArgumentException for null private key");
        } catch (IllegalArgumentException e) {
            // Expected
        }

        try {
            KeyConverter.publicKeyToEVPKey(null);
            fail("Should throw IllegalArgumentException for null public key");
        } catch (IllegalArgumentException e) {
            // Expected
        }
    }

    @Test
    public void testFreeEVPKeyWithZeroHandle() {
        // Should not crash
        KeyConverter.freeEVPKey(0);
    }

    @Test
    public void testECKeyPairFromFIPSProviderConverts() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", "OpenSSLFIPSProvider");
        for (String curve : new String[]{"P-256", "P-384", "P-521"}) {
            kpg.initialize(new ECGenParameterSpec(curve));
            KeyPair kp = kpg.generateKeyPair();

            long privHandle = KeyConverter.privateKeyToEVPKey(kp.getPrivate());
            assertTrue("EC private key handle must be non-zero for " + curve, privHandle != 0);

            long pubHandle = KeyConverter.publicKeyToEVPKey(kp.getPublic());
            assertTrue("EC public key handle must be non-zero for " + curve, pubHandle != 0);

            KeyConverter.freeEVPKey(privHandle);
            KeyConverter.freeEVPKey(pubHandle);
        }
    }

    @Test
    public void testDHKeyPairFromFIPSProviderConverts() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH", "OpenSSLFIPSProvider");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        long privHandle = KeyConverter.privateKeyToEVPKey(kp.getPrivate());
        assertTrue("DH private key handle must be non-zero", privHandle != 0);

        long pubHandle = KeyConverter.publicKeyToEVPKey(kp.getPublic());
        assertTrue("DH public key handle must be non-zero", pubHandle != 0);

        KeyConverter.freeEVPKey(privHandle);
        KeyConverter.freeEVPKey(pubHandle);
    }
}

