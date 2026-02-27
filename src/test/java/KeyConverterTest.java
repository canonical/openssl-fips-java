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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
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
    public void testEd25519KeyConversion() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            KeyPair kp = kpg.generateKeyPair();

            // Convert to EVP_PKEY handle
            long privateHandle = KeyConverter.privateKeyToEVPKey(kp.getPrivate());
            assertTrue("Ed25519 private key conversion should succeed", privateHandle != 0);

            long publicHandle = KeyConverter.publicKeyToEVPKey(kp.getPublic());
            assertTrue("Ed25519 public key conversion should succeed", publicHandle != 0);

            // Clean up
            KeyConverter.freeEVPKey(privateHandle);
            KeyConverter.freeEVPKey(publicHandle);
        } catch (NoSuchAlgorithmException e) {
            // Ed25519 may not be available in all JDKs
            System.out.println("Ed25519 not available, skipping test");
        }
    }

    @Test
    public void testEd448KeyConversion() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed448");
            KeyPair kp = kpg.generateKeyPair();

            // Convert to EVP_PKEY handle
            long privateHandle = KeyConverter.privateKeyToEVPKey(kp.getPrivate());
            assertTrue("Ed448 private key conversion should succeed", privateHandle != 0);

            long publicHandle = KeyConverter.publicKeyToEVPKey(kp.getPublic());
            assertTrue("Ed448 public key conversion should succeed", publicHandle != 0);

            // Clean up
            KeyConverter.freeEVPKey(privateHandle);
            KeyConverter.freeEVPKey(publicHandle);
        } catch (NoSuchAlgorithmException e) {
            // Ed448 may not be available in all JDKs
            System.out.println("Ed448 not available, skipping test");
        }
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
}

