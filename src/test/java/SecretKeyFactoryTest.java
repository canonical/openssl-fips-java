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
import java.security.InvalidKeyException;
import java.security.spec.KeySpec;
import java.security.Security;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class SecretKeyFactoryTest {

    @Test
    public void testPBKDF2() throws Exception {
        String password = "Zaq12wsXCde34rfV";
        String salt = "NaClCommonSaltRockSaltSeaSalt";
        int iterationCount = 120000;

        char[] passwordChars = new char[16]; 
        password.getChars(0, 16, passwordChars, 0);
        PBEKeySpec keySpec = new PBEKeySpec(passwordChars, salt.getBytes(), iterationCount);

        SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2", "OpenSSLFIPSProvider");
        SecretKey sk1 = pbkdf.generateSecret(keySpec);
        SecretKey sk2 = pbkdf.translateKey(sk1);
        assertNotEquals("SecretKey is of length 0", sk1.getEncoded().length, 0);
        assertArrayEquals("Invalid secret key", sk1.getEncoded(), sk2.getEncoded());

        KeySpec spec = pbkdf.getKeySpec(sk2, PBEKeySpec.class);
        assertTrue("Returned KeySpec is not of the expected type", spec instanceof PBEKeySpec);
        assertEquals("Returned KeySpec does not match original KeySpec", ((PBEKeySpec)spec).getIterationCount(), 120000);
        assertArrayEquals("Returned KeySpec does not match original KeySpec", ((PBEKeySpec)spec).getPassword(), password.toCharArray());
        assertArrayEquals("Returned KeySpec does not match original KeySpec", ((PBEKeySpec)spec).getSalt(), salt.getBytes());
    }

    @Test
    public void testTranslateForeignPBEKeyIgnoresEncodedLength() throws Exception {
        SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2", "OpenSSLFIPSProvider");

        final char[] password = "Zaq12wsXCde34rfV".toCharArray();
        final byte[] salt = "NaClCommonSaltRockSaltSeaSalt".getBytes();
        final byte[] foreignEncoded = new byte[17];

        PBEKey foreign = new PBEKey() {
            public char[] getPassword() { return password.clone(); }
            public byte[] getSalt() { return salt.clone(); }
            public int getIterationCount() { return 120000; }
            public byte[] getEncoded() { return foreignEncoded.clone(); }
            public String getAlgorithm() { return "PBEWithMD5AndDES"; }
            public String getFormat() { return "RAW"; }
        };

        SecretKey translated;
        try {
            translated = pbkdf.translateKey(foreign);
        } catch (InvalidKeyException expected) {
            return;
        }
        assertNotEquals("Translated key length must not be inherited from a foreign encoded form",
                        foreignEncoded.length, translated.getEncoded().length);
    }

    @Test
    public void testPBKDF2ExplicitKeyLength() throws Exception {
        char[] password = "Zaq12wsXCde34rfV".toCharArray();
        byte[] salt = "NaClCommonSaltRockSaltSeaSalt".getBytes();
        int iterationCount = 120000;

        SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2", "OpenSSLFIPSProvider");

        for (int keyLengthBits : new int[]{128, 256, 512}) {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterationCount, keyLengthBits);
            SecretKey key = pbkdf.generateSecret(spec);
            assertEquals("Key length mismatch for " + keyLengthBits + " bits",
                    keyLengthBits / 8, key.getEncoded().length);
        }
    }

    @Test
    public void testPBKDF2DifferentKeyLengthsProduceDifferentKeys() throws Exception {
        char[] password = "Zaq12wsXCde34rfV".toCharArray();
        byte[] salt = "NaClCommonSaltRockSaltSeaSalt".getBytes();
        int iterationCount = 120000;

        SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2", "OpenSSLFIPSProvider");

        SecretKey key128 = pbkdf.generateSecret(new PBEKeySpec(password, salt, iterationCount, 128));
        SecretKey key256 = pbkdf.generateSecret(new PBEKeySpec(password, salt, iterationCount, 256));

        // The 128-bit key must be a prefix of the 256-bit key (same PRF, same inputs).
        byte[] k128 = key128.getEncoded();
        byte[] k256 = key256.getEncoded();
        byte[] k256prefix = new byte[16];
        System.arraycopy(k256, 0, k256prefix, 0, 16);
        assertArrayEquals("Shorter key must be a prefix of the longer key", k128, k256prefix);
    }

    @Test
    public void testPBKDF2RejectsBelowFIPSMinimumIterations() throws Exception {
        SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2", "OpenSSLFIPSProvider");
        char[] password = "password".toCharArray();
        byte[] salt = "NaClCommonSaltRockSaltSeaSalt".getBytes();

        for (int iterations : new int[]{1, 500, 999}) {
            try {
                pbkdf.generateSecret(new PBEKeySpec(password, salt, iterations));
                fail("Expected InvalidKeySpecException for iteration count " + iterations);
            } catch (java.security.spec.InvalidKeySpecException expected) {
                // correct
            }
        }
    }

    @Test
    public void testPBKDF2AcceptsFIPSMinimumIterations() throws Exception {
        SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2", "OpenSSLFIPSProvider");
        char[] password = "password".toCharArray();
        byte[] salt = "NaClCommonSaltRockSaltSeaSalt".getBytes();

        SecretKey key = pbkdf.generateSecret(new PBEKeySpec(password, salt, 1000));
        assertNotEquals("Key at FIPS minimum iterations must be non-empty", 0, key.getEncoded().length);
    }

    @Test
    public void testTranslateKeyRejectsBelowFIPSMinimumIterations() throws Exception {
        SecretKeyFactory pbkdf = SecretKeyFactory.getInstance("PBKDF2", "OpenSSLFIPSProvider");

        final char[] password = "password".toCharArray();
        final byte[] salt = "NaClCommonSaltRockSaltSeaSalt".getBytes();

        for (int iterations : new int[]{1, 500, 999}) {
            final int it = iterations;
            PBEKey foreign = new PBEKey() {
                public char[] getPassword() { return password.clone(); }
                public byte[] getSalt() { return salt.clone(); }
                public int getIterationCount() { return it; }
                public byte[] getEncoded() { return new byte[64]; }
                public String getAlgorithm() { return "PBKDF2WithHmacSHA512"; }
                public String getFormat() { return "RAW"; }
            };
            try {
                pbkdf.translateKey(foreign);
                fail("Expected InvalidKeyException for iteration count " + iterations);
            } catch (InvalidKeyException expected) {
                // correct
            }
        }
    }

    @BeforeClass
    public static void addProvider() throws Exception {
        Security.addProvider(new OpenSSLFIPSProvider());
    }
}
