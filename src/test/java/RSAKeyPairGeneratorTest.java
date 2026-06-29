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
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import com.canonical.openssl.key.KeyConverter;
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class RSAKeyPairGeneratorTest {

    @BeforeClass
    public static void addProvider() {
        Security.addProvider(new OpenSSLFIPSProvider());
    }

    private static KeyPairGenerator rsa() throws Exception {
        return KeyPairGenerator.getInstance("RSA", "OpenSSLFIPSProvider");
    }

    // Parse the generated X.509 public key with the JDK to read back the actual
    // modulus size and public exponent the FIPS module produced.
    private static RSAPublicKey parsePublic(KeyPair kp) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) kf.generatePublic(
            new X509EncodedKeySpec(kp.getPublic().getEncoded()));
    }

    private static void assertGeneratesKeyOfSize(KeyPair kp, int expectedBits) throws Exception {
        assertNotNull("Null KeyPair", kp);
        assertNotNull("Null private key", kp.getPrivate());
        assertNotNull("Null public key", kp.getPublic());
        assertEquals("RSA", kp.getPublic().getAlgorithm());
        assertEquals("RSA", kp.getPrivate().getAlgorithm());
        assertEquals("X.509", kp.getPublic().getFormat());
        assertEquals("PKCS#8", kp.getPrivate().getFormat());

        RSAPublicKey pub = parsePublic(kp);
        assertEquals("Unexpected modulus size", expectedBits, pub.getModulus().bitLength());
        assertEquals("Unexpected public exponent",
            RSAKeyGenParameterSpec.F4, pub.getPublicExponent());
    }

    @Test
    public void defaultGeneratesApproved2048() throws Exception {
        // No initialize() call: must default to a FIPS-approved 2048-bit key.
        assertGeneratesKeyOfSize(rsa().generateKeyPair(), 2048);
    }

    @Test
    public void keysizeInit2048() throws Exception {
        KeyPairGenerator kpg = rsa();
        kpg.initialize(2048);
        assertGeneratesKeyOfSize(kpg.generateKeyPair(), 2048);
    }

    @Test
    public void keysizeInit3072() throws Exception {
        KeyPairGenerator kpg = rsa();
        kpg.initialize(3072);
        assertGeneratesKeyOfSize(kpg.generateKeyPair(), 3072);
    }

    @Test
    public void specInit2048WithF4() throws Exception {
        KeyPairGenerator kpg = rsa();
        kpg.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4));
        assertGeneratesKeyOfSize(kpg.generateKeyPair(), 2048);
    }

    @Test
    public void generatedKeysAreFipsDecodable() throws Exception {
        // The generated DER must round-trip back into the OpenSSL FIPS module,
        // proving the keys are usable on the FIPS crypto path (not just by the JDK).
        KeyPair kp = rsa().generateKeyPair();

        long pubHandle = KeyConverter.publicKeyToEVPKey(kp.getPublic());
        assertTrue("FIPS decode of public key failed", pubHandle != 0);
        KeyConverter.freeEVPKey(pubHandle);

        long privHandle = KeyConverter.privateKeyToEVPKey(kp.getPrivate());
        assertTrue("FIPS decode of private key failed", privHandle != 0);
        KeyConverter.freeEVPKey(privHandle);
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsUnapprovedKeysize1024() throws Exception {
        rsa().initialize(1024);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void rejectsSpecKeysize1024() throws Exception {
        rsa().initialize(new RSAKeyGenParameterSpec(1024, RSAKeyGenParameterSpec.F4));
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void rejectsTooSmallExponent() throws Exception {
        // e = 3 is below the FIPS 186-5 lower bound of 65537.
        rsa().initialize(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3)));
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void rejectsEvenExponent() throws Exception {
        // 65538 is in range but even; a valid RSA exponent must be odd.
        rsa().initialize(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(65538)));
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void rejectsNonRSASpec() throws Exception {
        rsa().initialize(new ECGenParameterSpec("prime256v1"));
    }

    @Test
    public void unapprovedKeysizeThrowsIllegalArgument() {
        try {
            rsa().initialize(2047);
            fail("expected IllegalArgumentException for unsupported RSA keysize");
        } catch (IllegalArgumentException expected) {
            // ok
        } catch (Exception e) {
            fail("expected IllegalArgumentException, got " + e.getClass().getName());
        }
    }
}
