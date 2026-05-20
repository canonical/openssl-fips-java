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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

public class KeyPairGeneratorSpecTest {

    @BeforeClass
    public static void addProvider() {
        Security.addProvider(new OpenSSLFIPSProvider());
    }

    private static KeyPairGenerator ec() throws Exception {
        return KeyPairGenerator.getInstance("EC", "OpenSSLFIPSProvider");
    }

    private static KeyPairGenerator dh() throws Exception {
        return KeyPairGenerator.getInstance("DH", "OpenSSLFIPSProvider");
    }

    private static void assertCurveAcceptedAndGenerates(String curveName) throws Exception {
        KeyPairGenerator kpg = ec();
        kpg.initialize(new ECGenParameterSpec(curveName));
        KeyPair kp = kpg.generateKeyPair();
        assertNotNull("Null KeyPair for " + curveName, kp);
        assertNotNull("Null private key for " + curveName, kp.getPrivate());
        assertNotNull("Null public key for " + curveName, kp.getPublic());
    }

    @Test
    public void ecAcceptsCanonicalOpenSSLName_P256() throws Exception {
        assertCurveAcceptedAndGenerates("prime256v1");
    }

    @Test
    public void ecAcceptsSecName_P256() throws Exception {
        assertCurveAcceptedAndGenerates("secp256r1");
    }

    @Test
    public void ecAcceptsPName_P256() throws Exception {
        assertCurveAcceptedAndGenerates("P-256");
    }

    @Test
    public void ecAcceptsNistName_P256() throws Exception {
        assertCurveAcceptedAndGenerates("NIST P-256");
    }

    @Test
    public void ecAcceptsSecName_P384() throws Exception {
        assertCurveAcceptedAndGenerates("secp384r1");
    }

    @Test
    public void ecAcceptsPName_P384() throws Exception {
        assertCurveAcceptedAndGenerates("P-384");
    }

    @Test
    public void ecAcceptsNistName_P384() throws Exception {
        assertCurveAcceptedAndGenerates("NIST P-384");
    }

    @Test
    public void ecAcceptsSecName_P521() throws Exception {
        assertCurveAcceptedAndGenerates("secp521r1");
    }

    @Test
    public void ecAcceptsPName_P521() throws Exception {
        assertCurveAcceptedAndGenerates("P-521");
    }

    @Test
    public void ecAcceptsNistName_P521() throws Exception {
        assertCurveAcceptedAndGenerates("NIST P-521");
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void ecRejectsUnsupportedCurve() throws Exception {
        ec().initialize(new ECGenParameterSpec("secp192r1"));
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void ecRejectsNonECGenParameterSpec() throws Exception {
        ec().initialize(new IvParameterSpec(new byte[16]));
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void dhRejectsDHParameterSpec() throws Exception {
        BigInteger p = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
            + "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
            + "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
            + "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
            + "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
            + "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16);
        BigInteger g = BigInteger.valueOf(2);
        dh().initialize(new DHParameterSpec(p, g));
    }

    @Test
    public void ecKeysizeStillWorks() throws Exception {
        KeyPairGenerator kpg = ec();
        kpg.initialize(384);
        assertNotNull(kpg.generateKeyPair());
    }

    @Test
    public void dhKeysizeStillWorks() throws Exception {
        KeyPairGenerator kpg = dh();
        kpg.initialize(2048);
        assertNotNull(kpg.generateKeyPair());
    }

    @Test
    public void ecKeysizeUnsupportedThrows() {
        try {
            ec().initialize(123);
            fail("expected IllegalArgumentException for unsupported EC keysize");
        } catch (IllegalArgumentException expected) {
        } catch (Exception e) {
            fail("expected IllegalArgumentException, got " + e.getClass().getName());
        }
    }

    @Test
    public void dhKeysizeUnsupportedThrows() {
        try {
            dh().initialize(1024);
            fail("expected IllegalArgumentException for unsupported DH keysize");
        } catch (IllegalArgumentException expected) {
        } catch (Exception e) {
            fail("expected IllegalArgumentException, got " + e.getClass().getName());
        }
    }
}
