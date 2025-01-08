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
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;
import java.security.KeyPair;
import java.util.Arrays;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;
import javax.crypto.KeyAgreement;
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.assertArrayEquals;

public class KeyAgreementTest {

    @BeforeClass
    public static void addProvider() {
        Security.addProvider(new OpenSSLFIPSProvider());
    }

    private void runTest(KeyPairGenerator kpg, String algo) throws Exception {
        KeyAgreement aliceAgreement = KeyAgreement.getInstance(algo, "OpenSSLFIPSProvider");
        KeyAgreement bobAgreement = KeyAgreement.getInstance(algo, "OpenSSLFIPSProvider");

        for (int i = 0; i < 2; i++) {
            KeyPair aliceKp = kpg.generateKeyPair();
            KeyPair bobKp = kpg.generateKeyPair();
            aliceAgreement.init(aliceKp.getPrivate());
            aliceAgreement.doPhase(bobKp.getPublic(), true);
            bobAgreement.init(bobKp.getPrivate());
            bobAgreement.doPhase(aliceKp.getPublic(), true);
            byte[] aliceSecret = aliceAgreement.generateSecret();
            byte[] bobSecret = bobAgreement.generateSecret();
            assertArrayEquals("Key Agreement test for " + algo +  " failed", aliceSecret, bobSecret);

            // make sure generateSecret() resets the KeyAgreement object
            // and can be reused for another agreement
        }
    }

    @Test
    public void testDH() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
        runTest(kpg, "DH");
    }

    @Test
    public void testECDH() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        runTest(kpg, "ECDH");
    }
}
