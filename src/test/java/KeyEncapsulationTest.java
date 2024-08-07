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
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Arrays;
import java.security.KeyPairGenerator;
import javax.crypto.KEM;
import javax.crypto.KEM.Encapsulated;
import javax.crypto.KEM.Encapsulator;
import javax.crypto.KEM.Decapsulator;
import javax.crypto.SecretKey;
import java.security.Security;
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.assertTrue;

public class KeyEncapsulationTest {
    @BeforeClass
    public static void addProvider() {
        Security.addProvider(new OpenSSLFIPSProvider());
    }

    @Test
    public void testKEMRSA() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);

        // Alice creates a key pair and shares the public key with Bob
        KeyPair aliceKeys = kpg.generateKeyPair();
        PublicKey alicePublicKey = aliceKeys.getPublic();
        PrivateKey alicePrivateKey = aliceKeys.getPrivate();

        // Bob generates a shared secret and wraps it using Alice's public key
        KEM bobKem = KEM.getInstance("RSA", "OpenSSLFIPSProvider");
        Encapsulator encapsulator = bobKem.newEncapsulator(alicePublicKey, null, null);
        int secretSize = encapsulator.secretSize();
        KEM.Encapsulated encapsulated = encapsulator.encapsulate(0, secretSize, "AES");
        SecretKey bobSecret = encapsulated.key();

        // Bob sends the encapsulated secret to Alice
        // Alice uses her RSA private key to unwrap the shared secret
        KEM aliceKem = KEM.getInstance("RSA", "OpenSSLFIPSProvider");
        Decapsulator decapsulator = aliceKem.newDecapsulator(alicePrivateKey, null);
        byte[] encapsulationBytes = encapsulated.encapsulation();
        SecretKey aliceSecret = decapsulator.decapsulate(encapsulationBytes, 0, encapsulationBytes.length, "AES");

        assertTrue("Key Encapsulation with RSA test failed", aliceSecret.equals(bobSecret));
    }
}
