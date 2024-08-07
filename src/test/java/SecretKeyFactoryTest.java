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
import java.util.Arrays;
import java.security.spec.KeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.InvalidKeyException;
import java.security.Security;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotEquals;

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
    }

    @BeforeClass
    public static void addProvider() throws Exception {
        Security.addProvider(new OpenSSLFIPSProvider());
    }
}
