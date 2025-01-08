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
import java.lang.FunctionalInterface;
import java.util.Arrays;
import java.util.function.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.nio.ByteBuffer;
import java.security.Security;
import com.canonical.openssl.provider.OpenSSLFIPSProvider;
import javax.crypto.Mac;
import java.security.SecureRandom;

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;

public class MacTest {

    private byte[] key = new byte[] {
        (byte)0x6c, (byte)0xde, (byte)0x14, (byte)0xf5, (byte)0xd5, (byte)0x2a, (byte)0x4a, (byte)0xdf,
        (byte)0x12, (byte)0x39, (byte)0x1e, (byte)0xbf, (byte)0x36, (byte)0xf9, (byte)0x6a, (byte)0x46,
        (byte)0x48, (byte)0xd0, (byte)0xb6, (byte)0x51, (byte)0x89, (byte)0xfc, (byte)0x24, (byte)0x85,
        (byte)0xa8, (byte)0x8d, (byte)0xdf, (byte)0x7e, (byte)0x80, (byte)0x14, (byte)0xc8, (byte)0xce,
        (byte)0x38, (byte)0xb5, (byte)0xb1, (byte)0xe0, (byte)0x82, (byte)0x2c, (byte)0x70, (byte)0xa4,
        (byte)0xc0, (byte)0x8e, (byte)0x5e, (byte)0xf9, (byte)0x93, (byte)0x9f, (byte)0xcf, (byte)0xf7,
        (byte)0x32, (byte)0x4d, (byte)0x0c, (byte)0xbd, (byte)0x31, (byte)0x12, (byte)0x0f, (byte)0x9a,
        (byte)0x15, (byte)0xee, (byte)0x82, (byte)0xdb, (byte)0x8d, (byte)0x29, (byte)0x54, (byte)0x14
    };

    private byte[] input = """
       From that time on, the world was hers for the reading.
       She would never be lonely again, never miss the lack of intimate friends.
       Books became her friends and there was one for every mood.""".getBytes();

    private byte[] input1 = """
       From that time on, the world was hers for the reading.
       She would never be lonely again, never miss the lack of intimate friends.
       Books became her friends and there was one for every mood""".getBytes();

    @FunctionalInterface
    interface TriFunction<A, B, C, D> {
        D apply(A op1, B op2, C op3);
    }

    private BiFunction<Mac, byte[], byte[]> macCompute1 = (mac, input) -> {
        try {
            mac.update(ByteBuffer.wrap(input));
            mac.update(ByteBuffer.wrap(input));
            byte[] macBytes = new byte[mac.getMacLength()];
            mac.doFinal(macBytes, 0);
            return macBytes;
        } catch (Exception ike) {
            return null;
        }
    };

    private BiFunction<Mac, byte[], byte[]> macCompute2 = (mac, input) -> {
        try {
            mac.update(ByteBuffer.wrap(input));
            return mac.doFinal(input);
        } catch (Exception ike) {
            return null;
        }
    };

    private BiFunction<Mac, byte[], byte[]> macCompute3 = (mac, input) -> {
        try {
            mac.update(ByteBuffer.wrap(input));
            mac.update(ByteBuffer.wrap(input));
            return mac.doFinal();
        } catch (Exception ike) {
            return null;
        }
    };

    private BiFunction<Mac, byte[], byte[]> macCompute4 = (mac, input) -> {
        try {
            mac.update(input, 0, 10240);
            mac.update(input, 0, 10240);
            byte[] macBytes = new byte[mac.getMacLength()];
            mac.doFinal(macBytes, 0);
            return macBytes;
        } catch (Exception ike) {
            return null;
        }
    };


    private BiFunction<Mac, byte[], byte[]> macCompute5 = (mac, input) -> {
        try {
            mac.update(input, 0, 10240);
            return mac.doFinal(input);
        } catch (Exception ike) {
            return null;
        }
    };

    private BiFunction<Mac, byte[], byte[]> macCompute6 = (mac, input) -> {
        try {
            mac.update(input, 0, 10240);
            mac.update(input, 0, 10240);
            return mac.doFinal();
        } catch (Exception ike) {
            return null;
        }
    };

    private BiFunction<Mac, byte[], byte[]> macCompute7 = (mac, input) -> {
        try {
            mac.update(input);
            mac.update(input);
            byte[] macBytes = new byte[mac.getMacLength()];
            mac.doFinal(macBytes, 0);
            return macBytes;
        } catch (Exception ike) {
            return null;
        }
    };

    private BiFunction<Mac, byte[], byte[]> macCompute8 = (mac, input) -> {
        try {
            mac.update(input);
            return mac.doFinal(input);
        } catch (Exception ike) {
            return null;
        }
    };

    private BiFunction<Mac, byte[], byte[]> macCompute9 = (mac, input) -> {
        try {
            mac.update(input);
            mac.update(input);
            return mac.doFinal();
        } catch (Exception ike) {
            return null;
        }
    };

    private BiFunction<Mac, byte[], byte[]> macCompute10 = (mac, input) -> {
        try {
            for (byte b : input) {
                mac.update(b);
            }
            for (byte b : input) {
               mac.update(b);
            }
            int len = mac.getMacLength();
            byte[] macBytes = new byte[len];
            mac.doFinal(macBytes, 0);
            return macBytes;
        } catch (Exception ike) {
            return null;
        }
    };

    private BiFunction<Mac, byte[], byte[]> macCompute11 = (mac, input) -> {
        try {
            for (byte b : input) {
                mac.update(b);
            }
            for (byte b : input) {
                mac.update(b);
            }
            return mac.doFinal();
        } catch (Exception ike) {
            return null;
        }
    };

    private BiFunction<Mac, byte[], byte[]> macCompute12 = (mac, input) -> {
        try {
            for (byte b : input) {
                mac.update(b);
            }
            return mac.doFinal(input);
        } catch (Exception ike) {
            return null;
        }
    };

    private TriFunction<Mac, SecretKeySpec, byte[], byte[]> macCompute = (mac, keySpec, input) -> {
        try {
            mac.init(keySpec, null);
            mac.update(input, 0, input.length);
            return mac.doFinal();
        } catch (Exception ike) {
            return null;
        }
    };

    private void runTest(String name, SecretKeySpec keySpec, String macName) throws Exception {
        Mac mac1 = Mac.getInstance(macName, "OpenSSLFIPSProvider");
        Mac mac2 = Mac.getInstance(macName, "OpenSSLFIPSProvider");
        Mac mac3 = Mac.getInstance(macName, "OpenSSLFIPSProvider");
        byte[] output1 = macCompute.apply(mac1, keySpec, input);
        byte[] output2 = macCompute.apply(mac2, keySpec, input);
        byte[] output3 = macCompute.apply(mac3, keySpec, input1);
        assertArrayEquals("Test for mac " + name + " failed.", output1, output2);
        assertFalse("Test for mac " + name  + " failed.", Arrays.equals(output2, output3));
    }

    private void runLargeTest(String name, SecretKeySpec keySpec, String macName) throws Exception {
        SecureRandom hmac = SecureRandom.getInstance("HashSHA512","OpenSSLFIPSProvider");
        byte[] input = new byte[10240];
        hmac.nextBytes(input);
        byte[][] outputs = new byte[12][];

        Mac mac = Mac.getInstance(macName, "OpenSSLFIPSProvider");
        mac.init(keySpec, null);

        outputs[0] = macCompute1.apply(mac, input);
        mac.reset();

        outputs[1] = macCompute2.apply(mac, input);
        mac.reset();

        outputs[2] = macCompute3.apply(mac, input);
        mac.reset();

        outputs[3] = macCompute4.apply(mac, input);
        mac.reset();

        outputs[4] = macCompute5.apply(mac, input);
        mac.reset();

        outputs[5] = macCompute6.apply(mac, input);
        mac.reset();

        outputs[6] = macCompute7.apply(mac, input);
        mac.reset();

        outputs[7] = macCompute8.apply(mac, input);
        mac.reset();

        outputs[8] = macCompute9.apply(mac, input);
        mac.reset();

        outputs[9] = macCompute10.apply(mac, input);
        mac.reset();

        outputs[10] = macCompute11.apply(mac, input);
        mac.reset();

        outputs[11] = macCompute12.apply(mac, input);

        assertAllElementsOfArrayAreEqual(outputs, name);
    }

    private void assertAllElementsOfArrayAreEqual(byte[][] arrays, String name) {
        for(int i = 0; i < arrays.length-1; i++) {
            assertArrayEquals("Test for mac " + name + " failed (" + i + ", " + (i + 1) + ").", arrays[i], arrays[i+1]);
        }
    }

    @Test
    public void testCMAC_AES() throws Exception {
        runTest("CMAC[Cipher: AES-256-CBC]",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 32), "AES"),
            "CMACwithAes256CBC");

    }

    @Test
    public void testLargeCMAC_AES() throws Exception {
        runLargeTest("CMAC[Cipher: AES-256-CBC]",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 32), "AES"),
            "CMACwithAes256CBC");

    }

    @Test
    public void testGMAC_AES() throws Exception {
        runTest("GMAC[Cipher: AES-128-GCM]",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 16), "AES"),
            "GMACWithAes128GCM");
    }

    @Test
    public void testLargeGMAC_AES() throws Exception {
        runLargeTest("GMAC[Cipher: AES-128-GCM]",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 16), "AES"),
            "GMACWithAes128GCM");
    }


    @Test
    public void testHMAC_SHA1() throws Exception {
        runTest("HMAC[Digest: SHA1]",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 64), "HMAC"),
            "HMACwithSHA1");
    }

    @Test
    public void testLargeHMAC_SHA1() throws Exception {
        runLargeTest("HMAC[Digest: SHA1]",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 64), "HMAC"),
            "HMACwithSHA1");
    }

    @Test
    public void testHMAC_SHA3_512() throws Exception {
        runTest("HMAC[Digest: SHA3-512]",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 64), "HMAC"),
            "HMACwithSHA3_512");
    }

    @Test
    public void testLargeHMAC_SHA3_512() throws Exception {
        runLargeTest("HMAC[Digest: SHA3-512]",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 64), "HMAC"),
            "HMACwithSHA3_512");
    }

    @Test
    public void testKMAC_128() throws Exception {
        runTest("KMAC-128",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 16), "KMAC-128"),
            "KMAC128");
    }

    @Test
    public void testLargeKMAC_128() throws Exception {
        runLargeTest("KMAC-128",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 16), "KMAC-128"),
            "KMAC128");
    }

    @Test
    public void testKMAC_256() throws Exception {
        runTest("KMAC-256",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 32), "KMAC-256"),
            "KMAC256");
    }

    @Test
    public void testLargeKMAC_256() throws Exception {
        runLargeTest("KMAC-256",
            new SecretKeySpec(Arrays.copyOfRange(key, 0, 32), "KMAC-256"),
            "KMAC256");
    }

    @BeforeClass 
    public static void addProvider() throws Exception {
        Security.addProvider(new OpenSSLFIPSProvider());
    }
}
