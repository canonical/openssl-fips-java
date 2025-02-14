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
import javax.crypto.CipherSpi;
import javax.crypto.Cipher;
import java.security.Key;
import java.security.Security;
import java.security.AlgorithmParameters;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import javax.crypto.ShortBufferException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.fail;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class CipherTest {

    String [] paddings = {
        "NONE",
        "PKCS7" ,
        "PKCS5",
        "ISO10126_2",
        "X9_23",
        "ISO7816_4"
    };

    String [] ciphers = {
        "AES128/ECB",
        "AES256/ECB",
        "AES192/ECB",
        "AES128/CBC",
        "AES256/CBC",
        "AES128/CFB1",
        "AES256/CFB1",
        "AES192/CFB1",
        "AES128/CFB8",
        "AES192/CFB8",
        "AES256/CFB8",
        "AES128/CTR",
        "AES192/CTR",
        "AES256/CTR",
        "AES128/CCM",
        "AES256/CCM",
        "AES192/CCM",
        "AES128/GCM",
        "AES192/GCM",
        "AES256/GCM"
    };
   
    @BeforeClass 
    public static void addProvider() {
        Security.addProvider(new OpenSSLFIPSProvider());
    }

    @Test
    public void testSingleUpdate() throws Exception {
        for (String cipher : ciphers) {
            // CCM tests currently fail
            // see https://github.com/openssl/openssl/issues/22773
            if (cipher.endsWith("CCM"))
                continue;

            for(String padding : paddings) {
                runTestSingleUpdate(cipher, padding);
            }
        }
    }

    @Test
    public void testMultipleUpdates() throws Exception {
        for (String cipher : ciphers) {
            // CCM tests currently fail
            // see https://github.com/openssl/openssl/issues/22773
            if (cipher.endsWith("CCM"))
                continue;
            for(String padding : paddings) {
                runTestMultipleUpdates(cipher, padding);
            }
        }
    }

    private void runTestMultipleUpdates(String nameKeySizeAndMode, String padding) throws Exception {
        String cipherName = nameKeySizeAndMode + "/" + padding;
        SecureRandom sr = SecureRandom.getInstance("NativePRNG");

        String aad = "The quick brown fox jumps over the lazy dog";

        byte[] key;
        String keySize = nameKeySizeAndMode.split("/")[0].substring(3);
        if (keySize.equals("128")) {
            key = new byte[16];
        } else if (keySize.equals("192")) {
            key = new byte[24];
        } else if (keySize.equals("256")) {
            key = new byte[32];
        } else {
            fail("Key size unsupported");
            return;
        }

        sr.nextBytes(key);

        byte[] iv = new byte[16];
        sr.nextBytes(iv);

        byte[] input = new byte[16];
        sr.nextBytes(input);

        AlgorithmParameterSpec spec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance(nameKeySizeAndMode + "/" + padding, "OpenSSLFIPSProvider");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec, sr);

        byte[] fullInput = new byte[32];
        System.arraycopy(input, 0, fullInput, 0, 16);
        System.arraycopy(input, 0, fullInput, 16, 16);

        byte[] fullEnc = new byte[128];
        int encLen = 0;

        // Add Additional Authentication Data
        if (nameKeySizeAndMode.endsWith("CCM") || nameKeySizeAndMode.endsWith("GCM")) {
            cipher.updateAAD(aad.getBytes(), 0, aad.length());
        }

        byte[] enc1 = cipher.update(input, 0, input.length);
        System.arraycopy(enc1, 0, fullEnc, 0, enc1.length);
        encLen += enc1.length;
 
        byte[] enc2 = cipher.doFinal(input, 0, input.length);
        System.arraycopy(enc2, 0, fullEnc, encLen, enc2.length);
        encLen += enc2.length;

        Cipher decipher = Cipher.getInstance(nameKeySizeAndMode + "/" + padding, "OpenSSLFIPSProvider");
        decipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec, sr);

        // Add Additional Authentication Data
        if (nameKeySizeAndMode.endsWith("CCM") || nameKeySizeAndMode.endsWith("GCM")) {
            decipher.updateAAD(aad.getBytes(), 0, aad.length());
        }

        byte[] output = decipher.doFinal(fullEnc, 0, encLen);

        assertArrayEquals("Multi-update cipher test for " + cipherName + " failed", fullInput, output); 
    }

    private void runTestSingleUpdate(String nameKeySizeAndMode, String padding) throws Exception {
        SecureRandom sr = SecureRandom.getInstance("NativePRNG");
        String cipherName = nameKeySizeAndMode + "/" + padding;
        Cipher cipher = Cipher.getInstance(cipherName, "OpenSSLFIPSProvider");

        String aad = "The quick brown fox jumps over the lazy dog";

        byte[] key;
        String keySize = nameKeySizeAndMode.split("/")[0].substring(3);
        if (keySize.equals("128")) {
            key = new byte[16];
        } else if (keySize.equals("192")) {
            key = new byte[24];
        } else if (keySize.equals("256")) {
            key = new byte[32];
        } else {
            fail("Key size unsupported");
            return;
        }

        sr.nextBytes(key);

        byte[] iv = new byte[16];
        sr.nextBytes(iv);
        AlgorithmParameterSpec spec = new IvParameterSpec(iv); 

        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec, sr);

        byte[] input = new byte[16];
        sr.nextBytes(input);

        // Add Additional Authentication Data
        if (nameKeySizeAndMode.endsWith("CCM") || nameKeySizeAndMode.endsWith("GCM")) {
            cipher.updateAAD(aad.getBytes(), 0, aad.length());
        }

        byte[] outFinal = cipher.doFinal(input, 0, input.length);

        Cipher decipher = Cipher.getInstance(cipherName, "OpenSSLFIPSProvider");
        decipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec, sr);

        // Add Additional Authentication Data
        if (nameKeySizeAndMode.endsWith("CCM") || nameKeySizeAndMode.endsWith("GCM")) {
            decipher.updateAAD(aad.getBytes(), 0, aad.length());
        }

        byte[] output = decipher.doFinal(outFinal, 0, outFinal.length);

        assertArrayEquals("Single update cipher test for " + cipherName + " failed",  input, output);
    }

    private void runTestGetOutputSize(String nameKeySizeAndMode, String padding) throws Exception {
        String cipherName = nameKeySizeAndMode + "/" + padding;
        SecureRandom sr = SecureRandom.getInstance("NativePRNG");

        byte[] key;
        String keySize = nameKeySizeAndMode.split("/")[0].substring(3);
        if (keySize.equals("128")) {
            key = new byte[16];
        } else if (keySize.equals("192")) {
            key = new byte[24];
        } else if (keySize.equals("256")) {
            key = new byte[32];
        } else {
            fail("Key size unsupported");
            return;
        }

        sr.nextBytes(key);

        byte[] iv = new byte[16];
        sr.nextBytes(iv);
        AlgorithmParameterSpec spec = new IvParameterSpec(iv);

        Cipher cipher = Cipher.getInstance(nameKeySizeAndMode + "/" + padding, "OpenSSLFIPSProvider");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec, sr);

        int inputSize = 512;
        if (!padding.equals("NONE")) {
            inputSize = 511;
        }
        byte[] input = new byte[inputSize];
        sr.nextBytes(input);

        byte[] fullInput = new byte[inputSize*2];
        System.arraycopy(input, 0, fullInput, 0, inputSize);
        System.arraycopy(input, 0, fullInput, inputSize, inputSize);

        byte[] fullEnc = new byte[cipher.getOutputSize(inputSize*2)];
        int encLen = 0;

        byte[] enc1 = cipher.update(input, 0, input.length);
        System.arraycopy(enc1, 0, fullEnc, 0, enc1.length);
        encLen += enc1.length;

        byte[] enc2 = cipher.doFinal(input, 0, input.length);
        System.arraycopy(enc2, 0, fullEnc, encLen, enc2.length);
        encLen += enc2.length;

        assertEquals("Encrypted text has an unexpected length for " + cipherName, encLen, cipher.getOutputSize(inputSize*2));

        Cipher decipher = Cipher.getInstance(nameKeySizeAndMode + "/" + padding, "OpenSSLFIPSProvider");
        decipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec, sr);
        byte[] output = decipher.doFinal(fullEnc, 0, fullEnc.length);
        assertArrayEquals("Multi-update cipher test for " + cipherName + " failed", fullInput, output);
    }

    @Test
    public void testBlockSize() throws Exception {
        for (String cipher : ciphers) {
            for(String padding : paddings) {
                runTestBlockSize(cipher, padding);
            }
        }
    }

    @Test
    public void testGetOutputSize() throws Exception {
        for (String cipher : ciphers) {
            if (cipher.endsWith("CCM"))
                continue;

            for(String padding : paddings) {
                runTestGetOutputSize(cipher, padding);
            }
        }
    }

    @Test
    public void testGetIV() throws Exception {
        for (String cipher : ciphers) {
            for(String padding : paddings) {
                runTestGetIV(cipher, padding);
            }
        }
    }

    private void runTestBlockSize(String cipherName, String padding) throws Exception {
        String fullName = cipherName + "/" + padding;
        Cipher cipher = Cipher.getInstance(fullName, "OpenSSLFIPSProvider");
        assertEquals("Invalid block size", cipher.getBlockSize(), 16);
    }

    private void runTestGetIV(String nameKeySizeAndMode, String padding) throws Exception {
        SecureRandom sr = SecureRandom.getInstance("NativePRNG");
        String cipherName = nameKeySizeAndMode + "/" + padding;

        Cipher cipher = Cipher.getInstance(cipherName, "OpenSSLFIPSProvider");

        byte[] key;
        String keySize = nameKeySizeAndMode.split("/")[0].substring(3);
        if (keySize.equals("128")) {
            key = new byte[16];
        } else if (keySize.equals("192")) {
            key = new byte[24];
        } else if (keySize.equals("256")) {
            key = new byte[32];
        } else {
            fail("Key size unsupported");
            return;
        }

        sr.nextBytes(key);

        byte[] iv = new byte[16];
        sr.nextBytes(iv);

        AlgorithmParameterSpec spec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec, sr);
        byte[] retIV = cipher.getIV();
        assertArrayEquals("Returned IV does not match supplied IV", iv, retIV);
    }

    @Test
    public void testKeyWrapUnwrap() throws Exception {
        for (String cipher : ciphers) {
            // CCM tests currently fail
            // see https://github.com/openssl/openssl/issues/22773
            if (cipher.endsWith("CCM"))
                continue;

            for(String padding : paddings) {
                runTestKeyWrapUnwrap(cipher, padding);
            }
        }
    }
    public void runTestKeyWrapUnwrap(String nameKeySizeAndMode, String padding) throws Exception {

        SecureRandom sr = SecureRandom.getInstance("NativePRNG");
        String cipherName = nameKeySizeAndMode + "/" + padding;

        // create key
        byte[] key;
        String keySize = nameKeySizeAndMode.split("/")[0].substring(3);
        if (keySize.equals("128")) {
            key = new byte[16];
        } else if (keySize.equals("192")) {
            key = new byte[24];
        } else if (keySize.equals("256")) {
            key = new byte[32];
        } else {
            fail("Key size unsupported");
            return;
        }

        sr.nextBytes(key);
        Key wrappingKey = new SecretKeySpec(key, "AES");

        byte[] iv = new byte[16];
        sr.nextBytes(iv);
        AlgorithmParameterSpec spec = new IvParameterSpec(iv);

        // create secret key to wrap/unwrap
        byte[] testKey = new byte[16];
        sr.nextBytes(testKey);
        SecretKeySpec sk1 = new SecretKeySpec(testKey, 0, 16, "AES");


        // init cipher for key wrapping
        Cipher cipher = Cipher.getInstance(cipherName, "OpenSSLFIPSProvider");
        cipher.init(Cipher.WRAP_MODE, wrappingKey, spec, sr);

        // wrap
        byte[] wrappedKey = cipher.wrap(sk1);

        // init cipher for key wrapping
        Cipher decipher = Cipher.getInstance(cipherName, "OpenSSLFIPSProvider");
        decipher.init(Cipher.UNWRAP_MODE, wrappingKey, spec, sr);

        // unwrap
        Key sk2 = decipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);

        assertArrayEquals("Invalid secret key " + (nameKeySizeAndMode + "/" +  padding), sk1.getEncoded(), sk2.getEncoded());
    }
}
