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
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

// TODO: refactoring
// failing CCM tests
public class CipherApiTest {

    private static boolean testFailed = false;

    static List<String> knownFailures = List.of(
        "AES192/GCM/ISO10126_2",
	"AES128/GCM/PKCS7",
        "AES256/CTR/NONE"
    );

    static String [] paddings = {
        "NONE",
        "PKCS7" ,
        "PKCS5",
        "ISO10126_2",
        "X9_23",
        "ISO7816_4"
    };

    static String [] ciphers = {
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
    
    public static void main(String[] args) throws Exception {
        Security.addProvider(new OpenSSLFIPSProvider());
        testSingleUpdate();
        testMultipleUpdates();
        System.exit(testFailed ? 1 : 0);
    }

    private static void testSingleUpdate() throws Exception {
        System.out.print("Test with single encryption updates: ");
        boolean fails = false;
        for (String cipher : ciphers) {
            // CCM tests currently fail
            // see https://github.com/openssl/openssl/issues/22773
            if (cipher.endsWith("CCM"))
                continue;

            for(String padding : paddings) {
                if (!runTestSingleUpdate(cipher, padding) && !knownFailures.contains(cipher+"/"+padding)) {
		    System.out.println("Cipher: " + cipher + "/" + padding  + ": FAILED");
                    fails = true;
                }
            }
        }
        if (fails == true) {
            testFailed = true;
            System.out.println("FAILED");
            fails = false;
        } else {
            System.out.println("PASSED");
        }
    }

    private static void testMultipleUpdates() throws Exception {
        System.out.print("Test with multiple encryption updates [skipping CCM tests]: "); 

        boolean fails = false;
        for (String cipher : ciphers) {
            // CCM tests currently fail
            // see https://github.com/openssl/openssl/issues/22773
            if (cipher.endsWith("CCM"))
                continue;
            for(String padding : paddings) {
                if (!runTestMultipleUpdates(cipher, padding)) { 
                    System.out.println(cipher + " " + padding);
                    fails = true;
                }
            }
        }

        if (fails == true) {
            testFailed = true;
            System.out.println("FAILED");
            fails = false; 
        } else {
            System.out.println("PASSED");
        }
    }

    private static boolean runTestMultipleUpdates(String nameKeySizeAndMode, String padding) throws Exception {
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
            System.out.println("Key size unsupported");
            return false;
        }

        sr.nextBytes(key);

        byte[] iv = new byte[8];
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
 
        byte[] enc1 = cipher.update(input, 0, input.length);
        System.arraycopy(enc1, 0, fullEnc, 0, enc1.length);
        encLen += enc1.length;
 
        byte[] enc2 = cipher.doFinal(input, 0, input.length);
        System.arraycopy(enc2, 0, fullEnc, encLen, enc2.length);
        encLen += enc2.length;

        Cipher decipher = Cipher.getInstance(nameKeySizeAndMode + "/" + padding, "OpenSSLFIPSProvider");
        decipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec, sr);
        byte[] output = decipher.doFinal(fullEnc, 0, encLen);

        return Arrays.equals(fullInput, output);
    }

    private static boolean runTestSingleUpdate(String nameKeySizeAndMode, String padding) throws Exception {
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
            System.out.println("Key size unsupported");
            return false;
        }

        sr.nextBytes(key);

        byte[] iv = new byte[8]; 
        sr.nextBytes(iv);

        AlgorithmParameterSpec spec = new IvParameterSpec(iv); 

        Cipher cipher = Cipher.getInstance(nameKeySizeAndMode + "/" + padding, "OpenSSLFIPSProvider"); 
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec, sr);

        byte[] input = new byte[16];
        sr.nextBytes(input);

        byte[] outFinal = cipher.doFinal(input, 0, input.length);

        Cipher decipher = Cipher.getInstance(nameKeySizeAndMode + "/" + padding, "OpenSSLFIPSProvider");
        decipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec, sr);
        byte[] output = decipher.doFinal(outFinal, 0, outFinal.length);

        return Arrays.equals(input, output);
    }
 
}
        


