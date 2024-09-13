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
import com.canonical.openssl.provider.OpenSSLFIPSProvider;
import java.security.Security;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.lang.reflect.Method;
import java.lang.reflect.Field;
import java.lang.Class;
import java.lang.IllegalAccessException;
import java.lang.NoSuchMethodException;
import java.lang.NoSuchFieldException;
import java.lang.reflect.InvocationTargetException;
import javax.crypto.KeyAgreement;
import javax.crypto.KEM;
import javax.crypto.Mac;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.SecretKeyFactory;
import javax.crypto.Cipher;

import com.canonical.openssl.drbg.*;
import com.canonical.openssl.keyagreement.*;
import com.canonical.openssl.keyencapsulation.*;
import com.canonical.openssl.mac.*;
import com.canonical.openssl.md.*;
import com.canonical.openssl.signature.*;
import com.canonical.openssl.kdf.*;
import com.canonical.openssl.cipher.*;

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;


public class ProviderSanityTest {
    @BeforeClass
    public static void addProvider() {
        Security.addProvider(new OpenSSLFIPSProvider());
    }

    private static void test(Class<?> klass, String algo, Class<?> expectedSpiClass, String privateFieldName) {
        assertDoesNotThrow(() -> { 
            Method getInstanceMethod = klass.getDeclaredMethod("getInstance", String.class, String.class);
            Object algoInstance = getInstanceMethod.invoke(null, algo, "OpenSSLFIPSProvider");
            assertNotNull("Failed to create instances for " + algo, algoInstance);
        });
    }

    @Test
    public void testDRBG() {
        test(SecureRandom.class, "AES256CTR", DrbgAES256CTR.class, "secureRandomSpi");
        test(SecureRandom.class, "HashSHA512", DrbgHashSHA512.class, "secureRandomSpi");
        test(SecureRandom.class, "HMACSHA256", DrbgHMACSHA256.class, "secureRandomSpi");
    }

    @Test
    public void testKeyAgreement() {
        test(KeyAgreement.class, "DH", DHKeyAgreement.class, "spi");
        test(KeyAgreement.class, "ECDH", ECDHKeyAgreement.class, "spi");
    }

    @Test
    public void testKeyEncapsulation() {
        test(KEM.class, "RSA", OpenSSLKEMRSA.class, "spi");
    }

    @Test
    public void testMAC() {
        test(Mac.class, "CMACwithAes256CBC", CMACwithAes256CBC.class, "spi");
        test(Mac.class, "GMACWithAes128GCM", GMACWithAes128GCM.class, "spi");
        test(Mac.class, "HMACwithSHA1", HMACwithSHA1.class, "spi");
        test(Mac.class, "HMACwithSHA3_512", HMACwithSHA3_512.class, "spi");
        test(Mac.class, "KMAC128", KMAC128.class, "spi");
        test(Mac.class, "KMAC256", KMAC256.class, "spi");
    }

    @Test
    public void testMessageDigests() {
        test(MessageDigest.class, "MDKeccakKemak128", MDKeccakKemak128.class, "digestSpi");
        test(MessageDigest.class, "MDKeccakKemak256", MDKeccakKemak256.class, "digestSpi");
        test(MessageDigest.class, "MDSHA1", MDSHA1.class, "digestSpi");
        test(MessageDigest.class, "MDSHA224", MDSHA224.class, "digestSpi");
        test(MessageDigest.class, "MDSHA256", MDSHA256.class, "digestSpi");
        test(MessageDigest.class, "MDSHA384", MDSHA384.class, "digestSpi");
        test(MessageDigest.class, "MDSHA512", MDSHA512.class, "digestSpi");
        test(MessageDigest.class, "MDSHA3_224", MDSHA3_224.class, "digestSpi");
        test(MessageDigest.class, "MDSHA3_256", MDSHA3_256.class, "digestSpi");
        test(MessageDigest.class, "MDSHA3_256", MDSHA3_256.class, "digestSpi");
        test(MessageDigest.class, "MDSHA3_256", MDSHA3_256.class, "digestSpi");
    }

    @Test
    public void testSignatures() {
        test(Signature.class, "RSA", SignatureRSA.class, "sigSpi");
        //test(Signature.class, "ED448", SignatureED448.class, "sigSpi");
        //test(Signature.class, "ED25519", SignatureED25519.class, "sigSpi");
    }

    @Test
    public void testKDF() {
        test(SecretKeyFactory.class, "PBKDF2", PBKDF2withSHA512.class, "spi");
    }

    @Test
    public void testCipher() {
        test(Cipher.class, "AES128/ECB/NONE", AES128withECBpaddingNONE.class, "spi");
        test(Cipher.class, "AES128/ECB/PKCS7", AES128withECBpaddingPKCS7.class, "spi");
        test(Cipher.class, "AES128/ECB/PKCS5", AES128withECBpaddingPKCS5.class, "spi");
        test(Cipher.class, "AES128/ECB/ISO10126_2", AES128withECBpaddingISO10126_2.class, "spi");
        test(Cipher.class, "AES128/ECB/X9_23", AES128withECBpaddingX9_23.class, "spi");
        test(Cipher.class, "AES128/ECB/ISO7816_4", AES128withECBpaddingISO7816_4.class, "spi");
        test(Cipher.class, "AES256/ECB/NONE", AES256withECBpaddingNONE.class, "spi");
        test(Cipher.class, "AES256/ECB/PKCS7", AES256withECBpaddingPKCS7.class, "spi");
        test(Cipher.class, "AES256/ECB/PKCS5", AES256withECBpaddingPKCS5.class, "spi");
        test(Cipher.class, "AES256/ECB/ISO10126_2", AES256withECBpaddingISO10126_2.class, "spi");
        test(Cipher.class, "AES256/ECB/X9_23", AES256withECBpaddingX9_23.class, "spi");
        test(Cipher.class, "AES256/ECB/ISO7816_4", AES256withECBpaddingISO7816_4.class, "spi");
        test(Cipher.class, "AES192/ECB/NONE", AES192withECBpaddingNONE.class, "spi");
        test(Cipher.class, "AES192/ECB/PKCS7", AES192withECBpaddingPKCS7.class, "spi");
        test(Cipher.class, "AES192/ECB/PKCS5", AES192withECBpaddingPKCS5.class, "spi");
        test(Cipher.class, "AES192/ECB/ISO10126_2", AES192withECBpaddingISO10126_2.class, "spi");
        test(Cipher.class, "AES192/ECB/X9_23", AES192withECBpaddingX9_23.class, "spi");
        test(Cipher.class, "AES192/ECB/ISO7816_4", AES192withECBpaddingISO7816_4.class, "spi");
        test(Cipher.class, "AES128/CBC/NONE", AES128withCBCpaddingNONE.class, "spi");
        test(Cipher.class, "AES128/CBC/PKCS7", AES128withCBCpaddingPKCS7.class, "spi");
        test(Cipher.class, "AES128/CBC/PKCS5", AES128withCBCpaddingPKCS5.class, "spi");
        test(Cipher.class, "AES128/CBC/ISO10126_2", AES128withCBCpaddingISO10126_2.class, "spi");
        test(Cipher.class, "AES128/CBC/X9_23", AES128withCBCpaddingX9_23.class, "spi");
        test(Cipher.class, "AES128/CBC/ISO7816_4", AES128withCBCpaddingISO7816_4.class, "spi");
        test(Cipher.class, "AES256/CBC/NONE", AES256withCBCpaddingNONE.class, "spi");
        test(Cipher.class, "AES256/CBC/PKCS7", AES256withCBCpaddingPKCS7.class, "spi");
        test(Cipher.class, "AES256/CBC/PKCS5", AES256withCBCpaddingPKCS5.class, "spi");
        test(Cipher.class, "AES256/CBC/ISO10126_2", AES256withCBCpaddingISO10126_2.class, "spi");
        test(Cipher.class, "AES256/CBC/X9_23", AES256withCBCpaddingX9_23.class, "spi");
        test(Cipher.class, "AES256/CBC/ISO7816_4", AES256withCBCpaddingISO7816_4.class, "spi");
        test(Cipher.class, "AES128/CFB1/NONE", AES128withCFB1paddingNONE.class, "spi");
        test(Cipher.class, "AES128/CFB1/PKCS7", AES128withCFB1paddingPKCS7.class, "spi");
        test(Cipher.class, "AES128/CFB1/PKCS5", AES128withCFB1paddingPKCS5.class, "spi");
        test(Cipher.class, "AES128/CFB1/ISO10126_2", AES128withCFB1paddingISO10126_2.class, "spi");
        test(Cipher.class, "AES128/CFB1/X9_23", AES128withCFB1paddingX9_23.class, "spi");
        test(Cipher.class, "AES128/CFB1/ISO7816_4", AES128withCFB1paddingISO7816_4.class, "spi");
        test(Cipher.class, "AES256/CFB1/NONE", AES256withCFB1paddingNONE.class, "spi");
        test(Cipher.class, "AES256/CFB1/PKCS7", AES256withCFB1paddingPKCS7.class, "spi");
        test(Cipher.class, "AES256/CFB1/PKCS5", AES256withCFB1paddingPKCS5.class, "spi");
        test(Cipher.class, "AES256/CFB1/ISO10126_2", AES256withCFB1paddingISO10126_2.class, "spi");
        test(Cipher.class, "AES256/CFB1/X9_23", AES256withCFB1paddingX9_23.class, "spi");
        test(Cipher.class, "AES256/CFB1/ISO7816_4", AES256withCFB1paddingISO7816_4.class, "spi");
        test(Cipher.class, "AES192/CFB1/NONE", AES192withCFB1paddingNONE.class, "spi");
        test(Cipher.class, "AES192/CFB1/PKCS7", AES192withCFB1paddingPKCS7.class, "spi");
        test(Cipher.class, "AES192/CFB1/PKCS5", AES192withCFB1paddingPKCS5.class, "spi");
        test(Cipher.class, "AES192/CFB1/ISO10126_2", AES192withCFB1paddingISO10126_2.class, "spi");
        test(Cipher.class, "AES192/CFB1/X9_23", AES192withCFB1paddingX9_23.class, "spi");
        test(Cipher.class, "AES192/CFB1/ISO7816_4", AES192withCFB1paddingISO7816_4.class, "spi");
        test(Cipher.class, "AES128/CFB8/NONE", AES128withCFB8paddingNONE.class, "spi");
        test(Cipher.class, "AES128/CFB8/PKCS7", AES128withCFB8paddingPKCS7.class, "spi");
        test(Cipher.class, "AES128/CFB8/PKCS5", AES128withCFB8paddingPKCS5.class, "spi");
        test(Cipher.class, "AES128/CFB8/ISO10126_2", AES128withCFB8paddingISO10126_2.class, "spi");
        test(Cipher.class, "AES128/CFB8/X9_23", AES128withCFB8paddingX9_23.class, "spi");
        test(Cipher.class, "AES128/CFB8/ISO7816_4", AES128withCFB8paddingISO7816_4.class, "spi");
        test(Cipher.class, "AES192/CFB8/NONE", AES192withCFB8paddingNONE.class, "spi");
        test(Cipher.class, "AES192/CFB8/PKCS7", AES192withCFB8paddingPKCS7.class, "spi");
        test(Cipher.class, "AES192/CFB8/PKCS5", AES192withCFB8paddingPKCS5.class, "spi");
        test(Cipher.class, "AES192/CFB8/ISO10126_2", AES192withCFB8paddingISO10126_2.class, "spi");
        test(Cipher.class, "AES192/CFB8/X9_23", AES192withCFB8paddingX9_23.class, "spi");
        test(Cipher.class, "AES192/CFB8/ISO7816_4", AES192withCFB8paddingISO7816_4.class, "spi");
        test(Cipher.class, "AES256/CFB8/NONE", AES256withCFB8paddingNONE.class, "spi");
        test(Cipher.class, "AES256/CFB8/PKCS7", AES256withCFB8paddingPKCS7.class, "spi");
        test(Cipher.class, "AES256/CFB8/PKCS5", AES256withCFB8paddingPKCS5.class, "spi");
        test(Cipher.class, "AES256/CFB8/ISO10126_2", AES256withCFB8paddingISO10126_2.class, "spi");
        test(Cipher.class, "AES256/CFB8/X9_23", AES256withCFB8paddingX9_23.class, "spi");
        test(Cipher.class, "AES256/CFB8/ISO7816_4", AES256withCFB8paddingISO7816_4.class, "spi");
        test(Cipher.class, "AES128/CTR/NONE", AES128withCTRpaddingNONE.class, "spi");
        test(Cipher.class, "AES128/CTR/PKCS7", AES128withCTRpaddingPKCS7.class, "spi");
        test(Cipher.class, "AES128/CTR/PKCS5", AES128withCTRpaddingPKCS5.class, "spi");
        test(Cipher.class, "AES128/CTR/ISO10126_2", AES128withCTRpaddingISO10126_2.class, "spi");
        test(Cipher.class, "AES128/CTR/X9_23", AES128withCTRpaddingX9_23.class, "spi");
        test(Cipher.class, "AES128/CTR/ISO7816_4", AES128withCTRpaddingISO7816_4.class, "spi");
        test(Cipher.class, "AES192/CTR/NONE", AES192withCTRpaddingNONE.class, "spi");
        test(Cipher.class, "AES192/CTR/PKCS7", AES192withCTRpaddingPKCS7.class, "spi");
        test(Cipher.class, "AES192/CTR/PKCS5", AES192withCTRpaddingPKCS5.class, "spi");
        test(Cipher.class, "AES192/CTR/ISO10126_2", AES192withCTRpaddingISO10126_2.class, "spi");
        test(Cipher.class, "AES192/CTR/X9_23", AES192withCTRpaddingX9_23.class, "spi");
        test(Cipher.class, "AES192/CTR/ISO7816_4", AES192withCTRpaddingISO7816_4.class, "spi");
        test(Cipher.class, "AES256/CTR/NONE", AES256withCTRpaddingNONE.class, "spi");
        test(Cipher.class, "AES256/CTR/PKCS7", AES256withCTRpaddingPKCS7.class, "spi");
        test(Cipher.class, "AES256/CTR/PKCS5", AES256withCTRpaddingPKCS5.class, "spi");
        test(Cipher.class, "AES256/CTR/ISO10126_2", AES256withCTRpaddingISO10126_2.class, "spi");
        test(Cipher.class, "AES256/CTR/X9_23", AES256withCTRpaddingX9_23.class, "spi");
        test(Cipher.class, "AES256/CTR/ISO7816_4", AES256withCTRpaddingISO7816_4.class, "spi");
        test(Cipher.class, "AES128/CCM/NONE", AES128withCCMpaddingNONE.class, "spi");
        test(Cipher.class, "AES128/CCM/PKCS7", AES128withCCMpaddingPKCS7.class, "spi");
        test(Cipher.class, "AES128/CCM/PKCS5", AES128withCCMpaddingPKCS5.class, "spi");
        test(Cipher.class, "AES128/CCM/ISO10126_2", AES128withCCMpaddingISO10126_2.class, "spi");
        test(Cipher.class, "AES128/CCM/X9_23", AES128withCCMpaddingX9_23.class, "spi");
        test(Cipher.class, "AES128/CCM/ISO7816_4", AES128withCCMpaddingISO7816_4.class, "spi");
        test(Cipher.class, "AES256/CCM/NONE", AES256withCCMpaddingNONE.class, "spi");
        test(Cipher.class, "AES256/CCM/PKCS7", AES256withCCMpaddingPKCS7.class, "spi");
        test(Cipher.class, "AES256/CCM/PKCS5", AES256withCCMpaddingPKCS5.class, "spi");
        test(Cipher.class, "AES256/CCM/ISO10126_2", AES256withCCMpaddingISO10126_2.class, "spi");
        test(Cipher.class, "AES256/CCM/X9_23", AES256withCCMpaddingX9_23.class, "spi");
        test(Cipher.class, "AES256/CCM/ISO7816_4", AES256withCCMpaddingISO7816_4.class, "spi");
        test(Cipher.class, "AES192/CCM/NONE", AES192withCCMpaddingNONE.class, "spi");
        test(Cipher.class, "AES192/CCM/PKCS7", AES192withCCMpaddingPKCS7.class, "spi");
        test(Cipher.class, "AES192/CCM/PKCS5", AES192withCCMpaddingPKCS5.class, "spi");
        test(Cipher.class, "AES192/CCM/ISO10126_2", AES192withCCMpaddingISO10126_2.class, "spi");
        test(Cipher.class, "AES192/CCM/X9_23", AES192withCCMpaddingX9_23.class, "spi");
        test(Cipher.class, "AES192/CCM/ISO7816_4", AES192withCCMpaddingISO7816_4.class, "spi");
        test(Cipher.class, "AES128/GCM/NONE", AES128withGCMpaddingNONE.class, "spi");
        test(Cipher.class, "AES128/GCM/PKCS7", AES128withGCMpaddingPKCS7.class, "spi");
        test(Cipher.class, "AES128/GCM/PKCS5", AES128withGCMpaddingPKCS5.class, "spi");
        test(Cipher.class, "AES128/GCM/ISO10126_2", AES128withGCMpaddingISO10126_2.class, "spi");
        test(Cipher.class, "AES128/GCM/X9_23", AES128withGCMpaddingX9_23.class, "spi");
        test(Cipher.class, "AES128/GCM/ISO7816_4", AES128withGCMpaddingISO7816_4.class, "spi");
        test(Cipher.class, "AES192/GCM/NONE", AES192withGCMpaddingNONE.class, "spi");
        test(Cipher.class, "AES192/GCM/PKCS7", AES192withGCMpaddingPKCS7.class, "spi");
        test(Cipher.class, "AES192/GCM/PKCS5", AES192withGCMpaddingPKCS5.class, "spi");
        test(Cipher.class, "AES192/GCM/ISO10126_2", AES192withGCMpaddingISO10126_2.class, "spi");
        test(Cipher.class, "AES192/GCM/X9_23", AES192withGCMpaddingX9_23.class, "spi");
        test(Cipher.class, "AES192/GCM/ISO7816_4", AES192withGCMpaddingISO7816_4.class, "spi");
        test(Cipher.class, "AES256/GCM/NONE", AES256withGCMpaddingNONE.class, "spi");
        test(Cipher.class, "AES256/GCM/PKCS7", AES256withGCMpaddingPKCS7.class, "spi");
        test(Cipher.class, "AES256/GCM/PKCS5", AES256withGCMpaddingPKCS5.class, "spi");
        test(Cipher.class, "AES256/GCM/ISO10126_2", AES256withGCMpaddingISO10126_2.class, "spi");
        test(Cipher.class, "AES256/GCM/X9_23", AES256withGCMpaddingX9_23.class, "spi");
        test(Cipher.class, "AES256/GCM/ISO7816_4", AES256withGCMpaddingISO7816_4.class, "spi");
    }
}
        
