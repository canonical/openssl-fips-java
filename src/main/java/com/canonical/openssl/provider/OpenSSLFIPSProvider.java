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
package com.canonical.openssl.provider;

import java.security.Provider;

public final class OpenSSLFIPSProvider extends Provider {
    public OpenSSLFIPSProvider() {
        super("OpenSSLFIPSProvider", "0.0.1", "A pass-through security provider for FIPS-certified openssl");

        // SecureRandom
        put("SecureRandom.AES256CTR", "com.canonical.openssl.drbg.DrbgAES256CTR");
        put("SecureRandom.HashSHA512", "com.canonical.openssl.drbg.DrbgHashSHA512");
        put("SecureRandom.HMACSHA256", "com.canonical.openssl.drbg.DrbgHMACSHA256");

        // Key Agreements
        put("KeyAgreement.DH", "com.canonical.openssl.keyagreement.DHKeyAgreement");
        put("KeyAgreement.ECDH", "com.canonical.openssl.keyagreement.ECDHKeyAgreement");

        // Key Encapsulation
        put("KEM.RSA", "com.canonical.openssl.keyencapsulation.OpenSSLKEMRSA");

        // Message Authentication Codes
        put("MAC.CMACwithAes256CBC", "com.canonical.openssl.mac.CMACwithAes256CBC");
        put("MAC.GMACWithAes128GCM", "com.canonical.openssl.mac.GMACWithAes128GCM");
        put("MAC.HMACwithSHA1", "com.canonical.openssl.mac.HMACwithSHA1");
        put("MAC.HMACwithSHA3_512", "com.canonical.openssl.mac.HMACwithSHA3_512");
        put("MAC.KMAC128", "com.canonical.openssl.mac.KMAC128");
        put("MAC.KMAC256", "com.canonical.openssl.mac.KMAC256");

        // Message Digests
        put("MessageDigest.MDKeccakKemak128", "com.canonical.openssl.md.MDKeccakKemak128");
        put("MessageDigest.MDKeccakKemak256", "com.canonical.openssl.md.MDKeccakKemak256");
        put("MessageDigest.MDSHA3_256", "com.canonical.openssl.md.MDSHA3_256");
        put("MessageDigest.MDSHA3_384", "com.canonical.openssl.md.MDSHA3_384");
        put("MessageDigest.MDSHA1", "com.canonical.openssl.md.MDSHA1");
        put("MessageDigest.MDSHA3_512", "com.canonical.openssl.md.MDSHA3_512");
        put("MessageDigest.MDSHA224", "com.canonical.openssl.md.MDSHA224");
        put("MessageDigest.MDSHA384", "com.canonical.openssl.md.MDSHA384");
        put("MessageDigest.MDSHA256", "com.canonical.openssl.md.MDSHA256");
        put("MessageDigest.MDSHA3_224", "com.canonical.openssl.md.MDSHA3_224");
        put("MessageDigest.MDSHA512", "com.canonical.openssl.md.MDSHA512");

        // Signatures
        put("Signature.RSA", "com.canonical.openssl.signature.SignatureRSA");
        // The openssl FIPS provider for Ubuntu Pro does not have support for ED448 and ED25519.
        // There is lack of clarity over the FIPS approval status of these algorithms.
        // put("Signature.ED448", "com.canonical.openssl.signature.SignatureED448");
        // put("Signature.ED25519", "com.canonical.openssl.signature.SignatureED25519");

        // Secret Key Factory
        put("SecretKeyFactory.PBKDF2", "com.canonical.openssl.kdf.PBKDF2withSHA512");

        // Ciphers
        put("Cipher.AES128/ECB/NONE","com.canonical.openssl.cipher.AES128withECBpaddingNONE");
        put("Cipher.AES128/ECB/PKCS7","com.canonical.openssl.cipher.AES128withECBpaddingPKCS7");
        put("Cipher.AES128/ECB/PKCS5","com.canonical.openssl.cipher.AES128withECBpaddingPKCS5");
        put("Cipher.AES128/ECB/ISO10126_2","com.canonical.openssl.cipher.AES128withECBpaddingISO10126_2");
        put("Cipher.AES128/ECB/X9_23","com.canonical.openssl.cipher.AES128withECBpaddingX9_23");
        put("Cipher.AES128/ECB/ISO7816_4","com.canonical.openssl.cipher.AES128withECBpaddingISO7816_4");
        put("Cipher.AES256/ECB/NONE","com.canonical.openssl.cipher.AES256withECBpaddingNONE");
        put("Cipher.AES256/ECB/PKCS7","com.canonical.openssl.cipher.AES256withECBpaddingPKCS7");
        put("Cipher.AES256/ECB/PKCS5","com.canonical.openssl.cipher.AES256withECBpaddingPKCS5");
        put("Cipher.AES256/ECB/ISO10126_2","com.canonical.openssl.cipher.AES256withECBpaddingISO10126_2");
        put("Cipher.AES256/ECB/X9_23","com.canonical.openssl.cipher.AES256withECBpaddingX9_23");
        put("Cipher.AES256/ECB/ISO7816_4","com.canonical.openssl.cipher.AES256withECBpaddingISO7816_4");
        put("Cipher.AES192/ECB/NONE","com.canonical.openssl.cipher.AES192withECBpaddingNONE");
        put("Cipher.AES192/ECB/PKCS7","com.canonical.openssl.cipher.AES192withECBpaddingPKCS7");
        put("Cipher.AES192/ECB/PKCS5","com.canonical.openssl.cipher.AES192withECBpaddingPKCS5");
        put("Cipher.AES192/ECB/ISO10126_2","com.canonical.openssl.cipher.AES192withECBpaddingISO10126_2");
        put("Cipher.AES192/ECB/X9_23","com.canonical.openssl.cipher.AES192withECBpaddingX9_23");
        put("Cipher.AES192/ECB/ISO7816_4","com.canonical.openssl.cipher.AES192withECBpaddingISO7816_4");
        put("Cipher.AES128/CBC/NONE","com.canonical.openssl.cipher.AES128withCBCpaddingNONE");
        put("Cipher.AES128/CBC/PKCS7","com.canonical.openssl.cipher.AES128withCBCpaddingPKCS7");
        put("Cipher.AES128/CBC/PKCS5","com.canonical.openssl.cipher.AES128withCBCpaddingPKCS5");
        put("Cipher.AES128/CBC/ISO10126_2","com.canonical.openssl.cipher.AES128withCBCpaddingISO10126_2");
        put("Cipher.AES128/CBC/X9_23","com.canonical.openssl.cipher.AES128withCBCpaddingX9_23");
        put("Cipher.AES128/CBC/ISO7816_4","com.canonical.openssl.cipher.AES128withCBCpaddingISO7816_4");
        put("Cipher.AES256/CBC/NONE","com.canonical.openssl.cipher.AES256withCBCpaddingNONE");
        put("Cipher.AES256/CBC/PKCS7","com.canonical.openssl.cipher.AES256withCBCpaddingPKCS7");
        put("Cipher.AES256/CBC/PKCS5","com.canonical.openssl.cipher.AES256withCBCpaddingPKCS5");
        put("Cipher.AES256/CBC/ISO10126_2","com.canonical.openssl.cipher.AES256withCBCpaddingISO10126_2");
        put("Cipher.AES256/CBC/X9_23","com.canonical.openssl.cipher.AES256withCBCpaddingX9_23");
        put("Cipher.AES256/CBC/ISO7816_4","com.canonical.openssl.cipher.AES256withCBCpaddingISO7816_4");
        put("Cipher.AES128/CFB1/NONE","com.canonical.openssl.cipher.AES128withCFB1paddingNONE");
        put("Cipher.AES128/CFB1/PKCS7","com.canonical.openssl.cipher.AES128withCFB1paddingPKCS7");
        put("Cipher.AES128/CFB1/PKCS5","com.canonical.openssl.cipher.AES128withCFB1paddingPKCS5");
        put("Cipher.AES128/CFB1/ISO10126_2","com.canonical.openssl.cipher.AES128withCFB1paddingISO10126_2");
        put("Cipher.AES128/CFB1/X9_23","com.canonical.openssl.cipher.AES128withCFB1paddingX9_23");
        put("Cipher.AES128/CFB1/ISO7816_4","com.canonical.openssl.cipher.AES128withCFB1paddingISO7816_4");
        put("Cipher.AES256/CFB1/NONE","com.canonical.openssl.cipher.AES256withCFB1paddingNONE");
        put("Cipher.AES256/CFB1/PKCS7","com.canonical.openssl.cipher.AES256withCFB1paddingPKCS7");
        put("Cipher.AES256/CFB1/PKCS5","com.canonical.openssl.cipher.AES256withCFB1paddingPKCS5");
        put("Cipher.AES256/CFB1/ISO10126_2","com.canonical.openssl.cipher.AES256withCFB1paddingISO10126_2");
        put("Cipher.AES256/CFB1/X9_23","com.canonical.openssl.cipher.AES256withCFB1paddingX9_23");
        put("Cipher.AES256/CFB1/ISO7816_4","com.canonical.openssl.cipher.AES256withCFB1paddingISO7816_4");
        put("Cipher.AES192/CFB1/NONE","com.canonical.openssl.cipher.AES192withCFB1paddingNONE");
        put("Cipher.AES192/CFB1/PKCS7","com.canonical.openssl.cipher.AES192withCFB1paddingPKCS7");
        put("Cipher.AES192/CFB1/PKCS5","com.canonical.openssl.cipher.AES192withCFB1paddingPKCS5");
        put("Cipher.AES192/CFB1/ISO10126_2","com.canonical.openssl.cipher.AES192withCFB1paddingISO10126_2");
        put("Cipher.AES192/CFB1/X9_23","com.canonical.openssl.cipher.AES192withCFB1paddingX9_23");
        put("Cipher.AES192/CFB1/ISO7816_4","com.canonical.openssl.cipher.AES192withCFB1paddingISO7816_4");
        put("Cipher.AES128/CFB8/NONE","com.canonical.openssl.cipher.AES128withCFB8paddingNONE");
        put("Cipher.AES128/CFB8/PKCS7","com.canonical.openssl.cipher.AES128withCFB8paddingPKCS7");
        put("Cipher.AES128/CFB8/PKCS5","com.canonical.openssl.cipher.AES128withCFB8paddingPKCS5");
        put("Cipher.AES128/CFB8/ISO10126_2","com.canonical.openssl.cipher.AES128withCFB8paddingISO10126_2");
        put("Cipher.AES128/CFB8/X9_23","com.canonical.openssl.cipher.AES128withCFB8paddingX9_23");
        put("Cipher.AES128/CFB8/ISO7816_4","com.canonical.openssl.cipher.AES128withCFB8paddingISO7816_4");
        put("Cipher.AES192/CFB8/NONE","com.canonical.openssl.cipher.AES192withCFB8paddingNONE");
        put("Cipher.AES192/CFB8/PKCS7","com.canonical.openssl.cipher.AES192withCFB8paddingPKCS7");
        put("Cipher.AES192/CFB8/PKCS5","com.canonical.openssl.cipher.AES192withCFB8paddingPKCS5");
        put("Cipher.AES192/CFB8/ISO10126_2","com.canonical.openssl.cipher.AES192withCFB8paddingISO10126_2");
        put("Cipher.AES192/CFB8/X9_23","com.canonical.openssl.cipher.AES192withCFB8paddingX9_23");
        put("Cipher.AES192/CFB8/ISO7816_4","com.canonical.openssl.cipher.AES192withCFB8paddingISO7816_4");
        put("Cipher.AES256/CFB8/NONE","com.canonical.openssl.cipher.AES256withCFB8paddingNONE");
        put("Cipher.AES256/CFB8/PKCS7","com.canonical.openssl.cipher.AES256withCFB8paddingPKCS7");
        put("Cipher.AES256/CFB8/PKCS5","com.canonical.openssl.cipher.AES256withCFB8paddingPKCS5");
        put("Cipher.AES256/CFB8/ISO10126_2","com.canonical.openssl.cipher.AES256withCFB8paddingISO10126_2");
        put("Cipher.AES256/CFB8/X9_23","com.canonical.openssl.cipher.AES256withCFB8paddingX9_23");
        put("Cipher.AES256/CFB8/ISO7816_4","com.canonical.openssl.cipher.AES256withCFB8paddingISO7816_4");
        put("Cipher.AES128/CTR/NONE","com.canonical.openssl.cipher.AES128withCTRpaddingNONE");
        put("Cipher.AES128/CTR/PKCS7","com.canonical.openssl.cipher.AES128withCTRpaddingPKCS7");
        put("Cipher.AES128/CTR/PKCS5","com.canonical.openssl.cipher.AES128withCTRpaddingPKCS5");
        put("Cipher.AES128/CTR/ISO10126_2","com.canonical.openssl.cipher.AES128withCTRpaddingISO10126_2");
        put("Cipher.AES128/CTR/X9_23","com.canonical.openssl.cipher.AES128withCTRpaddingX9_23");
        put("Cipher.AES128/CTR/ISO7816_4","com.canonical.openssl.cipher.AES128withCTRpaddingISO7816_4");
        put("Cipher.AES192/CTR/NONE","com.canonical.openssl.cipher.AES192withCTRpaddingNONE");
        put("Cipher.AES192/CTR/PKCS7","com.canonical.openssl.cipher.AES192withCTRpaddingPKCS7");
        put("Cipher.AES192/CTR/PKCS5","com.canonical.openssl.cipher.AES192withCTRpaddingPKCS5");
        put("Cipher.AES192/CTR/ISO10126_2","com.canonical.openssl.cipher.AES192withCTRpaddingISO10126_2");
        put("Cipher.AES192/CTR/X9_23","com.canonical.openssl.cipher.AES192withCTRpaddingX9_23");
        put("Cipher.AES192/CTR/ISO7816_4","com.canonical.openssl.cipher.AES192withCTRpaddingISO7816_4");
        put("Cipher.AES256/CTR/NONE","com.canonical.openssl.cipher.AES256withCTRpaddingNONE");
        put("Cipher.AES256/CTR/PKCS7","com.canonical.openssl.cipher.AES256withCTRpaddingPKCS7");
        put("Cipher.AES256/CTR/PKCS5","com.canonical.openssl.cipher.AES256withCTRpaddingPKCS5");
        put("Cipher.AES256/CTR/ISO10126_2","com.canonical.openssl.cipher.AES256withCTRpaddingISO10126_2");
        put("Cipher.AES256/CTR/X9_23","com.canonical.openssl.cipher.AES256withCTRpaddingX9_23");
        put("Cipher.AES256/CTR/ISO7816_4","com.canonical.openssl.cipher.AES256withCTRpaddingISO7816_4");
        put("Cipher.AES128/CCM/NONE","com.canonical.openssl.cipher.AES128withCCMpaddingNONE");
        put("Cipher.AES128/CCM/PKCS7","com.canonical.openssl.cipher.AES128withCCMpaddingPKCS7");
        put("Cipher.AES128/CCM/PKCS5","com.canonical.openssl.cipher.AES128withCCMpaddingPKCS5");
        put("Cipher.AES128/CCM/ISO10126_2","com.canonical.openssl.cipher.AES128withCCMpaddingISO10126_2");
        put("Cipher.AES128/CCM/X9_23","com.canonical.openssl.cipher.AES128withCCMpaddingX9_23");
        put("Cipher.AES128/CCM/ISO7816_4","com.canonical.openssl.cipher.AES128withCCMpaddingISO7816_4");
        put("Cipher.AES256/CCM/NONE","com.canonical.openssl.cipher.AES256withCCMpaddingNONE");
        put("Cipher.AES256/CCM/PKCS7","com.canonical.openssl.cipher.AES256withCCMpaddingPKCS7");
        put("Cipher.AES256/CCM/PKCS5","com.canonical.openssl.cipher.AES256withCCMpaddingPKCS5");
        put("Cipher.AES256/CCM/ISO10126_2","com.canonical.openssl.cipher.AES256withCCMpaddingISO10126_2");
        put("Cipher.AES256/CCM/X9_23","com.canonical.openssl.cipher.AES256withCCMpaddingX9_23");
        put("Cipher.AES256/CCM/ISO7816_4","com.canonical.openssl.cipher.AES256withCCMpaddingISO7816_4");
        put("Cipher.AES192/CCM/NONE","com.canonical.openssl.cipher.AES192withCCMpaddingNONE");
        put("Cipher.AES192/CCM/PKCS7","com.canonical.openssl.cipher.AES192withCCMpaddingPKCS7");
        put("Cipher.AES192/CCM/PKCS5","com.canonical.openssl.cipher.AES192withCCMpaddingPKCS5");
        put("Cipher.AES192/CCM/ISO10126_2","com.canonical.openssl.cipher.AES192withCCMpaddingISO10126_2");
        put("Cipher.AES192/CCM/X9_23","com.canonical.openssl.cipher.AES192withCCMpaddingX9_23");
        put("Cipher.AES192/CCM/ISO7816_4","com.canonical.openssl.cipher.AES192withCCMpaddingISO7816_4");
        put("Cipher.AES128/GCM/NONE","com.canonical.openssl.cipher.AES128withGCMpaddingNONE");
        put("Cipher.AES128/GCM/PKCS7","com.canonical.openssl.cipher.AES128withGCMpaddingPKCS7");
        put("Cipher.AES128/GCM/PKCS5","com.canonical.openssl.cipher.AES128withGCMpaddingPKCS5");
        put("Cipher.AES128/GCM/ISO10126_2","com.canonical.openssl.cipher.AES128withGCMpaddingISO10126_2");
        put("Cipher.AES128/GCM/X9_23","com.canonical.openssl.cipher.AES128withGCMpaddingX9_23");
        put("Cipher.AES128/GCM/ISO7816_4","com.canonical.openssl.cipher.AES128withGCMpaddingISO7816_4");
        put("Cipher.AES192/GCM/NONE","com.canonical.openssl.cipher.AES192withGCMpaddingNONE");
        put("Cipher.AES192/GCM/PKCS7","com.canonical.openssl.cipher.AES192withGCMpaddingPKCS7");
        put("Cipher.AES192/GCM/PKCS5","com.canonical.openssl.cipher.AES192withGCMpaddingPKCS5");
        put("Cipher.AES192/GCM/ISO10126_2","com.canonical.openssl.cipher.AES192withGCMpaddingISO10126_2");
        put("Cipher.AES192/GCM/X9_23","com.canonical.openssl.cipher.AES192withGCMpaddingX9_23");
        put("Cipher.AES192/GCM/ISO7816_4","com.canonical.openssl.cipher.AES192withGCMpaddingISO7816_4");
        put("Cipher.AES256/GCM/NONE","com.canonical.openssl.cipher.AES256withGCMpaddingNONE");
        put("Cipher.AES256/GCM/PKCS7","com.canonical.openssl.cipher.AES256withGCMpaddingPKCS7");
        put("Cipher.AES256/GCM/PKCS5","com.canonical.openssl.cipher.AES256withGCMpaddingPKCS5");
        put("Cipher.AES256/GCM/ISO10126_2","com.canonical.openssl.cipher.AES256withGCMpaddingISO10126_2");
        put("Cipher.AES256/GCM/X9_23","com.canonical.openssl.cipher.AES256withGCMpaddingX9_23");
        put("Cipher.AES256/GCM/ISO7816_4","com.canonical.openssl.cipher.AES256withGCMpaddingISO7816_4");
    }
}
