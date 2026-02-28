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
import com.canonical.openssl.signature.*;
import com.canonical.openssl.key.OpenSSLKey;
import com.canonical.openssl.key.OpenSSLPublicKey;
import com.canonical.openssl.key.OpenSSLPrivateKey;
import com.canonical.openssl.key.KeyConverter;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.security.spec.AlgorithmParameterSpec;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.Security;
import java.security.Signature;
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

public class SignatureTest {

    static String message = "Apollo is one of the Olympian deities in classical "
         + "Greek and Roman religion and Greek and Roman mythology. Apollo "
         + "has been recognized as a god of archery, music and dance, truth "
         + "and prophecy, healing and diseases, the Sun and light, poetry, "
         + "and more. One of the most important and complex of the Greek gods, "
         + "he is the son of Zeus and Leto, and the twin brother of Artemis, "
         + "goddess of the hunt. He is considered to be the most beautiful "
         + "god and is represented as the ideal of the kouros (ephebe, or a "
         + "beardless, athletic youth). Apollo is known in Greek-influenced "
         + "Etruscan mythology as Apulu.";

    @Test
    public void testRSABasic() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = gen.generateKeyPair();
        PublicKey publicKey = new RSAPublicKey(KeyConverter.publicKeyToEVPKey(kp.getPublic()));
        PrivateKey privateKey = new RSAPrivateKey(KeyConverter.privateKeyToEVPKey(kp.getPrivate()));

        Signature signer = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        signer.initSign(privateKey);
        byte[] bytes = message.getBytes();
        signer.update(bytes, 0, bytes.length);
        byte[] sigBytes = signer.sign();

        Signature verifier = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        verifier.initVerify(publicKey);
        verifier.update(bytes, 0, bytes.length);

        assertTrue("SignatureTest for RSA failed.", verifier.verify(sigBytes));
    }

    @Test
    public void testRSAwithMultipleUpdates() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(4096);
        KeyPair kp = gen.generateKeyPair();
        PublicKey publicKey = new RSAPublicKey(KeyConverter.publicKeyToEVPKey(kp.getPublic()));
        PrivateKey privateKey = new RSAPrivateKey(KeyConverter.privateKeyToEVPKey(kp.getPrivate()));

        Signature signer = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        signer.initSign(privateKey);
        byte[] bytes = message.getBytes();
        signer.update(bytes, 0, bytes.length);
        signer.update(bytes, 2, bytes.length-2);
        signer.update(bytes, 3, bytes.length-3); 
        byte[] sigBytes = signer.sign();

        Signature verifier = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        verifier.initVerify(publicKey);
        verifier.update(bytes, 0, bytes.length);
        verifier.update(bytes, 2, bytes.length-2);
        verifier.update(bytes, 3, bytes.length-3);

        assertTrue("SignatureTest with multiple updates for RSA failed.", verifier.verify(sigBytes));
    }

    @Test
    public void testRSAsingleByteUpdates() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = gen.generateKeyPair();
        PublicKey publicKey = new RSAPublicKey(KeyConverter.publicKeyToEVPKey(kp.getPublic()));
        PrivateKey privateKey = new RSAPrivateKey(KeyConverter.privateKeyToEVPKey(kp.getPrivate()));

        Signature signer = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        signer.initSign(privateKey);
        byte[] bytes = message.getBytes();

        for (var b : bytes) {
            signer.update(b);
        }
        byte[] sigBytes = signer.sign();

        Signature verifier = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        verifier.initVerify(publicKey);
        verifier.update(bytes, 0, bytes.length);

        assertTrue("RSA SignatureTest with byte updates failed.", verifier.verify(sigBytes));
    }

    @Test
    public void testRSAmultipleByteBufferUpdates() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(8192);
        KeyPair kp = gen.generateKeyPair();
        PublicKey publicKey = new RSAPublicKey(KeyConverter.publicKeyToEVPKey(kp.getPublic()));
        PrivateKey privateKey = new RSAPrivateKey(KeyConverter.privateKeyToEVPKey(kp.getPrivate()));

        Signature signer = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        signer.initSign(privateKey);
        byte[] bytes = message.getBytes();
        signer.update(ByteBuffer.wrap(message.getBytes()));
        byte[] sigBytes = signer.sign();

        Signature verifier = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        verifier.initVerify(publicKey);
        verifier.update(bytes, 0, bytes.length);

        assertTrue("RSA SignatureTest with ByteBuffer updates failed.", verifier.verify(sigBytes));
    }

    @Test
    public void testRSAsignNonzeroOffset() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(4096);
        KeyPair kp = gen.generateKeyPair();
        PublicKey publicKey = new RSAPublicKey(KeyConverter.publicKeyToEVPKey(kp.getPublic()));
        PrivateKey privateKey = new RSAPrivateKey(KeyConverter.privateKeyToEVPKey(kp.getPrivate()));

        byte[] sigBytes = new byte[612];
        Signature signer = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        signer.initSign(privateKey);
        byte[] bytes = message.getBytes();
        signer.update(ByteBuffer.wrap(message.getBytes()));
        signer.sign(sigBytes, 100, 512);

        Signature verifier = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        verifier.initVerify(publicKey);
        verifier.update(bytes, 0, bytes.length);

        assertTrue("RSA SignatureTest with non-zero offset failed.", verifier.verify(sigBytes, 100, 512));
    }

    @Test
    public void testRSAtamperedSignature() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = gen.generateKeyPair();
        PublicKey publicKey = new RSAPublicKey(KeyConverter.publicKeyToEVPKey(kp.getPublic()));
        PrivateKey privateKey = new RSAPrivateKey(KeyConverter.privateKeyToEVPKey(kp.getPrivate()));

        Signature signer = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        signer.initSign(privateKey);
        byte[] bytes = message.getBytes();

        for (var b : bytes) {
            signer.update(b);
        }
        byte[] sigBytes = signer.sign();

        Signature verifier = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        verifier.initVerify(publicKey);
        verifier.update(bytes, 0, bytes.length);

        // tamper signature
        sigBytes[0] += 1;

        assertFalse("RSA SignatureTest with tampered signature failed.", verifier.verify(sigBytes));
    }

    @Test
    public void testRSAtamperedContent() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = gen.generateKeyPair();
        PublicKey publicKey = new RSAPublicKey(KeyConverter.publicKeyToEVPKey(kp.getPublic()));
        PrivateKey privateKey = new RSAPrivateKey(KeyConverter.privateKeyToEVPKey(kp.getPrivate()));


        Signature signer = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        signer.initSign(privateKey);
        byte[] bytes = message.getBytes();

        for (var b : bytes) {
            signer.update(b);
        }
        byte[] sigBytes = signer.sign();

        // tamper content
        bytes[0] += 1;
        Signature verifier = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        verifier.initVerify(publicKey);
        verifier.update(bytes, 0, bytes.length);

        assertFalse("RSA SignatureTest with tampered content failed.", verifier.verify(sigBytes));
    }

    @BeforeClass
    public static void addProvider() throws Exception {
        Security.addProvider(new OpenSSLFIPSProvider());
    }
}

class TestKey {
    public byte[] getEncoded() {
        return null;
    }

    public String getFormat() {
        return null;
    }

    public String getAlgorithm() {
        return "";
    }
}

class RSAPublicKey extends TestKey implements OpenSSLPublicKey {
    long nativeKey = 0L;

    public RSAPublicKey(long nativeKey) {
        this.nativeKey = nativeKey;
    }

    public long getNativeKeyHandle() {
        return nativeKey; 
    }
}

class RSAPrivateKey extends TestKey implements OpenSSLPrivateKey {
    long nativeKey = 0L;

    public RSAPrivateKey(long nativeKey) {
        this.nativeKey = nativeKey;
    }

    public long getNativeKeyHandle() {
        return nativeKey;
    }
}
