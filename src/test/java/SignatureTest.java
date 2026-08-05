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
import com.canonical.openssl.key.OpenSSLPublicKey;
import com.canonical.openssl.key.OpenSSLPrivateKey;
import com.canonical.openssl.key.KeyConverter;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

import org.junit.Test;
import org.junit.BeforeClass;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.fail;

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
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "OpenSSLFIPSProvider");
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
    public void testRSAwithEncodedKeys() throws Exception {
        // Keys taken straight from the KeyPairGenerator are opaque encoded
        // keys; the Signature engine must accept them without an explicit
        // KeyConverter step.
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "OpenSSLFIPSProvider");
        gen.initialize(2048);
        KeyPair kp = gen.generateKeyPair();

        Signature signer = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        signer.initSign(kp.getPrivate());
        byte[] bytes = message.getBytes();
        signer.update(bytes, 0, bytes.length);
        byte[] sigBytes = signer.sign();

        Signature verifier = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        verifier.initVerify(kp.getPublic());
        verifier.update(bytes, 0, bytes.length);

        assertTrue("SignatureTest with encoded keys failed.", verifier.verify(sigBytes));
    }

    @Test
    public void testRSAwithMixedKeys() throws Exception {
        // Both key representations must interoperate: sign with a
        // native-handle key and verify with the encoded key, and vice versa.
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "OpenSSLFIPSProvider");
        KeyPair kp = gen.generateKeyPair();
        PrivateKey nativePrivateKey = new RSAPrivateKey(KeyConverter.privateKeyToEVPKey(kp.getPrivate()));
        PublicKey nativePublicKey = new RSAPublicKey(KeyConverter.publicKeyToEVPKey(kp.getPublic()));
        byte[] bytes = message.getBytes();

        Signature signer = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        signer.initSign(nativePrivateKey);
        signer.update(bytes, 0, bytes.length);
        byte[] sigBytes = signer.sign();

        Signature verifier = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        verifier.initVerify(kp.getPublic());
        verifier.update(bytes, 0, bytes.length);
        assertTrue("native-sign/encoded-verify failed.", verifier.verify(sigBytes));

        signer = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        signer.initSign(kp.getPrivate());
        signer.update(bytes, 0, bytes.length);
        sigBytes = signer.sign();

        verifier = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        verifier.initVerify(nativePublicKey);
        verifier.update(bytes, 0, bytes.length);
        assertTrue("encoded-sign/native-verify failed.", verifier.verify(sigBytes));
    }

    @Test
    public void testUnencodablePrivateKeyRejected() throws Exception {
        // A key that is neither OpenSSL-based nor encodable must be rejected
        // with InvalidKeyException rather than a runtime exception.
        Signature signer = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        try {
            signer.initSign(new UnencodablePrivateKey());
            fail("Expected InvalidKeyException for an unencodable private key");
        } catch (InvalidKeyException expected) {
        }
    }

    @Test
    public void testUnencodablePublicKeyRejected() throws Exception {
        Signature verifier = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        try {
            verifier.initVerify(new UnencodablePublicKey());
            fail("Expected InvalidKeyException for an unencodable public key");
        } catch (InvalidKeyException expected) {
        }
    }

    @Test
    public void testWrongKeyAlgorithmRejected() throws Exception {
        // An EC key must not be accepted by an RSA signature: the native layer
        // derives the scheme from the key, so this would otherwise produce an
        // ECDSA signature from an object advertising RSAwithSHA256.
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "OpenSSLFIPSProvider");
        KeyPair kp = gen.generateKeyPair();

        Signature signer = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        try {
            signer.initSign(kp.getPrivate());
            fail("Expected InvalidKeyException for an EC private key on RSAwithSHA256");
        } catch (InvalidKeyException expected) {
        }

        Signature verifier = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        try {
            verifier.initVerify(kp.getPublic());
            fail("Expected InvalidKeyException for an EC public key on RSAwithSHA256");
        } catch (InvalidKeyException expected) {
        }
    }

    @Test
    public void testFailedReinitDoesNotBreakPriorState() throws Exception {
        // A rejected re-initialization must not leave a freed native context
        // behind: the previously initialized state stays usable.
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "OpenSSLFIPSProvider");
        KeyPair kp = gen.generateKeyPair();
        byte[] bytes = message.getBytes();

        Signature signer = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        signer.initSign(kp.getPrivate());

        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC", "OpenSSLFIPSProvider");
        try {
            signer.initSign(ecGen.generateKeyPair().getPrivate());
            fail("Expected InvalidKeyException on re-init with an EC key");
        } catch (InvalidKeyException expected) {
        }

        signer.update(bytes, 0, bytes.length);
        byte[] sigBytes = signer.sign();

        Signature verifier = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        verifier.initVerify(kp.getPublic());
        verifier.update(bytes, 0, bytes.length);
        assertTrue("Signature after a failed re-init failed to verify.", verifier.verify(sigBytes));
    }

    @Test
    public void testThrowingPrivateKeyRejected() throws Exception {
        // A key whose getEncoded() throws (e.g. a destroyed key) must surface as
        // InvalidKeyException, not as an unchecked exception.
        Signature signer = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        try {
            signer.initSign(new ThrowingPrivateKey());
            fail("Expected InvalidKeyException for a key whose getEncoded() throws");
        } catch (InvalidKeyException expected) {
        }
    }

    @Test
    public void testRSAwithMultipleUpdates() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "OpenSSLFIPSProvider");
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
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "OpenSSLFIPSProvider");
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
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "OpenSSLFIPSProvider");
        gen.initialize(4096);
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
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "OpenSSLFIPSProvider");
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
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "OpenSSLFIPSProvider");
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
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "OpenSSLFIPSProvider");
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

class UnencodablePrivateKey extends TestKey implements PrivateKey {
    // Reports RSA so it reaches the conversion path; getEncoded() returns null,
    // so the key cannot be converted.
    @Override
    public String getAlgorithm() {
        return "RSA";
    }
}

class UnencodablePublicKey extends TestKey implements PublicKey {
    @Override
    public String getAlgorithm() {
        return "RSA";
    }
}

class ThrowingPrivateKey extends TestKey implements PrivateKey {
    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    @Override
    public byte[] getEncoded() {
        throw new IllegalStateException("key has been destroyed");
    }
}
