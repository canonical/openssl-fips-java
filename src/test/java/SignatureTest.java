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
import java.security.PublicKey;
import java.security.PrivateKey;
import java.util.Arrays;
import java.nio.ByteBuffer;
import java.security.spec.AlgorithmParameterSpec;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
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

public class SignatureTest {
    static {
        System.loadLibrary("sigtest");
    }

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
    public void testRSA() throws Exception {
        RSAKeyPairGenerator gen = new RSAKeyPairGenerator();
        gen.generateKeyPair();
        testSignature("RSA", gen.pubKey, gen.privKey);
    }

    @Test
    public void testED25519() throws Exception {
        EdDSAPublicKey publicKey = new EdDSAPublicKey("src/test/keys/ed25519-pub.pem");
        EdDSAPrivateKey privateKey = new EdDSAPrivateKey("src/test/keys/ed25519-priv.pem");
        testSignature("ED25519", publicKey, privateKey);
    }

    @Test
    public void testED448() throws Exception {
        EdDSAPublicKey publicKey = new EdDSAPublicKey("src/test/keys/ed448-pub.pem");
        EdDSAPrivateKey privateKey = new EdDSAPrivateKey("src/test/keys/ed448-priv.pem");
        testSignature("ED448", publicKey, privateKey);
    }

    private static void testSignature(String algo,  PublicKey publicKey, PrivateKey privateKey) throws Exception {
        Signature signer = Signature.getInstance(algo, "OpenSSLFIPSProvider");
        if (algo.equals("RSA")) {
            signer.setParameter("digest", "SHA-256"); // TODO: why does this work only with SHA-256? 
        }
        signer.initSign(privateKey);
        byte[] bytes = message.getBytes();
        signer.update(bytes, 0, bytes.length);
        byte[] sigBytes = signer.sign();

        Signature verifier = Signature.getInstance(algo, "OpenSSLFIPSProvider");
        if (algo.equals("RSA")) {
            verifier.setParameter("digest", "SHA-256");
        }
        verifier.initVerify(publicKey);
        verifier.update(bytes, 0, bytes.length);
        assertTrue("SignatureTest for " + algo + " failed.", verifier.verify(sigBytes));
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
 
class EdDSAPublicKey extends TestKey implements OpenSSLPublicKey {
   long nativeKey = 0L; 
   public long getNativeKeyHandle() {
       return nativeKey;
   }

   EdDSAPublicKey(String filename) {
       nativeKey = readPubKeyFromPem0(filename);
   }

   native long readPubKeyFromPem0(String filename);
}

class EdDSAPrivateKey extends TestKey implements OpenSSLPrivateKey {
    long nativeKey = 0L;
    public long getNativeKeyHandle() {
        return nativeKey; 
    }

    EdDSAPrivateKey(String filename) {
        nativeKey = readPrivKeyFromPem0(filename);
    }

    native long readPrivKeyFromPem0(String filename);
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

class RSAKeyPairGenerator {
    long nativePrivKey = 0;
    long nativePubKey = 0;

    RSAPrivateKey privKey;
    RSAPublicKey pubKey;

    public void generateKeyPair() {
        generateKeyPair0();
        privKey = new RSAPrivateKey(nativePrivKey);
        pubKey = new RSAPublicKey(nativePubKey);
    }

    private native void generateKeyPair0();
}
