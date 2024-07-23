package com.canonical.openssl.kdf;

import com.canonical.openssl.util.NativeLibraryLoader;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.SecretKeyFactorySpi;

/* Source: BouncyCastle User Guide
 * URL: https://downloads.bouncycastle.org/fips-java/docs/BC-FJA-UserGuide-1.0.2.pdf
 * Quote:
 *  "KDFs are currently not directly exposed in the JCE/JCA layer,
 *   although they are made use of internally by algorithms like
 *   Diffe-Hellman and also by the JSSE. They can be invoked directly
 *   using the low-level API."
 */

/* At the C level, the prototype implements PBKDF2 and HKDF. The latter
 * HMAC-based KDF does not fit into any JCE/JCA API. The former, PBKDF2,
 * could be provided using the SecretKeyFactory API because its key spec
 * can be represented by class PBEKeySpec. As a result, only PBKDF2
 * is implemented in this prototype.
 */
public class OpenSSLPBKDF2 extends SecretKeyFactorySpi {

    static {
        NativeLibraryLoader.load();
    }

    public class PBKDF2SecretKey implements PBEKey {
        char[] password;
        byte[] salt;
        int iterationCount;

        byte[] keyBytes;

        public PBKDF2SecretKey(char[] password, byte[] salt, int iterationCount) {
            this.password = password;
            this.salt = salt;
            this.iterationCount = iterationCount;
        }

        public int getIterationCount() {
            return iterationCount;
        }

        public char[] getPassword() {
            return password;
        }

        public byte[] getSalt() {
            return salt;
        }

        public void setEncoded(byte[] keyBytes) {
            this.keyBytes = keyBytes;
        }

        public byte[] getEncoded() {
            return keyBytes;
        }

        public String getFormat() {
            // TODO: what's the right format here?
            return null;
        }

        public String getAlgorithm() {
            return "PBKDF2-SHA512";
        }
    }

    protected SecretKey engineGenerateSecret(KeySpec keyspec) throws InvalidKeySpecException {
        if (keyspec instanceof PBEKeySpec pbeKeySpec) {
            PBKDF2SecretKey secretKey = new PBKDF2SecretKey(pbeKeySpec.getPassword(),
                                    pbeKeySpec.getSalt(), pbeKeySpec.getIterationCount());
            byte[] secretBytes = generateSecret0(pbeKeySpec.getPassword(), pbeKeySpec.getSalt(),
                                                pbeKeySpec.getIterationCount());
            secretKey.setEncoded(secretBytes);
            return secretKey;
        } else {
            throw new InvalidKeySpecException("Invalid KeySpec type, should be PBEKeySpec");
        }
    }

    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException {
        // TODO: this is quite half-hearted :-/
        if (keySpec.isAssignableFrom(PBEKeySpec.class) && key instanceof PBEKey pbeKey) {
            return new PBEKeySpec(pbeKey.getPassword(), pbeKey.getSalt(), pbeKey.getIterationCount());
        }
        throw new InvalidKeySpecException("Given key is not representable by " + keySpec);
    }

    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        if (key instanceof PBEKey pbeKey) {
            PBKDF2SecretKey secretKey = new PBKDF2SecretKey(pbeKey.getPassword(), pbeKey.getSalt(),
                                                            pbeKey.getIterationCount()); 
            byte[] secretBytes = generateSecret0(pbeKey.getPassword(), pbeKey.getSalt(), pbeKey.getIterationCount());
            secretKey.setEncoded(secretBytes);
            return secretKey;
        } else {
            throw new InvalidKeyException("A key of type PBEKey is expected, given " + key.getClass() + " instead");
        }
    }

    private native byte[] generateSecret0(char[] password, byte[] salt, int iterationCount); 
}
