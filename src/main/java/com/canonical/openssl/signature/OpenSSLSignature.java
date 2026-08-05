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
package com.canonical.openssl.signature;

import com.canonical.openssl.key.*;
import com.canonical.openssl.util.NativeMemoryCleaner;
import com.canonical.openssl.util.NativeLibraryLoader;

import java.lang.ref.Cleaner;
import java.util.concurrent.atomic.AtomicLong;
import java.nio.ByteBuffer;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;

/* This implementation will be exercised by the user through the
 * java.security.Signature API which isn't marked thread-safe.
 * This implementation is also NOT thread-safe and applications need
 * handle thread-safety concerns if need be.
 */
public abstract class OpenSSLSignature extends SignatureSpi {

    static {
        NativeLibraryLoader.load();    
    }

    private static class SignatureState implements Runnable {
        private final AtomicLong nativeHandle;

        SignatureState(long handle) {
            this.nativeHandle = new AtomicLong(handle);
        }

        @Override
        public void run() {
            long handle = nativeHandle.getAndSet(0);
            if (handle != 0) cleanupNativeMemory(handle);
        }
    }
    private long nativeHandle = 0L;

    private static Cleaner cleaner = NativeMemoryCleaner.cleaner;
    private Cleaner.Cleanable cleanable;

    private Params params = new Params(null, -1, Padding.NONE, null);;

    protected static enum Padding { NONE, PSS };

    protected static class Params {

        static final int NO_PADDING = 0;
        static final int PSS_PADDING = 1;

        String digest;
        int saltLength;
        int padding;
        String mgf1Digest;

        public Params(String digest, int saltLength, Padding padding, String mgf1Digest) {
            this.digest = digest;
            this.saltLength = saltLength;
            this.padding = (padding == Padding.NONE ? NO_PADDING : PSS_PADDING); 
            this.mgf1Digest = mgf1Digest;
        }

        public String getDigest() {
            return this.digest;
        }

        public int getSaltLength() {
            return this.saltLength;
        }

        public String getMgf1Digest() {
            return this.mgf1Digest;
        }

        public int getPadding() {
            return padding;
        }
    }

    protected OpenSSLSignature(Params params) {
        this.params = params;
    }

    protected abstract String getSignatureName();

    /**
     * The key algorithm this signature works with, as reported by
     * {@link java.security.Key#getAlgorithm()}. Derived from the signature name
     * by stripping the digest suffix ("RSAwithSHA256" -&gt; "RSA"), which covers
     * every signature currently registered by this provider.
     */
    protected String getKeyAlgorithm() {
        String name = getSignatureName();
        int index = name.toLowerCase().indexOf("with");
        return index > 0 ? name.substring(0, index) : name;
    }

    /*
     * The native layer derives the signature scheme from the key's own type
     * (EVP_DigestSignInit_ex uses the EVP_PKEY's keymgmt), so a key of the
     * wrong family would silently produce a signature in a different scheme
     * than the one this SPI advertises. Reject the mismatch up front.
     */
    private void checkKeyAlgorithm(java.security.Key key) throws InvalidKeyException {
        String expected = getKeyAlgorithm();
        String actual = key.getAlgorithm();
        if (actual == null) {
            throw new InvalidKeyException("Key does not report an algorithm; expected " + expected);
        }
        if (expected.equalsIgnoreCase(actual)) {
            return;
        }
        // Ed25519/Ed448 keys are reported as "EdDSA" by some providers.
        if (("ED25519".equalsIgnoreCase(expected) || "ED448".equalsIgnoreCase(expected))
                && "EdDSA".equalsIgnoreCase(actual)) {
            return;
        }
        throw new InvalidKeyException("Key algorithm " + actual + " does not match "
                + getSignatureName() + ", which requires a " + expected + " key");
    }

    @Override
    protected Object engineGetParameter(String param) {
        throw new InvalidParameterException("Legacy getParameter(String) is not supported; use getParameters()");
    }

    @Override
    protected void engineSetParameter(String param, Object value) {
        // supporting only "digest" for now
        // mgf1digest and saltlen are relevant only with PSS padding, but there's
        // issue: https://github.com/pushkarnk/openssl-fips-jni-wrapper/issues/2
        if (param.equals("digest") && value instanceof String digestName) {
            this.params = new Params(digestName, -1, Padding.NONE, null);  
        } 
    }

    @Override
    protected void engineInitSign(PrivateKey key) throws InvalidKeyException {
       if (key == null) {
           throw new InvalidKeyException("Key must not be null");
       }
       OpenSSLPrivateKey privKey;
       boolean converted = false;
       if (key instanceof OpenSSLPrivateKey opensslKey) {
           // Handle is owned by the caller's key object; must not be freed here.
           privKey = opensslKey;
       } else {
           // Accept any key with a PKCS#8 encoding - including this provider's
           // own EncodedPrivateKey - by converting it to a native handle
           // through the FIPS-safe OSSL_DECODER path.
           checkKeyAlgorithm(key);
           long handle = convertPrivateKey(key);
           // Set before publishing the handle so the finally block always frees
           // a handle this method allocated.
           converted = true;
           privKey = new ConvertedPrivateKey(key.getAlgorithm(), handle);
       }
       try {
           // Drop any previous context first, and clear the field so a failed
           // initialization cannot leave a freed handle behind for update()/sign().
           if (cleanable != null) {
               cleanable.clean();
               cleanable = null;
           }
           nativeHandle = 0L;
           try {
               nativeHandle = engineInitSign0(getSignatureName(), privKey, params);
           } catch (ProviderException e) {
               throw new InvalidKeyException("Failed to initialize signature for signing", e);
           }
           if (nativeHandle == 0) {
               throw new InvalidKeyException("Failed to initialize signature for signing");
           }
           cleanable = cleaner.register(this, new SignatureState(nativeHandle));
       } finally {
           // The native signature context acquires its own reference to the
           // key (EVP_PKEY_CTX_new_from_pkey), so a converted handle can be
           // released as soon as initialisation completes.
           if (converted) {
               KeyConverter.freeEVPKey(privKey.getNativeKeyHandle());
           }
       }
    }

    @Override
    protected void engineInitSign(PrivateKey key, SecureRandom random) throws InvalidKeyException {
        // TODO: how does one use the SecureRandom?
        engineInitSign(key);
    }

    @Override
    protected void engineInitVerify(PublicKey key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key must not be null");
        }
        OpenSSLPublicKey pubKey;
        boolean converted = false;
        if (key instanceof OpenSSLPublicKey opensslKey) {
            // Handle is owned by the caller's key object; must not be freed here.
            pubKey = opensslKey;
        } else {
            // Accept any key with an X.509 encoding - including this provider's
            // own EncodedPublicKey - by converting it to a native handle
            // through the FIPS-safe OSSL_DECODER path.
            checkKeyAlgorithm(key);
            long handle = convertPublicKey(key);
            converted = true;
            pubKey = new ConvertedPublicKey(key.getAlgorithm(), handle);
        }
        try {
            // See engineInitSign: clear prior state before re-initializing.
            if (cleanable != null) {
                cleanable.clean();
                cleanable = null;
            }
            nativeHandle = 0L;
            try {
                nativeHandle = engineInitVerify0(getSignatureName(), pubKey, params);
            } catch (ProviderException e) {
                throw new InvalidKeyException("Failed to initialize signature for verification", e);
            }
            if (nativeHandle == 0) {
                throw new InvalidKeyException("Failed to initialize signature for verification");
            }
            cleanable = cleaner.register(this, new SignatureState(nativeHandle));
        } finally {
            // See engineInitSign: converted handles can be released once
            // initialisation completes.
            if (converted) {
                KeyConverter.freeEVPKey(pubKey.getNativeKeyHandle());
            }
        }
    }

    private static long convertPrivateKey(PrivateKey key) throws InvalidKeyException {
        final long handle;
        try {
            handle = KeyConverter.privateKeyToEVPKey(key);
        } catch (RuntimeException e) {
            // Includes IllegalArgumentException for unencodable keys and
            // IllegalStateException from keys that have been destroyed.
            throw new InvalidKeyException(
                    "Unsupported private key type: " + key.getClass().getName(), e);
        }
        if (handle == 0) {
            throw new InvalidKeyException(
                    "Failed to convert private key of type: " + key.getClass().getName());
        }
        return handle;
    }

    private static long convertPublicKey(PublicKey key) throws InvalidKeyException {
        final long handle;
        try {
            handle = KeyConverter.publicKeyToEVPKey(key);
        } catch (RuntimeException e) {
            throw new InvalidKeyException(
                    "Unsupported public key type: " + key.getClass().getName(), e);
        }
        if (handle == 0) {
            throw new InvalidKeyException(
                    "Failed to convert public key of type: " + key.getClass().getName());
        }
        return handle;
    }

    /**
     * A {@link PrivateKey} backed solely by a native {@code EVP_PKEY} handle,
     * used to adapt converted keys for the native signature engine. The adapter
     * itself exposes no encoding; the handle it wraps is owned by the
     * {@code engineInit*} method that created it and is freed there.
     */
    private static final class ConvertedPrivateKey implements OpenSSLPrivateKey {
        private final String algorithm;
        private final long nativeHandle;

        ConvertedPrivateKey(String algorithm, long nativeHandle) {
            this.algorithm = algorithm;
            this.nativeHandle = nativeHandle;
        }

        @Override
        public long getNativeKeyHandle() {
            return nativeHandle;
        }

        @Override
        public String getAlgorithm() {
            return algorithm;
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return null;
        }
    }

    /**
     * Public-key counterpart of {@link ConvertedPrivateKey}.
     */
    private static final class ConvertedPublicKey implements OpenSSLPublicKey {
        private final String algorithm;
        private final long nativeHandle;

        ConvertedPublicKey(String algorithm, long nativeHandle) {
            this.algorithm = algorithm;
            this.nativeHandle = nativeHandle;
        }

        @Override
        public long getNativeKeyHandle() {
            return nativeHandle;
        }

        @Override
        public String getAlgorithm() {
            return algorithm;
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return null;
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        if (params == null || params.padding != Params.PSS_PADDING) {
            return null;
        }
        String mgf1Digest = (params.mgf1Digest != null) ? params.mgf1Digest : params.digest;
        if (mgf1Digest == null) {
            throw new ProviderException("PSS padding is set but no digest has been configured");
        }
        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("RSASSA-PSS");
            ap.init(new PSSParameterSpec(params.digest, "MGF1", new MGF1ParameterSpec(mgf1Digest), params.saltLength, 1));
            return ap;
        } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
            throw new ProviderException("Could not encode PSS AlgorithmParameters", e);
        }
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (params == null) {
            throw new InvalidAlgorithmParameterException("AlgorithmParameterSpec must not be null");
        }
        if (!(params instanceof PSSParameterSpec pss)) {
            throw new InvalidAlgorithmParameterException("Only PSSParameterSpec is supported, got: " + params.getClass().getName());
        }
        if (!"MGF1".equalsIgnoreCase(pss.getMGFAlgorithm())) {
            throw new InvalidAlgorithmParameterException("Only MGF1 is supported for PSS MGF, got: " + pss.getMGFAlgorithm());
        }
        if (pss.getTrailerField() != 1) {
            throw new InvalidAlgorithmParameterException("Only PSS trailerField=1 is supported, got: " + pss.getTrailerField());
        }
        AlgorithmParameterSpec mgfSpec = pss.getMGFParameters();
        if (mgfSpec != null && !(mgfSpec instanceof MGF1ParameterSpec)) {
            throw new InvalidAlgorithmParameterException("Only MGF1 is supported for PSS MGF, got: " + mgfSpec.getClass().getName());
        }
        String mgf1Digest = (mgfSpec != null) ? ((MGF1ParameterSpec) mgfSpec).getDigestAlgorithm() : null;
        this.params = new Params(pss.getDigestAlgorithm(), pss.getSaltLength(), Padding.PSS, mgf1Digest);
    }

    @Override
    protected byte[] engineSign() {
        if (nativeHandle == 0) {
            throw new IllegalStateException("Signature not initialized");
        }
        return engineSign0();
    }

    @Override
    protected int engineSign(byte[] outbuf, int offset, int len) throws SignatureException {
        byte[] sign = engineSign();
        if (len < sign.length) {
            throw new SignatureException("Output buffer too small: need " + sign.length + " bytes, got " + len);
        }
        System.arraycopy(sign, 0, outbuf, offset, sign.length);
        return sign.length;
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        engineUpdate(new byte[] { b }, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if (nativeHandle == 0) {
            throw new IllegalStateException("Signature not initialized");
        }
        if (b == null) {
            throw new NullPointerException("input array must not be null");
        }
        if (off < 0 || len < 0 || off > b.length - len) {
            throw new IllegalArgumentException("Invalid offset/length");
        }
        engineUpdate0(b, off, len);
    }

    @Override
    protected void engineUpdate(ByteBuffer input) {
        if (!input.hasRemaining()) {
            return;
        }
        try {
            if (input.hasArray()) {
                engineUpdate(input.array(), input.arrayOffset() + input.position(), input.remaining());
                input.position(input.limit());
            } else {
                byte[] tmp = new byte[input.remaining()];
                input.get(tmp);
                engineUpdate(tmp, 0, tmp.length);
            }
        } catch (SignatureException se) {
            throw new ProviderException("engineUpdate(ByteBuffer) failed", se);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) {
        return engineVerify(sigBytes, 0, sigBytes.length);
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes, int offset, int length) {
        if (nativeHandle == 0) {
            throw new IllegalStateException("Signature not initialized");
        }
        if (sigBytes == null) {
            throw new NullPointerException("signature bytes must not be null");
        }
        if (offset < 0 || length < 0 || offset > sigBytes.length - length) {
            throw new IllegalArgumentException("Invalid offset/length");
        }
        return engineVerify0(sigBytes, offset, length);
    }

    private static void cleanupNativeMemory(long handle) {
        cleanupNativeMemory0(handle);
    }

    private static native void cleanupNativeMemory0(long handle);
    private native long engineInitSign0(String signatureType, OpenSSLPrivateKey privateKey, Params params);
    private native long engineInitVerify0(String signatureType, OpenSSLPublicKey publicKey, Params params);
    private native byte[] engineSign0();
    private native void engineUpdate0(byte[] input, int offset, int length);
    private native boolean engineVerify0(byte[] sigBytes, int offset, int length);
}
