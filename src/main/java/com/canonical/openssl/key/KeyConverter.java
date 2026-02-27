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
package com.canonical.openssl.key;
import com.canonical.openssl.util.NativeLibraryLoader;
import java.security.PrivateKey;
import java.security.PublicKey;
/**
 * Utility class for converting Java Key objects to OpenSSL EVP_PKEY handles.
 * 
 * This class provides FIPS-safe conversion using OpenSSL 3.x OSSL_DECODER API,
 * which properly routes through the FIPS provider and avoids direct key structure
 * manipulation that could violate FIPS boundaries.
 * 
 * Supported key types:
 * - RSA
 * - EC (including Ed25519, Ed448)
 * - DH
 * 
 * The converter handles two scenarios:
 * 1. OpenSSLKey instances (already have native handles)
 * 2. Standard Java Key instances (converted via DER encoding + OSSL_DECODER)
 */
public class KeyConverter {
    static {
        NativeLibraryLoader.load();
    }
    /**
     * Convert a Java PrivateKey to an OpenSSL EVP_PKEY handle.
     * 
     * @param key The private key to convert
     * @return Native EVP_PKEY pointer as long, or 0 on failure
     * @throws IllegalArgumentException if key is null or cannot be encoded
     */
    public static long privateKeyToEVPKey(PrivateKey key) {
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }
        // Fast path: if already an OpenSSL key, just return the handle
        if (key instanceof OpenSSLPrivateKey) {
            return ((OpenSSLPrivateKey) key).getNativeKeyHandle();
        }
        // Standard Java key: encode to DER and decode via OSSL_DECODER
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new IllegalArgumentException("Key does not support encoding");
        }
        return privateKeyToEVPKey0(encoded);
    }
    /**
     * Convert a Java PublicKey to an OpenSSL EVP_PKEY handle.
     * 
     * @param key The public key to convert
     * @return Native EVP_PKEY pointer as long, or 0 on failure
     * @throws IllegalArgumentException if key is null or cannot be encoded
     */
    public static long publicKeyToEVPKey(PublicKey key) {
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }
        // Fast path: if already an OpenSSL key, just return the handle
        if (key instanceof OpenSSLPublicKey) {
            return ((OpenSSLPublicKey) key).getNativeKeyHandle();
        }
        // Standard Java key: encode to DER and decode via OSSL_DECODER
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new IllegalArgumentException("Key does not support encoding");
        }
        return publicKeyToEVPKey0(encoded);
    }
    /**
     * Free an EVP_PKEY handle.
     * 
     * IMPORTANT: Only call this if the EVP_PKEY was created by this converter.
     * Do NOT call this on handles obtained from OpenSSLKey instances, as those
     * are managed by their owning objects.
     * 
     * @param evpKeyPtr Native EVP_PKEY pointer to free
     */
    public static void freeEVPKey(long evpKeyPtr) {
        if (evpKeyPtr != 0) {
            freeEVPKey0(evpKeyPtr);
        }
    }
    /* Native methods */
    private static native long privateKeyToEVPKey0(byte[] encodedKey);
    private static native long publicKeyToEVPKey0(byte[] encodedKey);
    private static native void freeEVPKey0(long evpKeyPtr);
}
