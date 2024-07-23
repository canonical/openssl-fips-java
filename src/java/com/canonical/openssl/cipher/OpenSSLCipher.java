package com.canonical.openssl.cipher;

import com.canonical.openssl.util.NativeMemoryCleaner;
import com.canonical.openssl.util.NativeLibraryLoader;
import java.lang.ref.Cleaner;
import javax.crypto.CipherSpi;
import javax.crypto.Cipher;
import java.security.Key;
import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import javax.crypto.ShortBufferException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;

abstract public class OpenSSLCipher extends CipherSpi {

    static {
        NativeLibraryLoader.load();
    }

    private static int UNDECIDED = -1;
    private static int DECRYPT = 0;
    private static int ENCRYPT = 1;

    String name;
    String mode;
    String padding;
    long cipherContext;
    byte []keyBytes;
    byte []iv;
    int inputSize;
    int outputSize;
    int opmode = UNDECIDED;
    boolean firstUpdate = true;

    private static class CipherState implements Runnable {
        private long nativeHandle;

        CipherState(long handle) {
            this.nativeHandle = handle;
        }

        @Override
        public void run() {
            cleanupNativeMemory(nativeHandle);
        }
    } 

    private Cleaner cleaner = NativeMemoryCleaner.cleaner;
    private Cleaner.Cleanable cleanable;

    protected OpenSSLCipher(String nameKeySizeAndMode, String padding) {
        this.name = name;
        this.mode = nameKeySizeAndMode.split("-")[2];
        this.padding = padding;
        this.cipherContext = createContext0(nameKeySizeAndMode, padding);
        cleanable = cleaner.register(this, new CipherState(this.cipherContext));
    }

    private boolean isModeCCM() {
        return mode.equals("CCM");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) {
        System.err.println("AlgorithmParameters will be ignored by the prototype");
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) {
        throw new UnsupportedOperationException ("The prototype supports only symmetric-key encrypt/decrypt with IVs");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) {
       if (opmode != Cipher.ENCRYPT_MODE && opmode != Cipher.DECRYPT_MODE && !(params instanceof IvParameterSpec)) {
            throw new UnsupportedOperationException ("The prototype supports only symmetric-key encrypt/decrypt with an IV");
        }
        this.firstUpdate = true;
        this.inputSize = this.outputSize = 0;
        this.opmode = (opmode == Cipher.ENCRYPT_MODE ? ENCRYPT : DECRYPT);
        this.keyBytes = key.getEncoded();
        this.iv = ((IvParameterSpec)params).getIV(); 
        if (!isModeCCM()) {
            doInit0(null, 0, 0, keyBytes, iv, this.opmode);
        }
    }

    @Override
    protected void engineSetMode(String mode) {
        this.mode = mode;
    }

    @Override
    protected void engineSetPadding(String padding) {
        this.padding = padding;
    }

    @Override
    protected byte[] engineUpdate(byte[] bytes, int offset, int length) {
        if (isModeCCM() && firstUpdate) {
            firstUpdate = false;
            doInit0(bytes, offset, length, keyBytes, iv, opmode);
        } 
        inputSize += length; 
        byte[] ret = doUpdate0(bytes, offset, length);
        outputSize += ret.length;
        return ret;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        throw new UnsupportedOperationException("Unimplemented");
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        throw new UnsupportedOperationException("The prototype ignores AlgorithmParameters");
    }

    @Override
    protected byte[] engineGetIV() {
        return iv;
    }

    protected abstract int engineGetOutputSize(int inputLen);

    protected abstract int engineGetBlockSize();

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, 
                                   IllegalBlockSizeException, BadPaddingException {
        throw new UnsupportedOperationException("Not implmenented");
    }

    @Override
    protected byte[] engineDoFinal(byte[] bytes, int offset, int length) throws IllegalBlockSizeException, BadPaddingException {
        if (isModeCCM() && firstUpdate) {
            firstUpdate = false;
            doInit0(bytes, offset, length, keyBytes, iv, opmode);
        }
        byte[] transformed = doUpdate0(bytes, offset, length); 
        return doFinal0(transformed, transformed.length);  
    }

    private static void cleanupNativeMemory(long handle) {
        cleanupNativeMemory0(handle);
    }

    private static native void cleanupNativeMemory0(long handle);

    native long createContext0(String nameAndMode, String padding);
    native void doInit0(byte[] input, int offset, int length, byte[] key, byte[] iv, int opmode);
    native byte[] doUpdate0(byte[] input, int offset, int length);
    native byte[] doFinal0(byte[] output, int length);
}
