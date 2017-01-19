package com.orange.helper;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Created by fqsq3375 on 19/01/2017.
 */
public interface IAesHelper {

    String ENCRYPTED = "encrypted_";
    String DECRYPTED = "decrypted_";
    String AES = "AES";
    String BC = "BC";

    ThreadLocal<byte[]> BLOCK = new ThreadLocal<byte[]>() {
        @Override
        protected byte[] initialValue() {
            return new byte[8];
        }
    };

    /**
     * DecryptionFile methode to decrypt a file with a stingkey
     * @param fileToDecrypt the absolute path of the file
     * @param stringKey the key to decrypt the file
     * @throws NoSuchPaddingException padding exception
     * @throws NoSuchAlgorithmException algorithm exception
     * @throws NoSuchProviderException provider exception
     * @throws InvalidKeyException key exception
     */
    void aesDecryptFile(String fileToDecrypt, String stringKey) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException;

    /**
     * Encrypt a file with a secretKey
     *
     * @param fileToEncrypt the absolute path of the file
     * @param key the key to decrypt the file
     * @throws IOException IOException
     * @throws InvalidKeyException key exception
     */
    void aesEncryptFile(String fileToEncrypt, SecretKey key) throws IOException, InvalidKeyException;

    /**
     * Prepare a random secrete key to encrypt
     *
     * @return a secretKey
     */
    SecretKey prepareKey();
}
