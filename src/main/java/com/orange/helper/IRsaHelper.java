package com.orange.helper;

import com.orange.exception.EncryptException;

/**
 * Created by fqsq3375 on 19/01/2017.
 */
public interface IRsaHelper {

    String RSA_CIPHER_TYPE = "RSA";

    /**
     * Method to encrypt a string by a rsaKey in string
     *
     * @param stringToEncrypt the key in string
     * @param rsaPrivateKeyPath the absolute path of the publicKey
     * @return the aes encrypt key
     */
    String DecryptRsaKey(String stringToEncrypt, String rsaPrivateKeyPath) throws EncryptException;
}
