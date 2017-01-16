package com.orange;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.security.NoSuchAlgorithmException;

public class Main {

    public static void main(String[] args) {
        String fileToEncrypt = null;
        System.out.print("test");
        if (args.length >= 2) {
            fileToEncrypt = args[0];
        }
        if (args.length >= 1) {
            String type = args[1];
        }
        if (fileToEncrypt != null && StringUtils.isNotEmpty(fileToEncrypt)) {
            File file = new File(fileToEncrypt);
        } else {
            System.out.print("pas de fichiers à encrypter");

        }
    }

    private String encryptionKey;


    public String encrypt(String plainText) throws Exception {
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE);
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes());

        return Base64.encodeBase64String(encryptedBytes);
    }

    public String decrypt(String encrypted) throws Exception {
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE);
        byte[] plainBytes = cipher.doFinal(Base64.decodeBase64(encrypted));

        return new String(plainBytes);
    }

    private Cipher getCipher(int cipherMode)
            throws Exception {
        String encryptionAlgorithm = "AES";
        SecretKeySpec keySpecification = new SecretKeySpec(
                encryptionKey.getBytes("UTF-8"), encryptionAlgorithm);
        Cipher cipher = Cipher.getInstance(encryptionAlgorithm);
        cipher.init(cipherMode, keySpecification);

        return cipher;
    }

    String prepareKey() {
        // prepare key
        String aesKeyForFutureUse = null;
        KeyGenerator keygen = null;
        try {
            keygen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        if (null != keygen) {
            SecretKey aesKey = keygen.generateKey();
            aesKeyForFutureUse = Base64.encodeBase64String(aesKey.getEncoded());
        }
        return aesKeyForFutureUse;
    }
}
