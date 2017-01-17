package com.orange;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class Main {
    static private String ENCRYPT = "encrypt";
    static private String DECRYPT = "decrypt";

    // http://stackoverflow.com/questions/5355466/converting-secret-key-into-a-string-and-vice-versa

    public static void main(String[] args) {
        String fileToEncrypt = null;
        String aesKeyForFutureUse = null;
        System.out.print("test");
        String type = null;
        if (args.length >= 2) {
            fileToEncrypt = args[1];
        }
        if (args.length >= 1) {
            type = args[0];
        }

        if (type != null && ENCRYPT.equals(type)){
            SecretKey keyAES = prepareKey();
            System.out.print("Encrypt Key : "+ Base64.encodeBase64String(keyAES.getEncoded()));
            if (fileToEncrypt != null && StringUtils.isNotEmpty(fileToEncrypt)) {
                File file = new File(fileToEncrypt);
                encryptFile(fileToEncrypt, keyAES);
            } else {
                System.out.print("pas de fichiers à encrypter");
            }
        }

    }

    private String encryptionKey;


    static void encryptFile(String fileToEncrypt, SecretKey key){
        Cipher c = null;
        try {
            c = Cipher.getInstance("DES/CFB8/NoPadding");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
        try {
            c.init(Cipher.ENCRYPT_MODE, key);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        CipherOutputStream cos = null;
        try {
            cos = new CipherOutputStream( new FileOutputStream(new File(fileToEncrypt)), c);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        PrintWriter pw = new PrintWriter(new OutputStreamWriter(cos));
        pw.println("Stand and unfold yourself");
        pw.close();
        oos.writeObject(c.getIV());
        oos.close();
    }

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

    static SecretKey prepareKey() {
        // prepare key
        SecretKey aesKey = null;
        KeyGenerator keygen = null;
        try {
            keygen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        if (null != keygen) {
            aesKey = keygen.generateKey();

        }
        return aesKey;
    }
}
