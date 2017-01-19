package com.orange;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;


public class Main {
    static private final String ENCRYPTED = "encrypted_";
    static private final String DECRYPTED = "decrypted_";
    static private final String AES = "AES";
    static private final String BC = "BC";

    static private final byte[] BLOCK = new byte[8];

    static private String ENCRYPT = "encrypt";
    static private String DECRYPT = "decrypt";

    // http://stackoverflow.com/questions/5355466/converting-secret-key-into-a-string-and-vice-versa

    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());


        String aesKeyForFutureUse = null;
        System.out.print("process start...");
        String type = null;
        if (args.length >= 1) {
            type = args[0];
        }

        if (type != null && ENCRYPT.equals(type) && args.length == 2){
            System.out.print(ENCRYPT +" process");

            String fileToEncrypt = args[1];

            SecretKey keyAES = prepareKey();
            System.out.print("Encrypt Key : "+ Base64.encodeBase64String(keyAES.getEncoded()));
            if (fileToEncrypt != null && StringUtils.isNotEmpty(fileToEncrypt)) {
                File file = new File(fileToEncrypt);
                try {
                    aesEncryptFile(fileToEncrypt, keyAES);

                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (NoSuchProviderException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                }


            } else if (type != null && DECRYPT.equals(type) && args.length == 4){
                System.out.print(DECRYPT +" process");
                String fileToDecrypt = args[1];
                String aesStringKey = args[2];
                String rsaPrivateKeyPath = args[3];

                PrivateKey privateKey = null;
                if (StringUtils.isNotEmpty(rsaPrivateKeyPath)) {
                    try {
                        privateKey = loadPrivateKey(rsaPrivateKeyPath);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

                try {
                    aesDecryptFile(fileToDecrypt, aesStringKey);
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (NoSuchProviderException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                }


            } else{
                System.out.print("pas de fichiers à encrypter");
            }
        }

    }

    static PrivateKey loadPrivateKey(String filename)
            throws Exception {

        byte[] keyBytes = null;
        if (StringUtils.isNotEmpty(filename)) {
            keyBytes = Files.readAllBytes(new File(filename).toPath());

        }
        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    static SecretKey stringToSecretKey(String stringKey){
        byte[] encodedKey     = Base64.decodeBase64(stringKey);
        SecretKey originalKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, AES);
        return originalKey;
    }

    static void aesEncryptFile(String fileToEncrypt, SecretKey key) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        Cipher c = null;
        c = Cipher.getInstance(AES, BC);
        c.init(Cipher.ENCRYPT_MODE, key);

        FileInputStream fis = null;
        FileOutputStream fos = null;

            fos = new FileOutputStream(fileToEncrypt + "_easCrypted");
            fis = new FileInputStream(fileToEncrypt);

        CipherOutputStream cos = null;
        if (fos != null) {
            cos = new CipherOutputStream(fos, c);
        }

        if (cos != null) {
            int i;
                while ((i = fis.read(BLOCK)) != -1) {
                    cos.write(BLOCK, 0, i);
                }
                cos.close();
        }
            fis.close();
            fos.close();
    }

    static void aesDecryptFile(String fileToDecrypt, String stringKey) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {

        //generate key from stringKey
        SecretKey key = null;
        if (StringUtils.isNotBlank(stringKey)) {
           key = stringToSecretKey(stringKey);
        }

        Cipher cipher = Cipher.getInstance(AES, BC);
        cipher.init(Cipher.DECRYPT_MODE, key);

        FileInputStream fis = new FileInputStream(fileToDecrypt);
        CipherInputStream cis = new CipherInputStream(fis, cipher);
        FileOutputStream fos = new FileOutputStream(fileToDecrypt.replace(ENCRYPTED, DECRYPTED));

        int i;
                while ((i = cis.read(BLOCK)) != -1) {
            fos.write(BLOCK, 0, i);
            }
        fos.close();
        fis.close();
    }

    static SecretKey prepareKey() {
        // prepare key
        SecretKey aesKey = null;
        KeyGenerator keygen = null;
        try {
            keygen = KeyGenerator.getInstance(AES, BC);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        if (null != keygen) {
            aesKey = keygen.generateKey();

        }
        return aesKey;
    }
}
