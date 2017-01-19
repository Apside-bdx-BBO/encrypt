package com.orange.helper.impl;

import com.orange.helper.IAesHelper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Created by fqsq3375 on 19/01/2017.
 */
public class AesHelper implements IAesHelper {

    private static Cipher cipher;
    static {
        try {
            cipher = Cipher.getInstance(AES, BC);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    public void aesDecryptFile(String fileToDecrypt, String stringKey) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {

        //generate key from stringKey
        SecretKey key = null;
        if (StringUtils.isNotBlank(stringKey)) {
            key = stringToSecretKey(stringKey);
        }


        cipher.init(Cipher.DECRYPT_MODE, key);

        FileInputStream fis = new FileInputStream(fileToDecrypt);
        CipherInputStream cis = new CipherInputStream(fis, cipher);
        FileOutputStream fos = new FileOutputStream(fileToDecrypt.replace(ENCRYPTED, DECRYPTED));

        int i;
        while ((i = cis.read(BLOCK.get())) != -1) {
            fos.write(BLOCK.get(), 0, i);
        }
        fos.close();
        fis.close();
    }

    public SecretKey prepareKey() {
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

    private SecretKey stringToSecretKey(String stringKey){
        byte[] encodedKey     = Base64.decodeBase64(stringKey);
        SecretKey originalKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, AES);
        return originalKey;
    }

    public void aesEncryptFile(String fileToEncrypt, SecretKey key) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException {
        cipher.init(Cipher.ENCRYPT_MODE, key);

        FileInputStream fis = null;
        FileOutputStream fos = null;

        fos = new FileOutputStream(fileToEncrypt + "_easCrypted");
        fis = new FileInputStream(fileToEncrypt);

        CipherOutputStream cos = null;
        if (fos != null) {
            cos = new CipherOutputStream(fos, cipher);
        }

        if (cos != null) {
            int i;
            while ((i = fis.read(BLOCK.get())) != -1) {
                cos.write(BLOCK.get(), 0, i);
            }
            cos.close();
        }
        fis.close();
        fos.close();
    }
}
