package com.orange;

import com.orange.exception.EncryptException;
import com.orange.helper.impl.AesHelper;
import com.orange.helper.impl.RsaHelper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;

import javax.crypto.*;

import static java.lang.System.out;


public class Main {

    static private String ENCRYPT = "encrypt";
    static private String DECRYPT = "decrypt";

    // http://stackoverflow.com/questions/5355466/converting-secret-key-into-a-string-and-vice-versa

    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());


        String aesKeyForFutureUse = null;
        out.print("process start...");
        String type = null;
        if (args.length > 1) {
            type = args[0];
        }

        AesHelper aesHelper = new AesHelper();

        if (type != null && ENCRYPT.equals(type) && args.length == 2){
            out.print(ENCRYPT +" process");
            String fileToEncrypt = args[1];

            SecretKey keyAES = aesHelper.prepareKey();

            out.print("Encrypt Key : "+ Base64.encodeBase64String(keyAES.getEncoded()));
            if (fileToEncrypt != null && StringUtils.isNotEmpty(fileToEncrypt)) {
                try {
                    aesHelper.aesEncryptFile(fileToEncrypt, keyAES);

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
                out.print(DECRYPT +" process");
                String fileToDecrypt = args[1];
                String aesEncryptStringKey = args[2];
                String rsaPrivateKeyPath = args[3];

                String decryptKey = null;

                RsaHelper rsaHelper = new RsaHelper();

                if (StringUtils.isNotEmpty(rsaPrivateKeyPath) && StringUtils.isNotEmpty(aesEncryptStringKey)) {
                    try {
                            decryptKey = rsaHelper.DecryptRsaKey(aesEncryptStringKey, rsaPrivateKeyPath);
                    } catch (EncryptException e) {
                        e.printStackTrace();
                    }
                }

                try {
                    aesHelper.aesDecryptFile(fileToDecrypt, decryptKey);
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
                out.print("pas de fichiers à encrypter");
            }
        }

    }
}
