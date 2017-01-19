package com.orange.helper.impl;

import com.orange.exception.EncryptException;
import com.orange.helper.IRsaHelper;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Created by fqsq3375 on 19/01/2017.
 */
public class RsaHelper implements IRsaHelper {

    private static final String PROBLEME_LORS_DE_L_INTEGRATION_DE_LA_CLE_PRIVEE = "Probleme lors de l'intégration de la cle privée :";
    private static final String CLE_INVALIDE = "Clé invalide";
    private static final String PADDING_INVALIDE = "padding invalide";
    private static final String TAILLE_DE_BLOCK_DE_DECRYPTAGE_INVALIDE = "taille de block de decryptage invalide";

    private static Cipher cipher;
    static {
        try {
            cipher = Cipher.getInstance(RSA_CIPHER_TYPE);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    private PrivateKey loadPrivateKey(String filename) throws Exception {

        byte[] keyBytes = null;
        if (StringUtils.isNotEmpty(filename)) {
            keyBytes = Files.readAllBytes(new File(filename).toPath());
        }
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public String DecryptRsaKey(String stringToDecrypt, String rsaPrivateKeyPath) throws EncryptException {
        PrivateKey privateKey = null;
        byte[] decryptKeyByte;
        String response = null;

        //Lancement de le cle privée passée en parametre
        if (StringUtils.isNotEmpty(rsaPrivateKeyPath)){
            try {
                privateKey = loadPrivateKey(rsaPrivateKeyPath);
            } catch (Exception e) {
                throw new EncryptException(PROBLEME_LORS_DE_L_INTEGRATION_DE_LA_CLE_PRIVEE, e);
            }
        }
        //Decryptage de la clé eas (string) avec la clé privée

        if (StringUtils.isNotEmpty(stringToDecrypt) && null != privateKey) {
            try {
                decryptKeyByte = processRsaDecryption(Base64.decodeBase64(stringToDecrypt), privateKey);
            } catch (InvalidKeyException e) {
                throw new EncryptException(CLE_INVALIDE, e);
            } catch (BadPaddingException e) {
                throw new EncryptException(PADDING_INVALIDE, e);
            } catch (IllegalBlockSizeException e) {
                throw new EncryptException(TAILLE_DE_BLOCK_DE_DECRYPTAGE_INVALIDE, e);
            }
            response = Base64.encodeBase64String(decryptKeyByte);
        }
        return response;
    }

    /**
     * Decrypt data
     *
     * @param data      Data to encrypt
     * @param privateKey PublicKey used to crypt
     * @return          The crypted data
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    private byte[] processRsaDecryption(byte[] data, PrivateKey privateKey) throws InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data); //Encrypte data avec le cipher, tel qu'il a été paramétré, ici en mode RSA, en encryption, encryption qui va utiliser la clé publique.
    }
}
