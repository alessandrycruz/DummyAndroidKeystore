package com.example.alessandrycruz.dummyandroidkeystore.security;

import android.content.Context;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;


/**
 * Created by alessandry.cruz on 5/31/2017.
 */

public class BaseSecurity_Util {
    private static final String TAG = BaseSecurity_Util.class.getSimpleName();
    private static final String KEYS_TORE_INSTANCE_TYPE = "AndroidKeyStore";
    private static final String KEY_STORE_ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA;
    private static final String KEY_STORE_CIPHER_INSTANCE_GREATER_API_23 = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String KEY_STORE_CIPHER_INSTANCE_LESS_API_23 = "RSA/ECB/PKCS1Padding";
    private static final String KEY_STORE_DATE_FORMAT = "MM/dd/yyyy HH:mm:ss";
    private static final String KEY_STORE_START_DATE = "06/02/2017 00:00:00";
    private static final String KEY_STORE_END_DATE = "06/02/2020 00:00:00";
    private static final String KEY_STORE_X500_PRINCIPAL_NAME = "CN=Sample Name, O=Android Authority";
    private static final BigInteger KEY_STORE_SERIAL_NUMBER = BigInteger.ONE;

    public List<String> getKeyStoreAliases() {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYS_TORE_INSTANCE_TYPE);
            keyStore.load(null);

            List<String> stringAliases = new ArrayList<>();
            Enumeration<String> keyStoreAliases = keyStore.aliases();

            while (keyStoreAliases.hasMoreElements()) {
                stringAliases.add(keyStoreAliases.nextElement());
            }

            return stringAliases;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    public KeyPair getKeyStoreKeyPair(Context context, String keyStoreName) {
        try {
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat(KEY_STORE_DATE_FORMAT,
                    Locale.getDefault());
            Date startDate = simpleDateFormat.parse(KEY_STORE_START_DATE);
            Date endDate = simpleDateFormat.parse(KEY_STORE_END_DATE);

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KEY_STORE_ALGORITHM, KEYS_TORE_INSTANCE_TYPE);

            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                // Api level 23+
                KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(
                        keyStoreName, KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                        .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                        .build();

                keyPairGenerator.initialize(keyGenParameterSpec);
            } else {
                // Api level 17+
                KeyPairGeneratorSpec keyPairGeneratorSpec = new KeyPairGeneratorSpec.Builder(context)
                        .setAlias(keyStoreName)
                        .setSubject(new X500Principal(KEY_STORE_X500_PRINCIPAL_NAME))
                        .setSerialNumber(KEY_STORE_SERIAL_NUMBER)
                        .setStartDate(startDate)
                        .setEndDate(endDate)
                        .build();

                keyPairGenerator.initialize(keyPairGeneratorSpec);
            }

            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            return keyPair;
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }

        return null;
    }

    public String encryptPlainTextWithKeyPair(String keyName, String plainText) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYS_TORE_INSTANCE_TYPE);
            keyStore.load(null);

            KeyStore.PrivateKeyEntry privateKeyEntry =
                    (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyName, null);
            PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();
            Cipher cipher;

            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                cipher = Cipher.getInstance(KEY_STORE_CIPHER_INSTANCE_GREATER_API_23);
            } else {
                cipher = Cipher.getInstance(KEY_STORE_CIPHER_INSTANCE_LESS_API_23);
            }

            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] encodedPlainText = cipher.doFinal(plainText.getBytes());

            return Base64.encodeToString(encodedPlainText, Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();

            return null;
        }
    }

    public String decryptCipherTextWithKeyPair(String keyStoreName, String cipherText) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYS_TORE_INSTANCE_TYPE);
            keyStore.load(null);

            KeyStore.PrivateKeyEntry privateKeyEntry =
                    (KeyStore.PrivateKeyEntry) keyStore.getEntry(keyStoreName, null);
            PrivateKey privateKey = privateKeyEntry.getPrivateKey();
            Cipher cipher;

            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                cipher = Cipher.getInstance(KEY_STORE_CIPHER_INSTANCE_GREATER_API_23);
            } else {
                cipher = Cipher.getInstance(KEY_STORE_CIPHER_INSTANCE_LESS_API_23);
            }

            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] encodedCipherText = cipher.doFinal(cipherText.getBytes());

            return Base64.encodeToString(encodedCipherText, Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}