package com.example.alessandrycruz.dummyandroidkeystore.security.utils;

import android.os.Build;
import android.util.Base64;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Created by alessandry.cruz on 5/31/2017.
 */

public class Secure_Util {
    private static final String ALGORITHM_MORE_API_19 = "PBKDF2withHmacSHA1And8BIT";
    private static final String ALGORITHM_LESS_API_19 = "PBKDF2WithHmacSHA1";

    // Number of PBKDF2 hardening rounds to use. Larger values increase
    // computation time. You should select a value that causes computation
    // to take > 100ms.
    private final int ITERATION_COUNT = 250; // 1000 Originally

    // Generate a 256-bit key
    private final int KEY_LENGTH = 256;

    public byte[] getSecretFactorySalt(int numBytes) {
        return new SecureRandom().generateSeed(numBytes);
    }

    public SecretKey generateSecretFactoryKey(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String algorithm = getSecretKeyFactoyAlgorithm();

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm);
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, KEY_LENGTH);

        return secretKeyFactory.generateSecret(keySpec);
    }

    public String secretKeyFactoryToString(SecretKey secretKey) {
        return Base64.encodeToString(secretKey.getEncoded(), Base64.DEFAULT);
    }

    private String getSecretKeyFactoyAlgorithm() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT ? ALGORITHM_MORE_API_19 : ALGORITHM_LESS_API_19;
    }
}