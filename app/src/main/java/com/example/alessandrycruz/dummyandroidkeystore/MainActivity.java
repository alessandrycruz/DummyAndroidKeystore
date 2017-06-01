package com.example.alessandrycruz.dummyandroidkeystore;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.example.alessandrycruz.dummyandroidkeystore.security.utils.Secure_Util;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = MainActivity.class.getSimpleName();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Secure_Util secure_Util = new Secure_Util();

        try {
            String system = "2";
            String agencyId = "3996";
            String userName = "Alex";
            String userPassword = "test";
            String password = system + agencyId + userName + userPassword;
            byte[] salt = secure_Util.getSecretFactorySalt(1000);

            SecretKey secretKey = secure_Util.generateSecretFactoryKey(password, salt);
            Log.d(TAG, "SecureKey: " + secure_Util.secretKeyFactoryToString(secretKey));
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}