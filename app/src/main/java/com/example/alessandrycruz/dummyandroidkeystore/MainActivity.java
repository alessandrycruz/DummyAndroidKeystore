package com.example.alessandrycruz.dummyandroidkeystore;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.example.alessandrycruz.dummyandroidkeystore.security.BaseSecurity_Util;

import java.security.KeyPair;
import java.util.List;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = MainActivity.class.getSimpleName();

    private BaseSecurity_Util mBaseSecurity_Util;
    private KeyPair mKeyPair;
    private String mKeyStoreName;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mBaseSecurity_Util = new BaseSecurity_Util();

        List<String> keyStoreAliases = mBaseSecurity_Util.getKeyStoreAliases();
        if (keyStoreAliases != null && keyStoreAliases.size() > 0) {
            // Gets the KeyStore name if already exits
            mKeyStoreName = keyStoreAliases.get(0);
        } else {
            // Create new KeyStore
            mKeyPair = mBaseSecurity_Util.getKeyStoreKeyPair(this, "KeyName");
        }

        String cipherText = mBaseSecurity_Util.encryptPlainTextWithKeyPair(mKeyStoreName, "PlainText");
        Log.i(TAG, "Cipher Text: " + cipherText);
        String plainText = mBaseSecurity_Util.decryptCipherTextWithKeyPair(mKeyStoreName, cipherText);
        Log.i(TAG, "Plain Text: " + plainText);
    }
}