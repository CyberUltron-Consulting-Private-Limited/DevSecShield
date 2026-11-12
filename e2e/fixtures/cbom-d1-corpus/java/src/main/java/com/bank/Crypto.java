package com.bank;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Random;

public class Crypto {
    private static final String TRANSFORM = "DES/ECB/PKCS5Padding";

    public byte[] legacyEncrypt(byte[] data, byte[] key) throws Exception {
        Cipher c = Cipher.getInstance(TRANSFORM);                       // J1 DES ECB via constant
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
        return c.doFinal(data);
    }

    public byte[] tripleDes(byte[] data, byte[] key) throws Exception {
        Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");      // J2 3DES CBC
        byte[] iv = new byte[8];                                         // J3 static zero IV
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DESede"), new IvParameterSpec(iv));
        return c.doFinal(data);
    }

    public byte[] aesDefault(byte[] data, SecretKey k) throws Exception {
        Cipher c = Cipher.getInstance("AES");                            // J4 AES default = ECB
        c.init(Cipher.ENCRYPT_MODE, k);
        return c.doFinal(data);
    }

    public KeyPair weakRsa() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");      // J5 RSA-1024
        kpg.initialize(1024);
        return kpg.generateKeyPair();
    }

    public byte[] md5(byte[] in) throws Exception {
        return MessageDigest.getInstance("MD5").digest(in);              // J6 MD5
    }

    public byte[] sign(PrivateKey k, byte[] in) throws Exception {
        Signature s = Signature.getInstance("SHA1withRSA");              // J7 SHA1withRSA
        s.initSign(k);
        s.update(in);
        return s.sign();
    }

    public int token() {
        return new Random().nextInt();                                   // J8 insecure RNG for token
    }

    public SSLContext trustAll() throws Exception {
        TrustManager[] tm = new TrustManager[]{ new X509TrustManager() { // J9 trust-all TrustManager
            public void checkClientTrusted(X509Certificate[] c, String a) {}
            public void checkServerTrusted(X509Certificate[] c, String a) {}
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
        SSLContext ctx = SSLContext.getInstance("TLSv1");                // J10 TLS 1.0
        ctx.init(null, tm, new SecureRandom());
        HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);  // J11 hostname verifier off
        return ctx;
    }

    private static final byte[] HARDCODED = "0123456789abcdef".getBytes();  // J12 hard-coded key
    public SecretKey hardKey() { return new SecretKeySpec(HARDCODED, "AES"); }

    public SecretKey rc4() throws Exception {
        return KeyGenerator.getInstance("RC4").generateKey();           // J13 RC4
    }
}
