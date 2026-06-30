/*
 * Java crypto fixture for C2 (JCA/JCE + BouncyCastle). Every asset here is a
 * labeled detection target resolvable by the call-expression model — the
 * entry-point class fixes the primitive context, the arguments supply the
 * parameters. Nothing here is a real credential. The prose below must NOT be
 * inventoried: STRONG examples like "AES-256-GCM, SHA-256, RSA-4096" in this
 * comment are ignored because comments are stripped before scanning.
 */
package com.example.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.SecretKeyFactory;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.signers.Ed25519Signer;

public class CryptoApp {

    // JCA transformation strings: algo / mode / padding all bound from one literal.
    public Cipher strongCipher() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");           // AES-GCM
    }

    public Cipher weakCipher() throws Exception {
        return Cipher.getInstance("DES/CBC/PKCS5Padding");        // DES-CBC
    }

    public Cipher legacyRsaCipher() throws Exception {
        return Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }

    // KeyPairGenerator + .initialize(int): the key size binds to the generator
    // variable across statements -> RSA-2048 (not a bare RSA).
    public void genRsaKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
    }

    public KeyGenerator genAesKey() throws Exception {
        return KeyGenerator.getInstance("AES");
    }

    // MessageDigest vs Signature: same SHA-256 token, different primitive ROLE.
    public MessageDigest digest() throws Exception {
        return MessageDigest.getInstance("SHA-256");              // hash
    }

    public Signature signature() throws Exception {
        return Signature.getInstance("SHA384withECDSA");          // signature (ECDSA)
    }

    public Mac mac() throws Exception {
        return Mac.getInstance("HmacSHA256");                     // mac (HMAC)
    }

    public SecretKeyFactory kdf() throws Exception {
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    }

    // BouncyCastle engines + a mode wrapper nesting an engine.
    public Object bouncyCastle() {
        GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());  // AES-GCM
        CBCBlockCipher cbc = new CBCBlockCipher(new DESedeEngine()); // 3DES-CBC
        SHA1Digest legacy = new SHA1Digest();                     // SHA-1 (weak)
        Ed25519Signer signer = new Ed25519Signer();               // Ed25519
        return gcm;
    }
}
