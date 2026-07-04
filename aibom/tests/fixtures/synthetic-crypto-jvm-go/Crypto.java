// C2 fixture — Java crypto-API usage across JCA/JCE + Bouncy Castle.
// Exercises the clean-room JAVA_RULES + JAVA_LITERALS detection lanes.
import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.security.MessageDigest;
import java.security.KeyPairGenerator;
import java.security.Signature;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMEngine;

public class Crypto {

    // JCA/JCE — the algorithm is embedded in a getInstance("...") string.
    void jca() throws Exception {
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher rsa = Cipher.getInstance("RSA");
        Cipher legacy = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        Cipher single = Cipher.getInstance("DES/CBC/PKCS5Padding");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        MessageDigest weak = MessageDigest.getInstance("MD5");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        Signature sig = Signature.getInstance("SHA256withRSA");
        Signature ec = Signature.getInstance("SHA256withECDSA");
        Mac mac = Mac.getInstance("HmacSHA256");
    }

    // Bouncy Castle low-level API — concrete engine/digest/signer classes.
    void bouncyCastle(byte[] seed) {
        AESEngine engine = new AESEngine();
        SHA256Digest digest = new SHA256Digest();
        Ed25519Signer signer = new Ed25519Signer();
        MLKEMEngine pqc = new MLKEMEngine(0);
    }
}
