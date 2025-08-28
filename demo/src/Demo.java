package demo;

import java.security.*;
import javax.crypto.*;
import javax.net.ssl.SSLContext;

public class Demo {
  public static void main(String[] args) throws Exception {
    MessageDigest md5    = MessageDigest.getInstance("MD5");
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    Signature sig1 = Signature.getInstance("SHA1withRSA");
    Signature sig2 = Signature.getInstance("SHA256withRSA");
    Cipher des    = Cipher.getInstance("DES/CBC/PKCS5Padding");
    Cipher aesEcb = Cipher.getInstance("AES/ECB/NoPadding");
    Cipher aesGcm = Cipher.getInstance("AES/GCM/NoPadding");
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(1024);
    SecureRandom sr1 = SecureRandom.getInstance("SHA1PRNG");
    SecureRandom sr2 = new SecureRandom();
    SSLContext tls = SSLContext.getInstance("TLSv1.2");
  }
}
