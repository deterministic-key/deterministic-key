package com.github.deterministic_key;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.File;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;
import java.util.Random;

public class DeterministicKey {

  public static void main(String[] args) throws Exception {
    byte[] seed = FileUtils.readFileToByteArray(new File(args[0]));
    SecureRandom random = new InsecureRandom(seed);
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(3072, random);
    PrivateKey key = kpg.generateKeyPair().getPrivate();

    StringWriter stringWriter = new StringWriter();
    PemWriter pemWriter = new PemWriter(stringWriter);
    pemWriter.writeObject(new JcaMiscPEMGenerator(key));

    pemWriter.flush();
    System.out.print(stringWriter.getBuffer().toString());
  }

  private static class InsecureRandom extends SecureRandom {

    public InsecureRandom(byte[] seed) {
      super(new Spi(), null);
      setSeed(seed);
    }

    private static class Spi extends SecureRandomSpi {

      private final Random random = new Random();

      protected void engineSetSeed(byte[] seed) {
        try {
          byte[] digest = MessageDigest.getInstance("SHA-256").digest(seed);
          BigInteger seedInt = new BigInteger(1, seed);
          random.setSeed(seedInt.mod(BigInteger.valueOf(Long.MAX_VALUE)).longValue());
        } catch (GeneralSecurityException e) {
          throw new RuntimeException(e);
        }
      }

      protected void engineNextBytes(byte[] bytes) {
        random.nextBytes(bytes);
      }

      protected byte[] engineGenerateSeed(int numBytes) {
        byte[] bytes = new byte[numBytes];
        random.nextBytes(bytes);
        return bytes;
      }
    }
  }
}
