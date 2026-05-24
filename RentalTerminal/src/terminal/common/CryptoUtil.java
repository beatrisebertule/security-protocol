package terminal.common;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;

public class CryptoUtil {

  private static final String RSA_ALGORITHM = "RSA";
  private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
  private static final int RSA_KEY_BITS = 512;
  private static final String HASH_ALGORITHM = "SHA-256";

  /**
   * Generate RSA-2048 key pair.
   */
  public static KeyPair generateKeyPair() throws GeneralSecurityException {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance(RSA_ALGORITHM);
    kpg.initialize(RSA_KEY_BITS);
    return kpg.generateKeyPair();
  }

  /**
   * Sign data with RSA private key (SHA256withRSA).
   */
  public static byte[] sign(PrivateKey privateKey, byte[] data) throws GeneralSecurityException {
    Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
    sig.initSign(privateKey);
    sig.update(data);
    return sig.sign();
  }

  /**
   * Verify RSA signature (SHA256withRSA).
   */
  public static boolean verify(PublicKey publicKey, byte[] data, byte[] signature)
      throws GeneralSecurityException {
    Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
    sig.initVerify(publicKey);
    sig.update(data);
    return sig.verify(signature);
  }

  /**
   * Create certificate: custom TLV format.
   * [2B idLen][id][2B pkLen][pk][2B sigLen][sig]
   *
   * Signed data = [2B idLen][id][2B pkLen][pk].
   * This matches what the card's verifyWithMPK() expects.
   */
  public static byte[] createCertificate(byte[] subjectId, byte[] publicKeyEncoded,
      PrivateKey signingKey) throws GeneralSecurityException {
    byte[] idLen = ByteUtil.shortToBytes((short) subjectId.length);
    byte[] pkLen = ByteUtil.shortToBytes((short) publicKeyEncoded.length);
    byte[] dataToSign = ByteUtil.concat(idLen, subjectId, pkLen, publicKeyEncoded);
    byte[] signature = sign(signingKey, dataToSign);

    byte[] sigLen = ByteUtil.shortToBytes((short) signature.length);
    return ByteUtil.concat(dataToSign, sigLen, signature);
  }

  /**
   * Parse certificate. Returns: [0] = subjectId, [1] = publicKey bytes, [2] = signature.
   */
  public static byte[][] parseCertificate(byte[] cert) {
    int offset = 0;

    int idLen = ByteUtil.bytesToShort(cert, offset) & 0xFFFF;
    offset += 2;
    byte[] subjectId = new byte[idLen];
    System.arraycopy(cert, offset, subjectId, 0, idLen);
    offset += idLen;

    int pkLen = ByteUtil.bytesToShort(cert, offset) & 0xFFFF;
    offset += 2;
    byte[] pubKey = new byte[pkLen];
    System.arraycopy(cert, offset, pubKey, 0, pkLen);
    offset += pkLen;

    int sigLen = ByteUtil.bytesToShort(cert, offset) & 0xFFFF;
    offset += 2;
    byte[] signature = new byte[sigLen];
    System.arraycopy(cert, offset, signature, 0, sigLen);

    return new byte[][] { subjectId, pubKey, signature };
  }

  /**
   * Verify certificate against master public key.
   */
  public static boolean verifyCertificate(byte[] cert, PublicKey masterPubKey)
      throws GeneralSecurityException {
    byte[][] parts = parseCertificate(cert);
    byte[] subjectId = parts[0];
    byte[] pubKeyBytes = parts[1];
    byte[] signature = parts[2];

    byte[] idLen = ByteUtil.shortToBytes((short) subjectId.length);
    byte[] pkLen = ByteUtil.shortToBytes((short) pubKeyBytes.length);
    byte[] dataToVerify = ByteUtil.concat(idLen, subjectId, pkLen, pubKeyBytes);
    return verify(masterPubKey, dataToVerify, signature);
  }

  /**
   * Extract public key from certificate bytes and reconstruct as PublicKey object.
   */
  public static PublicKey extractPublicKeyFromCert(byte[] cert) throws GeneralSecurityException {
    byte[][] parts = parseCertificate(cert);
    return decodePublicKey(parts[1]);
  }

  /**
   * SHA-256 hash of PIN string.
   */
  public static byte[] hashPin(String pin) throws GeneralSecurityException {
    MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
    return md.digest(pin.getBytes());
  }

  /**
   * Encode RSA public key: [2B modLen][modulus][2B expLen][exponent].
   */
  public static byte[] encodePublicKey(PublicKey publicKey) {
    RSAPublicKey rsaPub = (RSAPublicKey) publicKey;
    byte[] modulus = toUnsignedBytes(rsaPub.getModulus());
    byte[] exponent = toUnsignedBytes(rsaPub.getPublicExponent());
    byte[] encoded = new byte[2 + modulus.length + 2 + exponent.length];
    encoded[0] = (byte) ((modulus.length >> 8) & 0xFF);
    encoded[1] = (byte) (modulus.length & 0xFF);
    System.arraycopy(modulus, 0, encoded, 2, modulus.length);
    encoded[2 + modulus.length] = (byte) ((exponent.length >> 8) & 0xFF);
    encoded[2 + modulus.length + 1] = (byte) (exponent.length & 0xFF);
    System.arraycopy(exponent, 0, encoded, 2 + modulus.length + 2, exponent.length);
    return encoded;
  }

  /**
   * Decode RSA public key from [2B modLen][modulus][2B expLen][exponent].
   */
  public static PublicKey decodePublicKey(byte[] encoded) throws GeneralSecurityException {
    int modLen = ((encoded[0] & 0xFF) << 8) | (encoded[1] & 0xFF);
    byte[] modBytes = new byte[modLen];
    System.arraycopy(encoded, 2, modBytes, 0, modLen);
    int expLen = ((encoded[2 + modLen] & 0xFF) << 8) | (encoded[2 + modLen + 1] & 0xFF);
    byte[] expBytes = new byte[expLen];
    System.arraycopy(encoded, 2 + modLen + 2, expBytes, 0, expLen);

    BigInteger modulus = new BigInteger(1, modBytes);
    BigInteger exponent = new BigInteger(1, expBytes);
    RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
    KeyFactory kf = KeyFactory.getInstance(RSA_ALGORITHM);
    return kf.generatePublic(spec);
  }

  /**
   * Generate secure random nonce.
   */
  public static byte[] generateNonce(int length) {
    byte[] nonce = new byte[length];
    new SecureRandom().nextBytes(nonce);
    return nonce;
  }

  private static byte[] toUnsignedBytes(BigInteger val) {
    byte[] bytes = val.toByteArray();
    if (bytes[0] == 0) {
      byte[] trimmed = new byte[bytes.length - 1];
      System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
      return trimmed;
    }
    return bytes;
  }
}
