package terminal.util;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.security.spec.ECFieldFp;
import java.security.spec.InvalidKeySpecException;

/**
 * Utility methods used for cryptographic operations.
 */
public class CryptoUtil {

  private static final String EC_ALGORITHM = "EC";
  private static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";
  private static final String EC_CURVE = "secp256r1";
  private static final String HASH_ALGORITHM = "SHA-256";
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  /**
   * Generate EC P-256 key pair.
   */
  public static KeyPair generateKeyPair() throws GeneralSecurityException {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance(EC_ALGORITHM);
    kpg.initialize(new ECGenParameterSpec(EC_CURVE), SECURE_RANDOM);
    return kpg.generateKeyPair();
  }

  /**
   * Signs data using an EC private key with ECDSA-SHA256.
   *
   * @param privateKey signing key
   * @param data       data to sign
   * @return generated signature (DER-encoded)
   */
  public static byte[] sign(PrivateKey privateKey, byte[] data) throws GeneralSecurityException {
    Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
    sig.initSign(privateKey);
    sig.update(data);
    return sig.sign();
  }

  /**
   * Verifies an ECDSA-SHA256 signature.
   *
   * @param publicKey verification key
   * @param data      signed data
   * @param signature signature bytes (DER-encoded)
   * @return true if signature is valid
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
   * Verify certificate against master public key (card cert format, no expiry).
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
   * Verify terminal certificate (format with 8B notAfter expiry field).
   * Format: [2B idLen][id][2B pkLen][pk][8B notAfter][2B sigLen][sig]
   */
  public static boolean verifyCertificateWithExpiry(byte[] cert, PublicKey masterPubKey)
      throws GeneralSecurityException {
    int offset = 0;
    int idLen = ByteUtil.bytesToShort(cert, offset) & 0xFFFF;
    offset += 2;
    byte[] subjectId = new byte[idLen];
    System.arraycopy(cert, offset, subjectId, 0, idLen);
    offset += idLen;

    int pkLen = ByteUtil.bytesToShort(cert, offset) & 0xFFFF;
    offset += 2;
    byte[] pubKeyBytes = new byte[pkLen];
    System.arraycopy(cert, offset, pubKeyBytes, 0, pkLen);
    offset += pkLen;

    byte[] notAfter = new byte[8];
    System.arraycopy(cert, offset, notAfter, 0, 8);
    offset += 8;

    int sigLen = ByteUtil.bytesToShort(cert, offset) & 0xFFFF;
    offset += 2;
    byte[] signature = new byte[sigLen];
    System.arraycopy(cert, offset, signature, 0, sigLen);

    byte[] idLenBytes = ByteUtil.shortToBytes((short) subjectId.length);
    byte[] pkLenBytes = ByteUtil.shortToBytes((short) pubKeyBytes.length);
    byte[] dataToVerify = ByteUtil.concat(idLenBytes, subjectId, pkLenBytes, pubKeyBytes, notAfter);
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
    // Explicit charset prevents hash mismatches when the JVM default locale is not UTF-8.
    return md.digest(pin.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Session-bound PIN hash: HASH(nonce || HASH(pin)).
   * Binding to the session nonce prevents a captured hash from being replayed
   * in a different session. Uses the same algorithm as hashPin so both sides
   * stay in sync when the algorithm is updated.
   */
  public static byte[] hashPinWithNonce(String pin, byte[] nonce) throws GeneralSecurityException {
    byte[] pinHash = hashPin(pin);
    MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
    md.update(nonce);
    return md.digest(pinHash);
  }

  /**
   * Encode EC P-256 public key as 65-byte uncompressed point: 0x04 || x32 || y32.
   */
  public static byte[] encodePublicKey(PublicKey publicKey) {
    ECPublicKey ecPub = (ECPublicKey) publicKey;
    ECPoint point = ecPub.getW();
    byte[] x = ByteUtil.toBigIntBytes(point.getAffineX(), 32);
    byte[] y = ByteUtil.toBigIntBytes(point.getAffineY(), 32);
    byte[] encoded = new byte[65];
    encoded[0] = 0x04;
    System.arraycopy(x, 0, encoded, 1, 32);
    System.arraycopy(y, 0, encoded, 33, 32);
    return encoded;
  }

  /**
   * Decode EC P-256 public key from 65-byte uncompressed point: 0x04 || x32 || y32.
   * Validates the point is on the P-256 curve to prevent invalid-curve attacks.
   */
  public static PublicKey decodePublicKey(byte[] encoded) throws GeneralSecurityException {
    if (encoded.length != 65 || encoded[0] != 0x04) {
      throw new InvalidKeySpecException(
          "Expected 65-byte uncompressed EC point (0x04 prefix)");
    }
    BigInteger x = new BigInteger(1, Arrays.copyOfRange(encoded, 1, 33));
    BigInteger y = new BigInteger(1, Arrays.copyOfRange(encoded, 33, 65));

    AlgorithmParameters params = AlgorithmParameters.getInstance(EC_ALGORITHM);
    params.init(new ECGenParameterSpec(EC_CURVE));
    ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);

    ECFieldFp field =
        (ECFieldFp) ecSpec.getCurve().getField();
    BigInteger p = field.getP();
    BigInteger a = ecSpec.getCurve().getA();
    BigInteger b = ecSpec.getCurve().getB();
    BigInteger lhs = y.modPow(BigInteger.valueOf(2), p);
    BigInteger rhs = x.modPow(BigInteger.valueOf(3), p)
        .add(a.multiply(x)).add(b).mod(p);
    if (!lhs.equals(rhs)) {
      throw new InvalidKeySpecException(
          "EC point is not on the P-256 curve");
    }

    ECPublicKeySpec keySpec = new ECPublicKeySpec(new ECPoint(x, y), ecSpec);
    return KeyFactory.getInstance(EC_ALGORITHM).generatePublic(keySpec);
  }

  /**
   * Create terminal certificate with validity period (H-3).
   * Format: [2B idLen][id][2B pkLen][pk][8B notAfterEpochSeconds][2B sigLen][sig]
   * notAfter is part of the signed data, binding the cert to its validity window.
   */
  public static byte[] createCertificateWithExpiry(byte[] subjectId, byte[] publicKeyEncoded,
      long notAfterEpochSeconds, PrivateKey signingKey) throws GeneralSecurityException {
    byte[] idLen = ByteUtil.shortToBytes((short) subjectId.length);
    byte[] pkLen = ByteUtil.shortToBytes((short) publicKeyEncoded.length);
    byte[] notAfterBytes = new byte[8];
    long ts = notAfterEpochSeconds;
    for (int i = 7; i >= 0; i--) {
      notAfterBytes[i] = (byte)(ts & 0xFF);
      ts >>= 8;
    }
    byte[] dataToSign = ByteUtil.concat(idLen, subjectId, pkLen, publicKeyEncoded, notAfterBytes);
    byte[] signature = sign(signingKey, dataToSign);
    byte[] sigLen = ByteUtil.shortToBytes((short) signature.length);
    return ByteUtil.concat(dataToSign, sigLen, signature);
  }

  /**
   * Generate secure random nonce.
   */
  public static byte[] generateNonce(int length) {
    byte[] nonce = new byte[length];
    SECURE_RANDOM.nextBytes(nonce);
    return nonce;
  }

}
