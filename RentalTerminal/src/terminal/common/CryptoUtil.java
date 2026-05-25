package terminal.common;

import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;

/**
 * Utility methods used for cryptographic operations.
 */
public class CryptoUtil { //TODO: Check this against the JavaCard crypto. I think we have some double things here.

  private static final String EC_ALGORITHM = "EC";
  // SHA256withECDSA had compatibility issues with JCardSim during testing.
  // SHA1 works correctly with the current setup.
  private static final String SIGNATURE_ALGORITHM = "SHA1withECDSA";
  private static final String CURVE_NAME = "secp256r1";
  private static final String HASH_ALGORITHM = "SHA-256";

  /**
  * Generates an EC key pair for the protocol.
  *
  * @return generated EC key pair
  */
  public static KeyPair generateECKeyPair() throws GeneralSecurityException {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance(EC_ALGORITHM);
    kpg.initialize(new ECGenParameterSpec(CURVE_NAME));
    return kpg.generateKeyPair();
  }

  /**
  * Signs data using an EC private key.
  *
  * @param privateKey signing key
  * @param data data to sign
  * @return generated signature
  */
  public static byte[] sign(PrivateKey privateKey, byte[] data) throws GeneralSecurityException {
    Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
    sig.initSign(privateKey);
    sig.update(data);
    return sig.sign();
  }

  /**
  * Verifies an ECDSA signature.
  *
  * @param publicKey verification key
  * @param data signed data
  * @param signature signature bytes
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
   * Create certificate: custom TLV format per section 4.
   * [2B subject ID len][NB subject ID][1B pubkey len][65B pubkey][1B sig
   * len][~72B sig]
   *
   * Signed data = [2B idLen][id][1B pkLen][pk] (length prefixes included).
   * This matches what the card's verifyWithMPK() expects.
   */
  public static byte[] createCertificate(byte[] subjectId, byte[] publicKeyEncoded,
      PrivateKey signingKey) throws GeneralSecurityException {
    // Signed data includes length prefixes: [2B idLen][id][1B pkLen][pk]
    byte[] idLen = ByteUtil.shortToBytes((short) subjectId.length);
    byte[] pkLen = new byte[] { (byte) publicKeyEncoded.length };
    byte[] dataToSign = ByteUtil.concat(idLen, subjectId, pkLen, publicKeyEncoded);
    byte[] signature = sign(signingKey, dataToSign);

    // Full cert: [signedData][1B sigLen][sig]
    byte[] sigLen = new byte[] { (byte) signature.length };
    return ByteUtil.concat(dataToSign, sigLen, signature);
  }

  /**
   * Parse certificate. Returns: [0] = subjectId, [1] = publicKey bytes, [2] =
   * signature.
   */
  public static byte[][] parseCertificate(byte[] cert) {
    int offset = 0;

    // Subject ID length (2 bytes, big-endian)
    int idLen = ByteUtil.bytesToShort(cert, offset) & 0xFFFF;
    offset += 2;

    byte[] subjectId = new byte[idLen];
    System.arraycopy(cert, offset, subjectId, 0, idLen);
    offset += idLen;

    // Public key length (1 byte)
    int pkLen = cert[offset] & 0xFF;
    offset += 1;

    byte[] pubKey = new byte[pkLen];
    System.arraycopy(cert, offset, pubKey, 0, pkLen);
    offset += pkLen;

    // Signature length (1 byte)
    int sigLen = cert[offset] & 0xFF;
    offset += 1;

    byte[] signature = new byte[sigLen];
    System.arraycopy(cert, offset, signature, 0, sigLen);

    return new byte[][] { subjectId, pubKey, signature };
  }

  /**
   * Verify certificate against master public key.
   * Signed data = [2B idLen][id][1B pkLen][pk] (must match createCertificate).
   */
  public static boolean verifyCertificate(byte[] cert, PublicKey masterPubKey)
      throws GeneralSecurityException {
    byte[][] parts = parseCertificate(cert);
    byte[] subjectId = parts[0];
    byte[] pubKeyBytes = parts[1];
    byte[] signature = parts[2];

    // Reconstruct signed data with length prefixes
    byte[] idLen = ByteUtil.shortToBytes((short) subjectId.length);
    byte[] pkLen = new byte[] { (byte) pubKeyBytes.length };
    byte[] dataToVerify = ByteUtil.concat(idLen, subjectId, pkLen, pubKeyBytes);
    return verify(masterPubKey, dataToVerify, signature);
  }

  /**
   * Extract public key from certificate bytes and reconstruct as PublicKey
   * object.
   */
  public static PublicKey extractPublicKeyFromCert(byte[] cert) throws GeneralSecurityException {
    byte[][] parts = parseCertificate(cert);
    return decodeECPublicKey(parts[1]);
  }

  /**
   * SHA-256 hash of PIN string.
   */
  public static byte[] hashPin(String pin) throws GeneralSecurityException {
    MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
    return md.digest(pin.getBytes());
  }

  /**
   * Encode EC public key to uncompressed point (65 bytes: 0x04 || X || Y).
   */
  public static byte[] encodeECPublicKey(PublicKey publicKey) {
    ECPublicKey ecPub = (ECPublicKey) publicKey;
    ECPoint w = ecPub.getW();
    byte[] x = toFixedLength(w.getAffineX().toByteArray(), 32);
    byte[] y = toFixedLength(w.getAffineY().toByteArray(), 32);
    byte[] encoded = new byte[65];
    encoded[0] = 0x04;
    System.arraycopy(x, 0, encoded, 1, 32);
    System.arraycopy(y, 0, encoded, 33, 32);
    return encoded;
  }

  /**
   * Decode 65-byte uncompressed EC point to PublicKey.
   */
  public static PublicKey decodeECPublicKey(byte[] encoded) throws GeneralSecurityException {
    if (encoded.length != 65 || encoded[0] != 0x04) {
      throw new IllegalArgumentException("Invalid uncompressed EC point");
    }
    // Get EC parameters from a fresh key pair
    KeyPairGenerator kpg = KeyPairGenerator.getInstance(EC_ALGORITHM);
    kpg.initialize(new ECGenParameterSpec(CURVE_NAME));
    KeyPair temp = kpg.generateKeyPair();
    ECPublicKey tempPub = (ECPublicKey) temp.getPublic();
    ECParameterSpec params = tempPub.getParams();

    byte[] xBytes = new byte[32];
    byte[] yBytes = new byte[32];
    System.arraycopy(encoded, 1, xBytes, 0, 32);
    System.arraycopy(encoded, 33, yBytes, 0, 32);

    java.math.BigInteger x = new java.math.BigInteger(1, xBytes);
    java.math.BigInteger y = new java.math.BigInteger(1, yBytes);

    ECPoint point = new ECPoint(x, y);
    ECPublicKeySpec spec = new ECPublicKeySpec(point, params);
    KeyFactory kf = KeyFactory.getInstance(EC_ALGORITHM);
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

  /**
   * Pad or trim big-integer byte array to fixed length.
   */
  private static byte[] toFixedLength(byte[] val, int len) {
    if (val.length == len)
      return val;
    byte[] result = new byte[len];
    if (val.length > len) {
      // Trim leading zero(s) from BigInteger encoding
      System.arraycopy(val, val.length - len, result, 0, len);
    } else {
      // Pad with leading zeros
      System.arraycopy(val, 0, result, len - val.length, val.length);
    }
    return result;
  }
}