package applet;

import javacard.framework.*;
import javacard.security.*;

public class CryptoManager {

  // NIST P-256 domain parameters
  private static final byte[] EC_FP_P = {
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
  };
  private static final byte[] EC_FP_A = {
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC
  };
  private static final byte[] EC_FP_B = {
      (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA, (byte) 0x3A, (byte) 0x93, (byte) 0xE7,
      (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55, (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xBC,
      (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0, (byte) 0xCC, (byte) 0x53, (byte) 0xB0, (byte) 0xF6,
      (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27, (byte) 0xD2, (byte) 0x60, (byte) 0x4B
  };
  private static final byte[] EC_FP_G = {
      (byte) 0x04,
      (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2, (byte) 0xE1, (byte) 0x2C, (byte) 0x42, (byte) 0x47,
      (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5, (byte) 0x63, (byte) 0xA4, (byte) 0x40, (byte) 0xF2,
      (byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81, (byte) 0x2D, (byte) 0xEB, (byte) 0x33, (byte) 0xA0,
      (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45, (byte) 0xD8, (byte) 0x98, (byte) 0xC2, (byte) 0x96,
      (byte) 0x4F, (byte) 0xE3, (byte) 0x42, (byte) 0xE2, (byte) 0xFE, (byte) 0x1A, (byte) 0x7F, (byte) 0x9B,
      (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A, (byte) 0x7C, (byte) 0x0F, (byte) 0x9E, (byte) 0x16,
      (byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57, (byte) 0x6B, (byte) 0x31, (byte) 0x5E, (byte) 0xCE,
      (byte) 0xCB, (byte) 0xB6, (byte) 0x40, (byte) 0x68, (byte) 0x37, (byte) 0xBF, (byte) 0x51, (byte) 0xF5
  };
  private static final byte[] EC_FP_R = {
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7, (byte) 0x17, (byte) 0x9E, (byte) 0x84,
      (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC, (byte) 0x63, (byte) 0x25, (byte) 0x51
  };

  private ECPublicKey masterPubKey;
  private ECPrivateKey cardPrivKey;
  private ECPublicKey cardPubKey;
  private ECPublicKey tempPubKey;

  private Signature signEngine;
  private Signature verifyEngine;
  private RandomData rng;

  private byte[] certificate;
  private short certLength;
  private byte[] assignmentToken;
  private short assignmentLength;
  private byte[] lastNonce;
  private byte[] tempBuf;
  private byte[] sigBuf;

  private boolean keyPairGenerated;

  public CryptoManager() {
    masterPubKey = buildECPubKey();
    cardPubKey = buildECPubKey();
    cardPrivKey = buildECPrivKey();
    tempPubKey = buildECPubKey();

    // JCardSim 3.0.4 ALG_ECDSA_SHA_256 produces signatures incompatible with
    // standard Java's SHA256withECDSA for cross-verification.
    // Use ALG_ECDSA_SHA (SHA-1) which works correctly across both platforms.
    // Terminal side must use "SHA1withECDSA" to match.
    signEngine = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
    verifyEngine = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);

    rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

    certificate = new byte[AppletConstants.MAX_CERT_LENGTH];
    certLength = 0;
    assignmentToken = new byte[AppletConstants.MAX_ASSIGN_LENGTH];
    assignmentLength = 0;
    lastNonce = JCSystem.makeTransientByteArray(AppletConstants.NONCE_LENGTH, JCSystem.CLEAR_ON_DESELECT);
    tempBuf = JCSystem.makeTransientByteArray((short) 320, JCSystem.CLEAR_ON_DESELECT);
    sigBuf = JCSystem.makeTransientByteArray((short) 80, JCSystem.CLEAR_ON_DESELECT);
    keyPairGenerated = false;
  }

  private ECPublicKey buildECPubKey() {
    ECPublicKey key = (ECPublicKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
    setDomainParams(key);
    return key;
  }

  private ECPrivateKey buildECPrivKey() {
    ECPrivateKey key = (ECPrivateKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    setDomainParams(key);
    return key;
  }

  private void setDomainParams(ECKey key) {
    key.setFieldFP(EC_FP_P, (short) 0, (short) EC_FP_P.length);
    key.setA(EC_FP_A, (short) 0, (short) EC_FP_A.length);
    key.setB(EC_FP_B, (short) 0, (short) EC_FP_B.length);
    key.setG(EC_FP_G, (short) 0, (short) EC_FP_G.length);
    key.setR(EC_FP_R, (short) 0, (short) EC_FP_R.length);
    key.setK((short) 1);
  }

  public void setMasterPublicKey(byte[] buf, short off, short len) {
    masterPubKey.setW(buf, off, len);
  }

  public void generateKeyPair() {
    KeyPair kp = new KeyPair(cardPubKey, cardPrivKey);
    kp.genKeyPair();
    keyPairGenerated = true;
  }

  public boolean isKeyPairGenerated() {
    return keyPairGenerated;
  }

  public short getPublicKey(byte[] buf, short off) {
    return cardPubKey.getW(buf, off);
  }

  public void setCertificate(byte[] buf, short off, short len) {
    Util.arrayCopy(buf, off, certificate, (short) 0, len);
    certLength = len;
  }

  public short getCertificate(byte[] buf, short off) {
    Util.arrayCopy(certificate, (short) 0, buf, off, certLength);
    return certLength;
  }

  public short getCertificateLength() {
    return certLength;
  }

  public boolean hasCertificate() {
    return certLength > 0;
  }

  public void setAssignment(byte[] buf, short off, short len) {
    Util.arrayCopy(buf, off, assignmentToken, (short) 0, len);
    assignmentLength = len;
  }

  public short getAssignment(byte[] buf, short off) {
    Util.arrayCopy(assignmentToken, (short) 0, buf, off, assignmentLength);
    return assignmentLength;
  }

  public short getAssignmentLength() {
    return assignmentLength;
  }

  public void clearAssignment() {
    Util.arrayFillNonAtomic(assignmentToken, (short) 0, assignmentLength, (byte) 0);
    assignmentLength = 0;
  }

  public short generateNonce(byte[] buf, short off) {
    rng.generateData(lastNonce, (short) 0, AppletConstants.NONCE_LENGTH);
    Util.arrayCopy(lastNonce, (short) 0, buf, off, AppletConstants.NONCE_LENGTH);
    return AppletConstants.NONCE_LENGTH;
  }

  public short sign(byte[] data, short dOff, short dLen, byte[] sig, short sOff) {
    signEngine.init(cardPrivKey, Signature.MODE_SIGN);
    return signEngine.sign(data, dOff, dLen, sig, sOff);
  }

  public boolean verifyWithMPK(byte[] data, short dOff, short dLen,
      byte[] sig, short sOff, short sLen) {
    // Copy to separate buffers to avoid any JCardSim quirks
    Util.arrayCopy(data, dOff, tempBuf, (short) 0, dLen);
    Util.arrayCopy(sig, sOff, sigBuf, (short) 0, sLen);
    verifyEngine.init(masterPubKey, Signature.MODE_VERIFY);
    return verifyEngine.verify(tempBuf, (short) 0, dLen, sigBuf, (short) 0, sLen);
  }

  /**
   * Verify terminal signature during mutual auth.
   * Input format: [1B sigLen][sigBytes][certBytes]
   * Verifies cert against MPK, extracts terminal pubkey, verifies sig of
   * lastNonce.
   * Returns 0 on success, 1 if cert verification fails, 2 if nonce sig
   * verification fails.
   */
  public short verifyTerminalSignature(byte[] buf, short off, short len) {
    short sigLen = (short) (buf[off] & 0xFF);
    short sigOff = (short) (off + 1);
    short certOff = (short) (sigOff + sigLen);
    short certLen = (short) (len - 1 - sigLen);

    // Parse cert to find signed data and signature within cert
    // Format: [2B subjectIdLen][subjectId][1B pubkeyLen][pubkey][1B
    // certSigLen][certSig]
    short subjectIdLen = Util.getShort(buf, certOff);
    short pubKeyLenOff = (short) (certOff + 2 + subjectIdLen);
    short pubKeyLen = (short) (buf[pubKeyLenOff] & 0xFF);
    short pubKeyOff = (short) (pubKeyLenOff + 1);
    short certSignedDataLen = (short) (2 + subjectIdLen + 1 + pubKeyLen);
    short certSigLenOff = (short) (certOff + certSignedDataLen);
    short certSigLen = (short) (buf[certSigLenOff] & 0xFF);
    short certSigOff = (short) (certSigLenOff + 1);

    // Verify certificate against MPK
    if (!verifyWithMPK(buf, certOff, certSignedDataLen, buf, certSigOff, certSigLen)) {
      return (short) 1;
    }

    // Load terminal public key from cert into tempPubKey
    tempPubKey.setW(buf, pubKeyOff, pubKeyLen);

    // Verify terminal's signature of our lastNonce
    verifyEngine.init(tempPubKey, Signature.MODE_VERIFY);
    if (!verifyEngine.verify(lastNonce, (short) 0, AppletConstants.NONCE_LENGTH,
        buf, sigOff, sigLen)) {
      return (short) 2;
    }
    return (short) 0;
  }

  /**
   * Sign data and prepend signature length byte.
   * Returns total bytes written (1 + sigLen).
   */
  public short signWithLength(byte[] data, short dOff, short dLen, byte[] out, short outOff) {
    signEngine.init(cardPrivKey, Signature.MODE_SIGN);
    short sigLen = signEngine.sign(data, dOff, dLen, out, (short) (outOff + 1));
    out[outOff] = (byte) (sigLen & 0xFF);
    return (short) (1 + sigLen);
  }

  /**
   * Sign nonce and append certificate.
   * Output: [1B sigLen][sig][certBytes]
   */
  public short signNonceWithCert(byte[] nonce, short nOff, short nLen,
      byte[] out, short outOff) {
    short written = signWithLength(nonce, nOff, nLen, out, outOff);
    Util.arrayCopy(certificate, (short) 0, out, (short) (outOff + written), certLength);
    return (short) (written + certLength);
  }

  /**
   * Sign vehicle challenge: Sign(sigma4 || vehicleNonce).
   * Output: signature bytes (sigma5).
   */
  public short signVehicleChallenge(byte[] vehicleNonce, short nOff, short nLen,
      byte[] out, short outOff) {
    // Build sigma4 || vehicleNonce in tempBuf
    short pos = (short) 0;
    Util.arrayCopy(assignmentToken, (short) 0, tempBuf, pos, assignmentLength);
    pos += assignmentLength;
    Util.arrayCopy(vehicleNonce, nOff, tempBuf, pos, nLen);
    pos += nLen;

    signEngine.init(cardPrivKey, Signature.MODE_SIGN);
    return signEngine.sign(tempBuf, (short) 0, pos, out, outOff);
  }
}
