package applet;

import javacard.framework.*;
import javacard.security.*;

public class CryptoManager {

  private RSAPublicKey masterPubKey;
  private RSAPrivateKey cardPrivKey;
  private RSAPublicKey cardPubKey;
  private RSAPublicKey tempPubKey;

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
    masterPubKey = (RSAPublicKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
    cardPubKey = (RSAPublicKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);
    cardPrivKey = (RSAPrivateKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
    tempPubKey = (RSAPublicKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);

    signEngine = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
    verifyEngine = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);

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

  /**
   * Set master public key from encoded bytes: [2B modLen][mod][2B expLen][exp].
   */
  public void setMasterPublicKey(byte[] buf, short off, short len) {
    short modLen = Util.getShort(buf, off);
    short modOff = (short) (off + 2);
    short expLenOff = (short) (modOff + modLen);
    short expLen = Util.getShort(buf, expLenOff);
    short expOff = (short) (expLenOff + 2);
    masterPubKey.setModulus(buf, modOff, modLen);
    masterPubKey.setExponent(buf, expOff, expLen);
  }

  public void generateKeyPair() {
    KeyPair kp = new KeyPair(cardPubKey, cardPrivKey);
    kp.genKeyPair();
    keyPairGenerated = true;
  }

  public boolean isKeyPairGenerated() {
    return keyPairGenerated;
  }

  /**
   * Encode card public key as [2B modLen][mod][2B expLen][exp] into buf at off.
   * Returns total bytes written.
   */
  public short getPublicKey(byte[] buf, short off) {
    short modLen = cardPubKey.getModulus(tempBuf, (short) 2);
    Util.setShort(tempBuf, (short) 0, modLen);
    short expStartOff = (short) (2 + modLen + 2);
    short expLen = cardPubKey.getExponent(tempBuf, expStartOff);
    Util.setShort(tempBuf, (short) (2 + modLen), expLen);
    short totalLen = (short) (expStartOff + expLen);
    Util.arrayCopy(tempBuf, (short) 0, buf, off, totalLen);
    return totalLen;
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
    Util.arrayCopy(data, dOff, tempBuf, (short) 0, dLen);
    Util.arrayCopy(sig, sOff, sigBuf, (short) 0, sLen);
    verifyEngine.init(masterPubKey, Signature.MODE_VERIFY);
    return verifyEngine.verify(tempBuf, (short) 0, dLen, sigBuf, (short) 0, sLen);
  }

  /**
   * Verify terminal signature during mutual auth.
   * Input format: [2B sigLen][sigBytes][certBytes]
   * Cert format:  [2B idLen][id][2B pkLen][pk][2B sigLen][sig]
   * Returns 0 on success, 1 if cert verification fails, 2 if nonce sig fails.
   */
  public short verifyTerminalSignature(byte[] buf, short off, short len) {
    short sigLen = Util.getShort(buf, off);
    short sigOff = (short) (off + 2);
    short certOff = (short) (sigOff + sigLen);

    // Parse cert: [2B idLen][id][2B pkLen][pk][2B certSigLen][certSig]
    short subjectIdLen = Util.getShort(buf, certOff);
    short pubKeyLenOff = (short) (certOff + 2 + subjectIdLen);
    short pubKeyLen = Util.getShort(buf, pubKeyLenOff);
    short pubKeyOff = (short) (pubKeyLenOff + 2);
    short certSignedDataLen = (short) (2 + subjectIdLen + 2 + pubKeyLen);
    short certSigLenOff = (short) (certOff + certSignedDataLen);
    short certSigLen = Util.getShort(buf, certSigLenOff);
    short certSigOff = (short) (certSigLenOff + 2);

    if (!verifyWithMPK(buf, certOff, certSignedDataLen, buf, certSigOff, certSigLen)) {
      return (short) 1;
    }

    // Load terminal public key from cert: [2B modLen][mod][2B expLen][exp]
    short tModLen = Util.getShort(buf, pubKeyOff);
    short tModOff = (short) (pubKeyOff + 2);
    short tExpLenOff = (short) (tModOff + tModLen);
    short tExpLen = Util.getShort(buf, tExpLenOff);
    short tExpOff = (short) (tExpLenOff + 2);
    tempPubKey.setModulus(buf, tModOff, tModLen);
    tempPubKey.setExponent(buf, tExpOff, tExpLen);

    verifyEngine.init(tempPubKey, Signature.MODE_VERIFY);
    if (!verifyEngine.verify(lastNonce, (short) 0, AppletConstants.NONCE_LENGTH,
        buf, sigOff, sigLen)) {
      return (short) 2;
    }
    return (short) 0;
  }

  /**
   * Sign data and prepend 2-byte signature length.
   * Returns total bytes written (2 + sigLen).
   */
  public short signWithLength(byte[] data, short dOff, short dLen, byte[] out, short outOff) {
    signEngine.init(cardPrivKey, Signature.MODE_SIGN);
    short sigLen = signEngine.sign(data, dOff, dLen, out, (short) (outOff + 2));
    Util.setShort(out, outOff, sigLen);
    return (short) (2 + sigLen);
  }

  /**
   * Sign nonce and append certificate.
   * Output: [2B sigLen][sig][certBytes]
   */
  public short signNonceWithCert(byte[] nonce, short nOff, short nLen,
      byte[] out, short outOff) {
    short written = signWithLength(nonce, nOff, nLen, out, outOff);
    Util.arrayCopy(certificate, (short) 0, out, (short) (outOff + written), certLength);
    return (short) (written + certLength);
  }

  /**
   * Sign vehicle challenge: Sign(vehicleToken || vehicleNonce).
   * Output: signature bytes (ephemeralVehicleToken).
   */
  public short signVehicleChallenge(byte[] vehicleNonce, short nOff, short nLen,
      byte[] out, short outOff) {
    short pos = (short) 0;
    Util.arrayCopy(assignmentToken, (short) 0, tempBuf, pos, assignmentLength);
    pos += assignmentLength;
    Util.arrayCopy(vehicleNonce, nOff, tempBuf, pos, nLen);
    pos += nLen;

    signEngine.init(cardPrivKey, Signature.MODE_SIGN);
    return signEngine.sign(tempBuf, (short) 0, pos, out, outOff);
  }
}
