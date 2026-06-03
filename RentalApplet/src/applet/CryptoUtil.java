/**
 * Encapsulates all cryptographic operations for the rental card applet.
 *
 * Handles EC P-256 key pair generation, master public key storage, certificate
 * and assignment token management, nonce generation, and signing/verification
 * using ALG_ECDSA_SHA_256.
 *
 * The transient tempBuf (400 bytes) is shared across operations and cleared on
 * card deselect.
 */
package applet;

import javacard.framework.*;
import javacard.security.*;

public class CryptoUtil {

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

  private boolean keyPairGenerated;

  public CryptoUtil() {
    masterPubKey = (ECPublicKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
    cardPubKey = (ECPublicKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
    cardPrivKey = (ECPrivateKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    tempPubKey = (ECPublicKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);

    signEngine = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    verifyEngine = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

    rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

    certificate = new byte[AppletConstants.MAX_CERT_LENGTH];
    certLength = 0;
    assignmentToken = new byte[AppletConstants.MAX_ASSIGN_LENGTH];
    assignmentLength = 0;
    lastNonce = JCSystem.makeTransientByteArray(AppletConstants.NONCE_LENGTH, JCSystem.CLEAR_ON_DESELECT);
    tempBuf = JCSystem.makeTransientByteArray((short) 400, JCSystem.CLEAR_ON_DESELECT);
    keyPairGenerated = false;
  }

  /**
   * Set master public key from encoded EC point: 65-byte uncompressed W (0x04 || x32 || y32).
   */
  public void setMasterPublicKey(byte[] buf, short off, short len) {
    masterPubKey.setW(buf, off, len);
  }

  public void generateKeyPair() {
    // Pass existing key objects so genKeyPair() fills their values in-place,
    // avoiding reference reassignment which is not safe in JavaCard EEPROM.
    KeyPair kp = new KeyPair(cardPubKey, cardPrivKey);
    kp.genKeyPair();
    keyPairGenerated = true;
  }

  public boolean isKeyPairGenerated() {
    return keyPairGenerated;
  }

  /**
   * Encode card public key as 65-byte uncompressed EC point into buf at off.
   * Returns total bytes written (always 65).
   */
  public short getPublicKey(byte[] buf, short off) {
    return encodeCardKey(buf, off);
  }

  private short encodeCardKey(byte[] buf, short off) {
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

  /**
   * Verify MSK signature over (reqVehicleToken || pkc) and store the token.
   * Returns false if signature verification fails.
   *
   * Expected token format: [2B rdLen][reqData][2B rvtLen][reqVehicleToken]
   *                        [2B pkLen][pkc][2B sigLen][MSK sig over rvt||pkc]
   *
   * @param buf buffer containing the assignment token
   * @param off offset of the token within buf
   * @param len total length of the token
   * @return true if the MSK signature is valid and the token has been stored,
   *         false if verification fails
   */
  public boolean verifyAndSetAssignment(byte[] buf, short off, short len) {
    short rdLen = Util.getShort(buf, off);
    short rvtOff = (short)(off + 2 + rdLen);
    short rvtLen = Util.getShort(buf, rvtOff);
    short pkcOff = (short)(rvtOff + 2 + rvtLen);
    short pkcLen = Util.getShort(buf, pkcOff);
    short sigOff = (short)(pkcOff + 2 + pkcLen);
    short sigLen = Util.getShort(buf, sigOff);
    short sigDataOff = (short)(sigOff + 2);

    // Build data to verify: reqVehicleToken || pkc
    short dataLen = (short)(rvtLen + pkcLen);
    Util.arrayCopy(buf, (short)(rvtOff + 2), tempBuf, (short)0, rvtLen);
    Util.arrayCopy(buf, (short)(pkcOff + 2), tempBuf, rvtLen, pkcLen);

    if (!verifyWithMPK(tempBuf, (short)0, dataLen, buf, sigDataOff, sigLen)) {
      return false;
    }

    Util.arrayCopy(buf, off, assignmentToken, (short)0, len);
    assignmentLength = len;
    return true;
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

  /**
   * Copy the last generated nonce into buf at off.
   *
   * This is needed for session-bound PIN verification. When the card generated
   * its nonce (via generateNonce / INS_GET_NONCE) it stored the value in
   * lastNonce. Later, during INS_VERIFY_PIN, the card must recompute
   * SHA-256(lastNonce || storedPinHash) to check what the terminal sent.
   * PinManager needs the nonce bytes but has no direct access to CryptoUtil's
   * private lastNonce field, so processVerifyPin fetches a copy here and passes
   * it to PinManager.verify().
   *
   * @param buf buffer to copy the nonce into
   * @param off offset in buf where the nonce should be written
   * @return number of bytes written (NONCE_LENGTH)
   */
  public short getLastNonce(byte[] buf, short off) {
    Util.arrayCopy(lastNonce, (short) 0, buf, off, AppletConstants.NONCE_LENGTH);
    return AppletConstants.NONCE_LENGTH;
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
    verifyEngine.init(masterPubKey, Signature.MODE_VERIFY);
    return verifyEngine.verify(data, dOff, dLen, sig, sOff, sLen);
  }

  /**
   * Verify Sign_MSK(cardId || timestamp). Builds cardId||timestamp in tempBuf,
   * then delegates to verifyWithMPK. Prevents cross-card replay of signed timestamps.
   */
  public boolean verifySignedTimestamp(byte[] cardId, short cardIdOff, short cardIdLen,
      byte[] timestamp, short tsOff, short tsLen,
      byte[] sig, short sigOff, short sigLen) {
    Util.arrayCopy(cardId, cardIdOff, tempBuf, (short) 0, cardIdLen);
    Util.arrayCopy(timestamp, tsOff, tempBuf, cardIdLen, tsLen);
    return verifyWithMPK(tempBuf, (short) 0, (short) (cardIdLen + tsLen), sig, sigOff, sigLen);
  }

  /**
   * Verify Sign_MSK(cardId || INS_BLOCK_CARD) to authorize card blocking.
   */
  public boolean verifyBlockAuthorization(byte[] cardId, short cardIdOff, short cardIdLen,
      byte[] sig, short sigOff, short sigLen) {
    Util.arrayCopy(cardId, cardIdOff, tempBuf, (short)0, cardIdLen);
    tempBuf[cardIdLen] = AppletConstants.INS_BLOCK_CARD;
    return verifyWithMPK(tempBuf, (short)0, (short)(cardIdLen + 1), sig, sigOff, sigLen);
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
    // Cert format: [2B idLen][id][2B pkLen][pk][8B notAfter][2B sigLen][sig]
    // notAfter is part of the signed data, binding the cert to its validity window.
    short certSignedDataLen = (short) (2 + subjectIdLen + 2 + pubKeyLen + 8);
    short certSigLenOff = (short) (certOff + certSignedDataLen);
    short certSigLen = Util.getShort(buf, certSigLenOff);
    short certSigOff = (short) (certSigLenOff + 2);

    if (!verifyWithMPK(buf, certOff, certSignedDataLen, buf, certSigOff, certSigLen)) {
      return (short) 1;
    }

    tempPubKey.setW(buf, pubKeyOff, pubKeyLen);

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
