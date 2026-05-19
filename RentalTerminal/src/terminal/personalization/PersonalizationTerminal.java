package terminal.personalization;

import java.security.GeneralSecurityException;

import terminal.backend.BackendSystem;
import terminal.common.CardComm;
import terminal.common.CryptoUtil;
import terminal.common.ProtocolConstants;
import terminal.common.Result;

/**
 * Personalization terminal: initializes a blank card with keys, certificate,
 * PIN.
 * Transitions: BLANK -> PERSONALIZED -> ISSUED.
 *
 * All public protocol methods return Result<T>; on failure the caller can
 * inspect Result.error without stack unwinding. CryptoUtil and backend
 * methods still throw GeneralSecurityException - they are wrapped here.
 */
public class PersonalizationTerminal {

  private final CardComm comm;
  private final BackendSystem backend;

  public PersonalizationTerminal(CardComm comm, BackendSystem backend) {
    this.comm = comm;
    this.backend = backend;
  }

  /**
   * Full card personalization: BLANK -> PERSONALIZED.
   * Uses default expiry of year 2100.
   *
   * @param cardId 4-byte card identifier
   * @param pin    PIN string (will be SHA-256 hashed)
   */
  public Result<Void> personalizeCard(byte[] cardId, String pin) {
    return personalizeCard(cardId, pin, 4102444800000L);
  }

  /**
   * Full card personalization with explicit expiry date.
   *
   * @param cardId       4-byte card identifier
   * @param pin          PIN string (will be SHA-256 hashed)
   * @param expiryMillis expiry timestamp in milliseconds since epoch
   */
  public Result<Void> personalizeCard(byte[] cardId, String pin, long expiryMillis) {
    // Step 1: send MPK, trigger on-card keypair generation, receive pkc
    byte[] mpk = backend.getMasterPublicKeyEncoded();
    Result<byte[]> keysResult = comm.send(
        ProtocolConstants.INS_PERSONALIZE_KEYS, (byte) 0x00, (byte) 0x00, mpk);
    if (!keysResult.success) {
      return Result.fail(keysResult.error);
    }
    byte[] pkc = keysResult.value;

    // Step 2: backend signs certificate, store on card
    byte[] cert;
    try {
      cert = backend.signCertificate(cardId, pkc);
    } catch (GeneralSecurityException e) {
      return Result.fail("certificate signing failed", e);
    }
    Result<byte[]> storeCertResult = comm.send(
        ProtocolConstants.INS_PERSONALIZE_KEYS, (byte) 0x01, (byte) 0x00, cert);
    if (!storeCertResult.success) {
      return Result.fail(storeCertResult.error);
    }

    // Step 3: set PIN hash
    byte[] pinHash;
    try {
      pinHash = CryptoUtil.hashPin(pin);
    } catch (GeneralSecurityException e) {
      return Result.fail("PIN hashing failed", e);
    }
    Result<byte[]> pinResult = comm.send(ProtocolConstants.INS_PERSONALIZE_PIN, pinHash);
    if (!pinResult.success) {
      return Result.fail(pinResult.error);
    }

    // Step 4: finalize - store card ID + expiry, transition to PERSONALIZED
    byte[] expiry = longToBytes(expiryMillis);
    byte[] payload = new byte[ProtocolConstants.CARD_ID_LENGTH + ProtocolConstants.EXPIRY_DATE_LENGTH];
    System.arraycopy(cardId, 0, payload, 0, ProtocolConstants.CARD_ID_LENGTH);
    System.arraycopy(expiry, 0, payload, ProtocolConstants.CARD_ID_LENGTH, ProtocolConstants.EXPIRY_DATE_LENGTH);
    Result<byte[]> finishResult = comm.send(ProtocolConstants.INS_PERSONALIZE_FINISH, payload);
    if (!finishResult.success) {
      return Result.fail(finishResult.error);
    }

    return Result.ok();
  }

  private static byte[] longToBytes(long v) {
    byte[] b = new byte[8];
    for (int i = 7; i >= 0; i--) {
      b[i] = (byte) (v & 0xFF);
      v >>= 8;
    }
    return b;
  }

  /**
   * Issue card to customer: PERSONALIZED -> ISSUED.
   *
   * @param customerId 4-byte customer identifier
   */
  public Result<Void> issueCard(byte[] customerId) {
    Result<byte[]> r = comm.send(ProtocolConstants.INS_ISSUE_CARD, customerId);
    if (!r.success) {
      return Result.fail(r.error);
    }
    return Result.ok();
  }

  /**
   * Get current card state.
   */
  public Result<Byte> getCardState() {
    Result<byte[]> r = comm.send(ProtocolConstants.INS_GET_STATE);
    if (!r.success) {
      return Result.fail(r.error);
    }
    return Result.ok(r.value[0]);
  }
}
