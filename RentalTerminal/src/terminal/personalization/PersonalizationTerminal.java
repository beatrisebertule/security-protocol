package terminal.personalization;

import java.security.GeneralSecurityException;

import terminal.backend.BackendSystem;
import terminal.util.ByteUtil;
import terminal.common.CardComm;
import terminal.util.CryptoUtil;
import terminal.common.ProtocolConstants;
import terminal.logging.Result;
import terminal.logging.VerboseLogger;
import terminal.logging.messages.PersonalizationMessages;

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
    VerboseLogger.get().step("MPK installed on card");
    byte[] pkc = keysResult.value;
    VerboseLogger.get().step("card keypair generated on card; pkc retrieved (" + pkc.length + " bytes)");

    // Step 2: backend signs certificate, store on card
    byte[] cert;
    try {
      cert = backend.signCertificate(cardId, pkc);
    } catch (GeneralSecurityException e) {
      return Result.fail(PersonalizationMessages.ERR_CERT_SIGNING, e);
    }
    VerboseLogger.get().step("certificate signed by backend");
    Result<byte[]> storeCertResult = comm.send(
        ProtocolConstants.INS_PERSONALIZE_KEYS, (byte) 0x01, (byte) 0x00, cert);
    if (!storeCertResult.success) {
      return Result.fail(storeCertResult.error);
    }
    VerboseLogger.get().step("certificate stored on card");

    // Step 3: set PIN hash
    byte[] pinHash;
    try {
      pinHash = CryptoUtil.hashPin(pin);
    } catch (GeneralSecurityException e) {
      return Result.fail(PersonalizationMessages.ERR_PIN_HASHING, e);
    }
    Result<byte[]> pinResult = comm.send(ProtocolConstants.INS_PERSONALIZE_PIN, pinHash);
    if (!pinResult.success) {
      return Result.fail(pinResult.error);
    }
    VerboseLogger.get().step("PIN hash set on card");

    // Step 4: finalize - store card ID + expiry, transition to PERSONALIZED
    byte[] expiry = ByteUtil.longToBytes(expiryMillis);
    byte[] payload = new byte[ProtocolConstants.CARD_ID_LENGTH + ProtocolConstants.EXPIRY_DATE_LENGTH];
    System.arraycopy(cardId, 0, payload, 0, ProtocolConstants.CARD_ID_LENGTH);
    System.arraycopy(expiry, 0, payload, ProtocolConstants.CARD_ID_LENGTH, ProtocolConstants.EXPIRY_DATE_LENGTH);
    Result<byte[]> finishResult = comm.send(ProtocolConstants.INS_PERSONALIZE_FINISH, payload);
    if (!finishResult.success) {
      return Result.fail(finishResult.error);
    }
    VerboseLogger.get().step("card ID + expiry set; card transitioned to PERSONALIZED");

    return Result.ok();
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
    VerboseLogger.get().step("card state transitioned to ISSUED");
    return Result.ok();
  }

}
