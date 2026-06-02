package terminal.personalization;

import java.security.GeneralSecurityException;
import java.time.LocalDate;
import java.time.ZoneOffset;

import terminal.TerminalBase;
import terminal.backend.BackendSystem;
import terminal.util.ByteUtil;
import terminal.util.CardComm;
import terminal.util.CryptoUtil;
import terminal.util.ProtocolConstants;
import terminal.logging.Result;
import terminal.logging.messages.PersonalizationMessages;

/**
 * Base personalization terminal logic.
 *
 * The base class implements personalization and card issuance flows while
 * delegating any user-facing step notification to subclasses via show.
 */
public abstract class PersonalizationTerminalBase extends TerminalBase {

  protected final BackendSystem backend;

  /**
   * Constructor for PersonalizationTerminalBase.
   */
  public PersonalizationTerminalBase(CardComm comm, BackendSystem backend) {
    super(comm);
    this.backend = backend;
  }

  /**
   * Full card personalization: BLANK -> PERSONALIZED.
   * Uses default expiry of 5 years from the current date.
   *
   * @param cardId 4-byte card identifier
   * @param pin    PIN string (will be SHA-256 hashed)
   */
  public Result<Void> personalizeCard(byte[] cardId, String pin) {
    long expiry = LocalDate.now(ZoneOffset.UTC).plusYears(5)
        .atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli();
    return personalizeCard(cardId, pin, expiry);
  }

  /**
   * Full card personalization with explicit expiry date.
   * BLANK -> PERSONALIZED.
   *
   * @param cardId       4-byte card identifier
   * @param pin          PIN string (will be SHA-256 hashed)
   * @param expiryMillis expiry timestamp in milliseconds since epoch
   */
  public Result<Void> personalizeCard(byte[] cardId, String pin, long expiryMillis) {
    // Personalize the keys first since it's the most likely to fail (backend signing, crypto issues) and we want to 
    // make sure the card is still blank if personalization fails partway through.
    byte[] mpk = backend.getMasterPublicKeyEncoded();
    Result<byte[]> keysResult = comm.send(
        ProtocolConstants.INS_PERSONALIZE_KEYS, (byte) 0x00, (byte) 0x00, mpk);
    if (!keysResult.success) {
      return Result.fail(keysResult.error);
    }
    showMessage("MPK installed on card");
    byte[] pkc = keysResult.value;
    showMessage("card keypair generated on card; pkc retrieved (" + pkc.length + " bytes)");
    // Keypair is generated on card and pkc retrieved - now ask backend to sign certificate for the card's public key and store it on the card
    byte[] cert;
    try {
      cert = backend.signCertificate(cardId, pkc);
    } catch (GeneralSecurityException e) {
      return Result.fail(PersonalizationMessages.ERR_CERT_SIGNING, e);
    }
    showMessage("certificate signed by backend");
    Result<byte[]> storeCertResult = comm.send(
        ProtocolConstants.INS_PERSONALIZE_KEYS, (byte) 0x01, (byte) 0x00, cert);
    if (!storeCertResult.success) {
      return Result.fail(storeCertResult.error);
    }
    showMessage("certificate stored on card");

    //Certificate is stored - now set the PIN and expiry/card ID, which transitions the card to PERSONALIZED state. Do these last since if they fail, the card is still blank and can be re-personalized.

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
    showMessage("PIN hash set on card");

    // Set card ID and expiry, which also transitions the card to PERSONALIZED state. Do this last since if it fails, the card is still blank and can be re-personalized.

    byte[] expiry = ByteUtil.longToBytes(expiryMillis);
    byte[] payload = new byte[ProtocolConstants.CARD_ID_LENGTH + ProtocolConstants.EXPIRY_DATE_LENGTH];
    System.arraycopy(cardId, 0, payload, 0, ProtocolConstants.CARD_ID_LENGTH);
    System.arraycopy(expiry, 0, payload, ProtocolConstants.CARD_ID_LENGTH, ProtocolConstants.EXPIRY_DATE_LENGTH);
    Result<byte[]> finishResult = comm.send(ProtocolConstants.INS_PERSONALIZE_FINISH, payload);
    if (!finishResult.success) {
      return Result.fail(finishResult.error);
    }
    showMessage("card ID + expiry set; card transitioned to PERSONALIZED");

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
    showMessage("card state transitioned to ISSUED");
    return Result.ok();
  }

}
