package terminal.vehicle;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

import terminal.TerminalBase;
import terminal.backend.BackendSystem;
import terminal.util.ByteUtil;
import terminal.util.CardComm;
import terminal.util.CryptoUtil;
import terminal.util.ProtocolConstants;
import terminal.util.TokenUtil;
import terminal.logging.LocalAuditLog;
import terminal.logging.Result;
import terminal.logging.messages.VehicleMessages;

/**
 * Base class for vehicle terminal. Contains all protocol logic shared across
 * vehicle terminal implementations.
 */
public abstract class VehicleTerminalBase extends TerminalBase {
  protected final PublicKey masterPublicKey;
  protected final KeyPair terminalKeyPair;
  protected final byte[] terminalCertificate;
  protected final byte[] vehicleId;
  protected short currentSeqNum = 0;
  protected byte[] currentCardId = null;
  public final LocalAuditLog auditLog = new LocalAuditLog();

  public VehicleTerminalBase(CardComm comm, PublicKey masterPublicKey,
      KeyPair terminalKeyPair, byte[] terminalCertificate, byte[] vehicleId) {
    super(comm);
    this.masterPublicKey = masterPublicKey;
    this.terminalKeyPair = terminalKeyPair;
    this.terminalCertificate = terminalCertificate;
    this.vehicleId = vehicleId;
  }

  /** Start the interactive vehicle terminal menu. Implemented by subclasses. */
  public abstract void runCLI();

  /**
   * Reads the current mileage stored on the smart card.
   *
   * @return {@code Result.ok(mileage)} on success; {@code Result.fail} otherwise
   */
  public Result<Short> getMileage() {
    Result<byte[]> r = comm.send(ProtocolConstants.INS_GET_MILEAGE);
    if (!r.success) {
      return Result.fail(r.error);
    }
    return Result.ok(ByteUtil.bytesToShort(r.value, 0));
  }

  /**
   * Verify the card is authorized to use this vehicle.
   * Performs terminal authentication, then checks
   * vehicleToken (assignment token) and ephemeralVehicleToken (card signs
   * vehicleToken + nonce).
   *
   * @return Result wrapping card public key bytes if authorized; Result.fail
   *         otherwise. Every failure path is buffered to the offline log as
   *         EVENT_VEHICLE_OPEN_FAIL before returning.
   */
  public Result<byte[]> open() {
    byte[] cardId = null;
    Result<byte[]> idResult = comm.send(ProtocolConstants.INS_GET_CARD_ID);
    if (idResult.success) {
      cardId = idResult.value;
    }

    Result<byte[]> r = executeOpenProtocol(cardId);
    if (!r.success) {
      auditLog.record(BackendSystem.EVENT_VEHICLE_OPEN_FAIL, cardId, vehicleId, null, r.error.getMessage());
    }
    return r;
  }

  /**
   * Return vehicle: send final mileage, get signed receipt, card goes back to
   * ISSUED.
   *
   * @param finalMileage final odometer reading
   * @param cardPkc      card public key bytes (from open)
   * @return signed receipt bytes: [2B mileage][signature]
   */
  public Result<byte[]> returnVehicle(short finalMileage, byte[] cardPkc) {
    byte[] data = new byte[2];
    data[0] = (byte) ((finalMileage >> 8) & 0xFF);
    data[1] = (byte) (finalMileage & 0xFF);

    log("return command sent to card");
    Result<byte[]> sendResult = comm.send(ProtocolConstants.INS_RETURN_VEHICLE, data);
    if (!sendResult.success) {
      return Result.fail(sendResult.error);
    }
    byte[] receipt = sendResult.value;
    log("receipt signature received (" + (receipt.length - 2) + " bytes)");

    int sigLen = receipt.length - 2;
    if (sigLen <= 0) {
      return Result.fail(VehicleMessages.ERR_RECEIPT_MISSING_SIG);
    }
    byte[] mileageBytes = new byte[2];
    System.arraycopy(receipt, 0, mileageBytes, 0, 2);
    byte[] sig = new byte[sigLen];
    System.arraycopy(receipt, 2, sig, 0, sigLen);

    try {
      PublicKey cardPubKey = CryptoUtil.decodePublicKey(cardPkc);
      if (!CryptoUtil.verify(cardPubKey, mileageBytes, sig)) {
        return Result.fail(VehicleMessages.ERR_RECEIPT_SIG_INVALID);
      }
    } catch (GeneralSecurityException e) {
      return Result.fail(VehicleMessages.ERR_RECEIPT_CRYPTO, e);
    }

    return Result.ok(receipt);
  }

  /**
   * Sends a mileage update to the card, guarded by a strictly increasing
   * sequence number to prevent replay attacks.
   *
   * @param mileage new odometer reading in km; must be &ge; current card value
   * @return {@code Result.ok()} on success; {@code Result.fail} otherwise
   */
  public Result<Void> updateMileage(short mileage) {
    Result<Short> prevResult = getMileage();
    if (!prevResult.success) {
      auditLog.record(BackendSystem.EVENT_MILEAGE_UPDATE, currentCardId, vehicleId, null,
          "FAILED: read previous mileage: " + prevResult.error.getMessage());
      return Result.fail(prevResult.error);
    }
    short previousMileage = prevResult.value;

    if (mileage < previousMileage) {
      auditLog.record(BackendSystem.EVENT_MILEAGE_UPDATE, currentCardId, vehicleId, null,
          "FAILED: rollback detected (old=" + previousMileage + ", new=" + mileage + ")");
      return Result.fail(VehicleMessages.ERR_MILEAGE_ROLLBACK);
    }

    byte[] data = new byte[4];
    data[0] = (byte) ((mileage >> 8) & 0xFF);
    data[1] = (byte) (mileage & 0xFF);
    data[2] = (byte) ((currentSeqNum >> 8) & 0xFF);
    data[3] = (byte) (currentSeqNum & 0xFF);

    log("mileage update sent to card (new=" + mileage + ")");
    Result<byte[]> sendResult = comm.send(ProtocolConstants.INS_UPDATE_MILEAGE, data);
    if (!sendResult.success) {
      auditLog.record(BackendSystem.EVENT_MILEAGE_UPDATE, currentCardId, vehicleId, null,
          "FAILED: " + sendResult.error.getMessage());
      return Result.fail(sendResult.error);
    }
    currentSeqNum++;

    auditLog.record(BackendSystem.EVENT_MILEAGE_UPDATE, currentCardId, vehicleId, null,
        "old=" + previousMileage + ", new=" + mileage);
    return Result.ok();
  }

  private Result<byte[]> executeOpenProtocol(byte[] cardId) {
    Result<byte[]> stateResult = comm.send(ProtocolConstants.INS_GET_STATE);
    if (!stateResult.success)
      return Result.fail(stateResult.error);
    byte state = stateResult.value[0];
    if (state != ProtocolConstants.STATE_ASSIGNED)
      return Result.fail(VehicleMessages.errCardNotAssigned(state));

    Result<Void> authResult = authenticateTerminal();
    if (!authResult.success)
      return Result.fail(authResult.error);

    Result<byte[][]> tokenResult = fetchAndVerifyAssignmentToken();
    if (!tokenResult.success)
      return Result.fail(tokenResult.error);
    byte[] vehicleToken = tokenResult.value[0];
    byte[] pkc = tokenResult.value[1];

    Result<byte[]> challengeResult = verifyCardChallenge(vehicleToken, pkc);
    if (!challengeResult.success)
      return Result.fail(challengeResult.error);

    currentCardId = cardId;
    auditLog.record(BackendSystem.EVENT_VEHICLE_OPENED, cardId, vehicleId, challengeResult.value, null);
    return Result.ok(pkc);
  }

  // Fetches card nonce and authenticates terminal (sets FLAG_TERMINAL_AUTH).
  private Result<Void> authenticateTerminal() {
    Result<byte[]> nonceResult = comm.send(ProtocolConstants.INS_GET_NONCE);
    if (!nonceResult.success)
      return Result.fail(nonceResult.error);
    byte[] cardNonce = nonceResult.value;
    log("card nonce received for terminal authentication");

    Result<Void> termAuthResult = sendTerminalAuth(cardNonce, terminalKeyPair, terminalCertificate);
    if (!termAuthResult.success)
      return Result.fail(termAuthResult.error);
    log("terminal authenticated to card");

    return Result.ok();
  }

  // Reads and validates the assignment token: MPK signature, vehicle ID match,
  // and card self-signature. Returns [vehicleToken, pkc].
  private Result<byte[][]> fetchAndVerifyAssignmentToken() {
    Result<byte[]> vehicleTokenResult = comm.send(ProtocolConstants.INS_GET_ASSIGNMENT_DATA);
    if (!vehicleTokenResult.success)
      return Result.fail(vehicleTokenResult.error);
    byte[] vehicleToken = vehicleTokenResult.value;
    log("vehicleToken read from card (" + vehicleToken.length + " bytes)");

    byte[][] parts = TokenUtil.parseAssignmentToken(vehicleToken);
    byte[] reqData = parts[0];
    byte[] reqVehicleToken = parts[1];
    byte[] pkc = parts[2];
    byte[] sig = parts[3];

    try {
      if (!CryptoUtil.verify(masterPublicKey, ByteUtil.concat(reqVehicleToken, pkc), sig))
        return Result.fail(VehicleMessages.ERR_VEHICLE_TOKEN_INVALID);
    } catch (GeneralSecurityException e) {
      return Result.fail(VehicleMessages.ERR_VEHICLE_TOKEN_CRYPTO, e);
    }
    log("vehicleToken verified against MPK");

    if (!Arrays.equals(Arrays.copyOf(reqData, ProtocolConstants.VEHICLE_ID_LENGTH), this.vehicleId))
      return Result.fail(VehicleMessages.ERR_WRONG_VEHICLE);

    try {
      if (!CryptoUtil.verify(CryptoUtil.decodePublicKey(pkc), reqData, reqVehicleToken))
        return Result.fail(VehicleMessages.ERR_REQ_VEHICLE_TOKEN_INVALID);
    } catch (GeneralSecurityException e) {
      return Result.fail(VehicleMessages.ERR_REQ_VEHICLE_TOKEN_CRYPTO, e);
    }

    return Result.ok(new byte[][] { vehicleToken, pkc });
  }

  // Generates vehicle nonce and verifies card's signed challenge.
  // Seeds currentSeqNum from vehicleNonce on success. Returns
  // ephemeralVehicleToken.
  private Result<byte[]> verifyCardChallenge(byte[] vehicleToken, byte[] pkc) {
    byte[] vehicleNonce = CryptoUtil.generateNonce(ProtocolConstants.NONCE_LENGTH);
    log("vehicle nonce generated");

    Result<byte[]> ephemeralResult = comm.send(ProtocolConstants.INS_SIGN_VEHICLE_CHALL, vehicleNonce);
    if (!ephemeralResult.success)
      return Result.fail(ephemeralResult.error);
    byte[] ephemeralVehicleToken = ephemeralResult.value;
    log("ephemeralVehicleToken received from card (" + ephemeralVehicleToken.length + " bytes)");

    try {
      if (!CryptoUtil.verify(CryptoUtil.decodePublicKey(pkc), ByteUtil.concat(vehicleToken, vehicleNonce),
          ephemeralVehicleToken))
        return Result.fail(VehicleMessages.ERR_EPHEMERAL_TOKEN_INVALID);
    } catch (GeneralSecurityException e) {
      return Result.fail(VehicleMessages.ERR_EPHEMERAL_TOKEN_CRYPTO, e);
    }
    log("ephemeralVehicleToken verified against pkc");

    // Seed from vehicleNonce so each session's sequence space is unpredictable,
    // preventing replay of UPDATE_MILEAGE APDUs captured from a previous session.
    currentSeqNum = ByteUtil.bytesToShort(vehicleNonce, 0);
    return Result.ok(ephemeralVehicleToken);
  }
}
