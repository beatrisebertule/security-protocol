package terminal.vehicle;

import java.security.*;
import java.util.*;
import java.util.Arrays;

import terminal.backend.BackendSystem;
import terminal.common.CardComm;
import terminal.common.CryptoUtil;
import terminal.common.ByteUtil;
import terminal.common.ProtocolConstants;
import terminal.common.Result;
import terminal.common.CardUtil;
import terminal.common.TokenUtil;
import terminal.common.VerboseLogger;
import terminal.messages.VehicleMessages;

/**
 * Vehicle terminal: offline authentication, mileage tracking, vehicle return.
 * Verifies card cryptographically using MPK. No backend connection during
 * operation.
 */
public class VehicleTerminal {

  private final CardComm comm;
  private final PublicKey masterPublicKey;
  private final byte[] vehicleId; // this vehicle's ID
  private short currentSeqNum = 0;
  private byte[] currentCardId = null;
  private final List<BackendSystem.AuditEntry> log = new ArrayList<>();

  /**
   * Constructs a VehicleTerminal bound to a specific vehicle and card channel.
   *
   * @param comm            channel used to send APDU commands to the smart card
   * @param masterPublicKey MPK used to verify assignment tokens (vehicleToken)
   * @param vehicleId       identifier of this vehicle, checked against tokens
   *                        during {@link #openVehicle()}
   */
  public VehicleTerminal(CardComm comm, PublicKey masterPublicKey, byte[] vehicleId) {
    this.comm = comm;
    this.masterPublicKey = masterPublicKey;
    this.vehicleId = vehicleId;
  }

  /**
   * Returns local audit log entries stored on the vehicle terminal.
   *
   * @return immutable view of audit log
   */
  public List<BackendSystem.AuditEntry> getLog() {
    return Collections.unmodifiableList(log);
  }

  /**
   * Sends locally stored log entries to the backend system.
   *
   * NOTE: Should only be called happens when the vehicle is parked at a reception
   * terminal
   *
   * @param backend backend instance receiving the logs
   */
  public void flushLogsToBackend(BackendSystem backend) {
    // Skip re-emitting to the audit file: localAudit already wrote each entry
    // when the event happened. We only need to populate the backend in-memory
    // auditLog so post-rental queries (e.g. backend.getAuditLog(cardId)) see them.
    for (BackendSystem.AuditEntry e : log) {
      backend.appendToAuditLogOnly(e);
    }
    log.clear();
  }

  /**
   * Appends an audit entry to the local offline log and immediately emits it to
   * the verbose audit stream. The local log is flushed to the backend on vehicle
   * return.
   *
   * @param eventType one of the {@code BackendSystem.EVENT_*} constants
   *                  (e.g. {@code EVENT_VEHICLE_OPENED},
   *                  {@code EVENT_VEHICLE_OPEN_FAIL},
   *
   * @param cardId
   *
   * @param evidence  cryptographic proof tied to the event (e.g. the
   *                  ephemeralVehicleToken on a successful open), or {@code null}
   *                  when no proof is available
   *
   * @param details   human-readable context string (e.g. error message on
   *                  failure, mileage value on update), or {@code null} when not
   *                  applicable
   */
  private void localAudit(String eventType, byte[] cardId, byte[] evidence, String details) {
    log.add(new BackendSystem.AuditEntry(eventType, cardId, vehicleId, evidence, details));
    VerboseLogger.get().audit(eventType, cardId, vehicleId, details);
  }

  /**
   * Verify the card is authorized to use this vehicle.
   * Checks vehicleToken (assignment token) and ephemeralVehicleToken (card signs
   * vehicleToken + nonce).
   *
   * @return Result wrapping card public key bytes if authorized; Result.fail
   *         otherwise. Every failure path is buffered to the offline `log` as
   *         EVENT_VEHICLE_OPEN_FAIL before returning.
   */
  public Result<byte[]> openVehicle() {

    // Read card ID early so failed attempts can still be logged.
    // If the card refuses INS_GET_CARD_ID (e.g. not personalized yet),
    // cardId stays null - same semantics as the old swallowed exception.
    byte[] cardId = null;
    Result<byte[]> idResult = comm.send(ProtocolConstants.INS_GET_CARD_ID);
    if (idResult.success) {
      cardId = idResult.value;
    }

    Result<byte[]> r = doOpenVehicle(cardId);
    if (!r.success) {
      localAudit(BackendSystem.EVENT_VEHICLE_OPEN_FAIL, cardId, null, r.error.getMessage());
    }
    return r;
  }

  /**
   * Performs the full cryptographic authorization sequence for a card.
   * Verifies the card is in ASSIGNED state, validates vehicleToken against MPK,
   * confirms the assigned vehicleId matches this terminal, verifies the card's
   * request signature (reqVehicleToken), then issues a nonce challenge and
   * verifies the card's ephemeralVehicleToken response.
   *
   * @param cardId card identifier, used only for audit logging; may be
   *               {@code null} if {@code INS_GET_CARD_ID} failed
   *
   * @return {@code Result.ok(pkc)} with the card's encoded public key bytes on
   *         success; {@code Result.fail} with a descriptive error on any
   *         verification failure
   */
  private Result<byte[]> doOpenVehicle(byte[] cardId) {
    // Get smart-card's state
    Result<byte[]> stateResult = comm.send(ProtocolConstants.INS_GET_STATE);
    if (!stateResult.success) {
      return Result.fail(stateResult.error);
    }

    // Is it assigned? It must be
    byte state = stateResult.value[0];
    if (state != ProtocolConstants.STATE_ASSIGNED) {
      return Result.fail(VehicleMessages.errCardNotAssigned(state));
    }

    // Get assignment token (vehicleToken)
    Result<byte[]> vehicleTokenResult = comm.send(ProtocolConstants.INS_GET_ASSIGNMENT_DATA);
    if (!vehicleTokenResult.success) {
      return Result.fail(vehicleTokenResult.error);
    }
    byte[] vehicleToken = vehicleTokenResult.value;
    VerboseLogger.get().step("vehicleToken read from card (" + vehicleToken.length + " bytes)");

    // Make sure that the vehicleToken is for this vehicle
    // Parse vehicleToken:
    // [1B reqDataLen][reqData]
    // [1B reqVehicleTokenLen][reqVehicleToken]
    // [1B pkcLen][pkc]
    // [1B sigLen][sig]
    byte[][] vehicleTokenParts = TokenUtil.parseAssignmentToken(vehicleToken);
    byte[] reqData = vehicleTokenParts[0];
    byte[] reqVehicleToken = vehicleTokenParts[1];
    byte[] pkc = vehicleTokenParts[2];
    byte[] sig = vehicleTokenParts[3];

    // Verify vehicleToken against MPK: verify(MSK, reqVehicleToken || pkc)
    byte[] dataToVerify = ByteUtil.concat(reqVehicleToken, pkc);
    try {
      if (!CryptoUtil.verify(masterPublicKey, dataToVerify, sig)) {
        return Result.fail(VehicleMessages.ERR_VEHICLE_TOKEN_INVALID);
      }
    } catch (GeneralSecurityException e) {
      return Result.fail(VehicleMessages.ERR_VEHICLE_TOKEN_CRYPTO, e);
    }
    VerboseLogger.get().step("vehicleToken verified against MPK");

    // Check vehicleId in reqData matches this vehicle
    byte[] assignedVehicleId = Arrays.copyOf(reqData, ProtocolConstants.VEHICLE_ID_LENGTH);
    // Prevent cards assigned to other vehicles from being reused here
    if (!Arrays.equals(assignedVehicleId, this.vehicleId)) {
      return Result.fail(VehicleMessages.ERR_WRONG_VEHICLE);
    }

    // Verify reqVehicleToken: card signed reqData with skc
    PublicKey cardPubKey;
    try {
      cardPubKey = CryptoUtil.decodePublicKey(pkc);
      if (!CryptoUtil.verify(cardPubKey, reqData, reqVehicleToken)) {
        return Result.fail(VehicleMessages.ERR_REQ_VEHICLE_TOKEN_INVALID);
      }
    } catch (GeneralSecurityException e) {
      return Result.fail(VehicleMessages.ERR_REQ_VEHICLE_TOKEN_CRYPTO, e);
    }

    // Generate vehicle nonce, get card to sign (vehicleToken || vehicleNonce)
    byte[] vehicleNonce = CryptoUtil.generateNonce(ProtocolConstants.NONCE_LENGTH);
    VerboseLogger.get().step("vehicle nonce generated");
    Result<byte[]> ephemeralVehicleTokenResult = comm.send(ProtocolConstants.INS_SIGN_VEHICLE_CHALL, vehicleNonce);
    if (!ephemeralVehicleTokenResult.success) {
      return Result.fail(ephemeralVehicleTokenResult.error);
    }
    byte[] ephemeralVehicleToken = ephemeralVehicleTokenResult.value;
    VerboseLogger.get().step("ephemeralVehicleToken received from card (" + ephemeralVehicleToken.length + " bytes)");

    // Verify ephemeralVehicleToken: card signed (vehicleToken || vehicleNonce) with
    // skc
    byte[] challengeData = ByteUtil.concat(vehicleToken, vehicleNonce);
    try {
      if (!CryptoUtil.verify(cardPubKey, challengeData, ephemeralVehicleToken)) {
        return Result.fail(VehicleMessages.ERR_EPHEMERAL_TOKEN_INVALID);
      }
    } catch (GeneralSecurityException e) {
      return Result.fail(VehicleMessages.ERR_EPHEMERAL_TOKEN_CRYPTO, e);
    }
    VerboseLogger.get().step("ephemeralVehicleToken verified against pkc");

    currentSeqNum = 0;
    currentCardId = cardId;
    localAudit(BackendSystem.EVENT_VEHICLE_OPENED, cardId, ephemeralVehicleToken, null);
    return Result.ok(pkc);
  }

  /**
   * Sends a mileage update to the card, guarded by a strictly increasing
   * sequence number to prevent replay attacks.
   *
   * @param mileage new odometer reading in km; must be &ge; the value currently
   *                stored on the card
   *
   * @return {@code Result.ok()} on success; {@code Result.fail} if the card
   *         cannot be read, the mileage is rolled back (attacker?), or the APDU
   *         is rejected
   */
  public Result<Void> updateMileage(short mileage) {
    Result<Short> prevResult = getMileage();
    if (!prevResult.success) {
      localAudit(BackendSystem.EVENT_MILEAGE_UPDATE, currentCardId, null,
          "FAILED: read previous mileage: " + prevResult.error.getMessage());
      return Result.fail(prevResult.error);
    }
    short previousMileage = prevResult.value;

    // Mileage should not decrease
    if (mileage < previousMileage) {
      localAudit(BackendSystem.EVENT_MILEAGE_UPDATE, currentCardId, null,
          "FAILED: rollback detected (old=" + previousMileage + ", new=" + mileage + ")");
      return Result.fail(VehicleMessages.ERR_MILEAGE_ROLLBACK);
    }

    byte[] data = new byte[4];

    data[0] = (byte) ((mileage >> 8) & 0xFF);
    data[1] = (byte) (mileage & 0xFF);
    data[2] = (byte) ((currentSeqNum >> 8) & 0xFF);
    data[3] = (byte) (currentSeqNum & 0xFF);

    VerboseLogger.get().step("mileage update sent to card (new=" + mileage + ")");
    Result<byte[]> sendResult = comm.send(ProtocolConstants.INS_UPDATE_MILEAGE, data);
    if (!sendResult.success) {
      localAudit(BackendSystem.EVENT_MILEAGE_UPDATE, currentCardId, null,
          "FAILED: " + sendResult.error.getMessage());
      return Result.fail(sendResult.error);
    }
    currentSeqNum++;

    localAudit(BackendSystem.EVENT_MILEAGE_UPDATE, currentCardId, null,
        "old=" + previousMileage + ", new=" + mileage);
    return Result.ok();
  }

  /**
   * Reads the current mileage stored on the smart card.
   *
   * @return {@code Result.ok(mileage)} with the odometer value in km on success;
   *         {@code Result.fail} if the card rejects {@code INS_GET_MILEAGE}
   */
  public Result<Short> getMileage() {
    Result<byte[]> r = comm.send(ProtocolConstants.INS_GET_MILEAGE);
    if (!r.success) {
      return Result.fail(r.error);
    }
    return Result.ok(ByteUtil.bytesToShort(r.value, 0));
  }

  // Vehicle return (Figure 3)
  /**
   * Return vehicle: send final mileage, get signed receipt, card goes back to
   * ISSUED.
   *
   * @param finalMileage final odometer reading
   * @param cardPkc      card public key bytes (from openVehicle)
   * @return signed receipt bytes: [2B mileage][signature]
   */
  public Result<byte[]> returnVehicle(short finalMileage, byte[] cardPkc) {
    byte[] data = new byte[2];
    data[0] = (byte) ((finalMileage >> 8) & 0xFF);
    data[1] = (byte) (finalMileage & 0xFF);

    VerboseLogger.get().step("return command sent to card");
    Result<byte[]> sendResult = comm.send(ProtocolConstants.INS_RETURN_VEHICLE, data);
    if (!sendResult.success) {
      return Result.fail(sendResult.error);
    }
    byte[] receipt = sendResult.value;
    VerboseLogger.get().step("receipt signature received (" + (receipt.length - 2) + " bytes)");

    // Verify receipt signature: card signed the 2-byte mileage
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
   * Entry point. Sets up a simulated card (personalized, issued, assigned),
   * then runs the vehicle terminal menu.
   */
  public static void main(String[] args) throws Exception {
    // Backend
    BackendSystem.reset();
    BackendSystem backend = BackendSystem.getInstance();
    backend.init();
    byte[] vehicleId = { 0x00, 0x00, 0x00, 0x01 };
    backend.registerVehicle(vehicleId, "AB-123-CD");
    byte[] customerId = { 0x00, 0x00, 0x00, 0x01 };
    backend.registerCustomer(customerId, "Alice");

    // JCardSim
    com.licel.jcardsim.smartcardio.CardSimulator simulator = new com.licel.jcardsim.smartcardio.CardSimulator();
    byte[] APPLET_AID = {
        (byte) 0x3B, (byte) 0x29, (byte) 0x72, (byte) 0x65, (byte) 0x6E, (byte) 0x74, (byte) 0x01
    };
    javacard.framework.AID aid = new javacard.framework.AID(
        APPLET_AID, (byte) 0, (byte) APPLET_AID.length);
    simulator.installApplet(aid, applet.RentalCardApplet.class);

    javax.smartcardio.CardTerminals terminals = com.licel.jcardsim.smartcardio.CardTerminalSimulator
        .terminals("VehicleTerminal");
    javax.smartcardio.CardTerminal terminal = terminals.getTerminal("VehicleTerminal");
    simulator.assignToTerminal(terminal);

    javax.smartcardio.Card card = terminal.connect("*");
    javax.smartcardio.CardChannel channel = card.getBasicChannel();

    channel.transmit(new javax.smartcardio.CommandAPDU(
        (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, APPLET_AID));

    CardComm comm = new CardComm(channel);

    // Personalize + issue
    byte[] cardId = { 0x00, 0x00, 0x00, 0x01 };
    terminal.personalization.PersonalizationTerminal pt = new terminal.personalization.PersonalizationTerminal(comm,
        backend);
    pt.personalizeCard(cardId, "1234");
    pt.issueCard(customerId);

    // Mutual auth + assign vehicle
    terminal.reception.ReceptionTerminal rt = new terminal.reception.ReceptionTerminal(comm, backend);
    Result<byte[]> authR = rt.mutualAuth("1234");
    if (!authR.success)
      throw new RuntimeException("mutualAuth failed: " + authR.error.getMessage());
    byte[] pkc = authR.value;
    long now = System.currentTimeMillis() / 1000;
    byte[] period = new byte[8];
    period[0] = (byte) ((now >> 24) & 0xFF);
    period[1] = (byte) ((now >> 16) & 0xFF);
    period[2] = (byte) ((now >> 8) & 0xFF);
    period[3] = (byte) (now & 0xFF);
    long end = now + 86400;
    period[4] = (byte) ((end >> 24) & 0xFF);
    period[5] = (byte) ((end >> 16) & 0xFF);
    period[6] = (byte) ((end >> 8) & 0xFF);
    period[7] = (byte) (end & 0xFF);
    rt.assignVehicle(vehicleId, customerId, pkc, period);

    System.out.println("Card assigned to vehicle AB-123-CD.");
    System.out.println("Vehicle ID: " + ByteUtil.toHex(vehicleId));

    // Run CLI
    new VehicleTerminal(comm, backend.getMasterPublicKey(), vehicleId).runCLI();
  }

  /**
   * Starts the interactive vehicle terminal menu on stdin/stdout.
   * Options: open vehicle (1), update mileage (2), return vehicle (3),
   * get mileage (4), get card state (5), exit (0). Exits automatically
   * after a successful vehicle return.
   */
  public void runCLI() {
    Scanner scanner = new Scanner(System.in);
    System.out.println("=== Vehicle Terminal [" + ByteUtil.toHex(vehicleId) + "] ===");
    byte[] cardPkc = null;

    try {
      boolean running = true;
      while (running) {
        System.out.println("\n1) Open vehicle (verify card)");
        System.out.println("2) Update mileage");
        System.out.println("3) Return vehicle");
        System.out.println("4) Get mileage");
        System.out.println("5) Get card state");
        System.out.println("0) Exit");
        System.out.print("Choice: ");
        String choice = scanner.nextLine().trim();

        switch (choice) {
          case "1":
            System.out.println("Verifying card...");
            Result<byte[]> openR = openVehicle();
            if (!openR.success) {
              System.err.println("Open failed: " + openR.error.getMessage());
              break;
            }
            cardPkc = openR.value;
            System.out.println("Vehicle unlocked.");
            break;
          case "2":
            if (cardPkc == null) {
              System.out.println("Open vehicle first.");
              break;
            }
            System.out.print("Mileage (km): ");
            short m = Short.parseShort(scanner.nextLine().trim());
            Result<Void> updR = updateMileage(m);
            if (!updR.success) {
              System.err.println("Update failed: " + updR.error.getMessage());
              break;
            }
            System.out.println("Mileage updated: " + m + " km");
            break;
          case "3":
            if (cardPkc == null) {
              System.out.println("Open vehicle first.");
              break;
            }
            System.out.print("Final mileage (km): ");
            short fm = Short.parseShort(scanner.nextLine().trim());
            Result<byte[]> retR = returnVehicle(fm, cardPkc);
            if (!retR.success) {
              System.err.println("Return failed: " + retR.error.getMessage());
              break;
            }
            System.out.println("Vehicle returned. Card state: ISSUED.");
            cardPkc = null;
            running = false;
            break;
          case "4":
            Result<Short> milR = getMileage();
            if (!milR.success) {
              System.err.println("Mileage read failed: " + milR.error.getMessage());
            } else {
              System.out.println("Mileage: " + milR.value + " km");
            }
            break;
          case "5":
            Result<Byte> stR = CardUtil.getCardState(comm);
            if (!stR.success) {
              System.err.println("State read failed: " + stR.error.getMessage());
            } else {
              System.out.println("State: 0x" + String.format("%02X", stR.value));
            }
            break;
          case "0":
            running = false;
            break;
          default:
            System.out.println("Unknown option.");
        }
      }
    } catch (Exception e) {
      System.err.println("Error: " + e.getMessage());
    }
  }
}
