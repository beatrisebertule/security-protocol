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
import terminal.common.VerboseLogger;

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

  public List<BackendSystem.AuditEntry> getLog() {
    return Collections.unmodifiableList(log);
  }

  public void flushLogsToBackend(BackendSystem backend) {
    // Skip re-emitting to the audit file: localAudit already wrote each entry
    // when the event happened. We only need to populate the backend in-memory
    // auditLog so post-rental queries (e.g. backend.getAuditLog(cardId)) see them.
    for (BackendSystem.AuditEntry e : log) {
      backend.appendToAuditLogOnly(e);
    }
    log.clear();
  }

  // Buffers offline audit + emits to verbose audit stream immediately so the
  // tmux red pane shows vehicle events in real time, not just on flush.
  private void localAudit(String eventType, byte[] cardId, byte[] evidence, String details) {
    log.add(new BackendSystem.AuditEntry(eventType, cardId, vehicleId, evidence, details));
    VerboseLogger.get().audit(eventType, cardId, vehicleId, details);
  }

  public VehicleTerminal(CardComm comm, PublicKey masterPublicKey, byte[] vehicleId) {
    this.comm = comm;
    this.masterPublicKey = masterPublicKey;
    this.vehicleId = vehicleId;
  }

  // PIN
  // 

  /**
   * Verify the card is authorized to use this vehicle.
   * Checks sigma4 (assignment token) and sigma5 (card signs sigma4 + nonce).
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

  private Result<byte[]> doOpenVehicle(byte[] cardId) {
    // Check card is ASSIGNED
    Result<byte[]> stateResult = comm.send(ProtocolConstants.INS_GET_STATE);
    if (!stateResult.success) {
      return Result.fail(stateResult.error);
    }
    byte state = stateResult.value[0];
    if (state != ProtocolConstants.STATE_ASSIGNED) {
      return Result.fail("Card not in ASSIGNED state (state=0x"
          + String.format("%02X", state) + ")");
    }

    // Get assignment token (sigma4)
    Result<byte[]> sigma4Result = comm.send(ProtocolConstants.INS_GET_ASSIGNMENT_DATA);
    if (!sigma4Result.success) {
      return Result.fail(sigma4Result.error);
    }
    byte[] sigma4 = sigma4Result.value;
    VerboseLogger.get().step("sigma4 read from card (" + sigma4.length + " bytes)");

    // Parse sigma4: [1B reqDataLen][reqData][1B sigma3Len][sigma3][1B
    // 
    // pkcLen][pkc][1B sigLen][sig]
    byte[][] sigmaParts = BackendSystem.parseAssignmentToken(sigma4);
    byte[] reqData = sigmaParts[0];
    byte[] sigma3 = sigmaParts[1];
    byte[] pkc = sigmaParts[2];
    byte[] sig = sigmaParts[3];

    // Verify sigma4 against MPK: verify(MSK, sigma3 || pkc)
    byte[] dataToVerify = ByteUtil.concat(sigma3, pkc);
    try {
      if (!CryptoUtil.verify(masterPublicKey, dataToVerify, sig)) {
        return Result.fail("Assignment token (sigma4) invalid");
      }
    } catch (GeneralSecurityException e) {
      return Result.fail("sigma4 verification crypto failure", e);
    }
    VerboseLogger.get().step("sigma4 verified against MPK");

    // Check vehicleId in reqData matches this vehicle
    byte[] assignedVehicleId = Arrays.copyOf(reqData, ProtocolConstants.VEHICLE_ID_LENGTH);
    // Prevent cards assigned to other vehicles from being reused here
    if (!Arrays.equals(assignedVehicleId, this.vehicleId)) {
      return Result.fail("Card not assigned to this vehicle");
    }

    // Verify sigma3: card signed reqData with skc
    PublicKey cardPubKey;
    try {
      cardPubKey = CryptoUtil.decodePublicKey(pkc);
      if (!CryptoUtil.verify(cardPubKey, reqData, sigma3)) {
        return Result.fail("Assignment request signature (sigma3) invalid");
      }
    } catch (GeneralSecurityException e) {
      return Result.fail("sigma3 verification crypto failure", e);
    }

    // Generate vehicle nonce, get card to sign (sigma4 || vehicleNonce)
    byte[] vehicleNonce = CryptoUtil.generateNonce(ProtocolConstants.NONCE_LENGTH);
    VerboseLogger.get().step("vehicle nonce generated");
    Result<byte[]> sigma5Result = comm.send(ProtocolConstants.INS_SIGN_VEHICLE_CHALL, vehicleNonce);
    if (!sigma5Result.success) {
      return Result.fail(sigma5Result.error);
    }
    byte[] sigma5 = sigma5Result.value;
    VerboseLogger.get().step("sigma5 received from card (" + sigma5.length + " bytes)");

    // Verify sigma5: card signed (sigma4 || vehicleNonce) with skc
    byte[] challengeData = ByteUtil.concat(sigma4, vehicleNonce);
    try {
      if (!CryptoUtil.verify(cardPubKey, challengeData, sigma5)) {
        return Result.fail("Vehicle challenge signature (sigma5) invalid");
      }
    } catch (GeneralSecurityException e) {
      return Result.fail("sigma5 verification crypto failure", e);
    }
    VerboseLogger.get().step("sigma5 verified against pkc");

    currentSeqNum = 0;
    currentCardId = cardId;
    localAudit(BackendSystem.EVENT_VEHICLE_OPENED, cardId, sigma5, null);
    return Result.ok(pkc);
  }

  /**
   * Send mileage update to card.
   *
   * @param mileage current odometer reading
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
      return Result.fail("Mileage rollback detected");
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
   * Get current mileage from card.
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
      return Result.fail("Return receipt missing signature");
    }
    byte[] mileageBytes = new byte[2];
    System.arraycopy(receipt, 0, mileageBytes, 0, 2);
    byte[] sig = new byte[sigLen];
    System.arraycopy(receipt, 2, sig, 0, sigLen);

    try {
      PublicKey cardPubKey = CryptoUtil.decodePublicKey(cardPkc);
      if (!CryptoUtil.verify(cardPubKey, mileageBytes, sig)) {
        return Result.fail("Return receipt signature invalid");
      }
    } catch (GeneralSecurityException e) {
      return Result.fail("Return receipt verification crypto failure", e);
    }

    return Result.ok(receipt);
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

  
  /**
   * Entry point. Sets up a simulated card (personalized, issued, assigned),
   * then runs the vehicle terminal menu.
   */
  public static void main(String[] args) throws Exception {
    // --- Backend ---
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
            Result<Byte> stR = getCardState();
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
