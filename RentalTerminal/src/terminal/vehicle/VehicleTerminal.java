package terminal.vehicle;

import java.security.*;
import java.util.*;
import java.util.Arrays;

import terminal.backend.BackendSystem;
import terminal.common.CardComm;
import terminal.common.CryptoUtil;
import terminal.common.ByteUtil;
import terminal.common.ProtocolConstants;

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
 * @param backend backend instance receiving the logs
 */  
  public void flushLogsToBackend(BackendSystem backend) {
    for (BackendSystem.AuditEntry e : log) {
      backend.logEvent(e.eventType, e.cardId, e.vehicleId, e.cryptoEvidence, e.details);
    }
    log.clear();
  }

  public VehicleTerminal(CardComm comm, PublicKey masterPublicKey, byte[] vehicleId) {
    this.comm = comm;
    this.masterPublicKey = masterPublicKey;
    this.vehicleId = vehicleId;
  }


  // Vehicle opening protocol (Fig 6) No PIN-------------------------------------------------------------------------

  /**
   * Verify the card is authorized to use this vehicle.
   * Checks sigma4 (assignment token) and sigma5 (card signs sigma4 + nonce).
   *
   * @return card public key bytes if authorized
   * @throws SecurityException if card is not authorized
   */
  public byte[] openVehicle() throws Exception {
    
    // Read card ID early so failed attempts can still be logged
    byte[] cardId = null;
    try {
      cardId = comm.sendCommandChecked(ProtocolConstants.INS_GET_CARD_ID);
    } catch (Exception e) {
      // Card ID might not be available yet
    }

    try {
      return doOpenVehicle(cardId);
    } catch (Exception e) {
      log.add(new BackendSystem.AuditEntry(BackendSystem.EVENT_VEHICLE_OPEN_FAIL,
          cardId, vehicleId, null, e.getMessage()));
      throw e;
    }
  }

  private byte[] doOpenVehicle(byte[] cardId) throws Exception {
    // Check card is ASSIGNED
    byte state = comm.sendCommandChecked(ProtocolConstants.INS_GET_STATE)[0];
    if (state != ProtocolConstants.STATE_ASSIGNED) {
      throw new SecurityException("Card not in ASSIGNED state (state=0x"
          + String.format("%02X", state) + ")");
    }

    // Get assignment token (sigma4)
    byte[] sigma4 = comm.sendCommandChecked(ProtocolConstants.INS_GET_ASSIGNMENT_DATA);

    // Parse sigma4: [1B reqDataLen][reqData][1B sigma3Len][sigma3][1B pkcLen][pkc][1B sigLen][sig]
    byte[][] sigma4Parts = BackendSystem.parseAssignmentToken(sigma4);
    byte[] reqData  = sigma4Parts[0];
    byte[] sigma3   = sigma4Parts[1];
    byte[] pkc      = sigma4Parts[2];
    byte[] sigma4Sig = sigma4Parts[3];

    // Verify sigma4 against MPK: verify(MSK, sigma3 || pkc)
    byte[] dataToVerify = ByteUtil.concat(sigma3, pkc);
    if (!CryptoUtil.verify(masterPublicKey, dataToVerify, sigma4Sig)) {
      throw new SecurityException("Assignment token (sigma4) invalid");
    }

    // Check vehicleId in reqData matches this vehicle
    byte[] assignedVehicleId = Arrays.copyOf(reqData, ProtocolConstants.VEHICLE_ID_LENGTH);
    // Prevent cards assigned to other vehicles from being reused here
    if (!Arrays.equals(assignedVehicleId, this.vehicleId)) {
      throw new SecurityException("Card not assigned to this vehicle");
    }

    // Verify sigma3: card signed reqData with skc
    PublicKey cardPubKey = CryptoUtil.decodeECPublicKey(pkc);
    if (!CryptoUtil.verify(cardPubKey, reqData, sigma3)) {
      throw new SecurityException("Assignment request signature (sigma3) invalid");
    }

    // Generate vehicle nonce, get card to sign (sigma4 || vehicleNonce)
    byte[] vehicleNonce = CryptoUtil.generateNonce(ProtocolConstants.NONCE_LENGTH);
    byte[] sigma5 = comm.sendCommandChecked(ProtocolConstants.INS_SIGN_VEHICLE_CHALL, vehicleNonce);

    // Verify sigma5: card signed (sigma4 || vehicleNonce) with skc
    byte[] challengeData = ByteUtil.concat(sigma4, vehicleNonce);
    if (!CryptoUtil.verify(cardPubKey, challengeData, sigma5)) {
      throw new SecurityException("Vehicle challenge signature (sigma5) invalid");
    }

    currentSeqNum = 0;
    currentCardId = cardId;
    log.add(new BackendSystem.AuditEntry(BackendSystem.EVENT_VEHICLE_OPENED,
        cardId, vehicleId, sigma5, null));
    return pkc;
  }

  // Mileage (Figure 2)
  /**
   * Send mileage update to card.
   *
   * @param mileage current odometer reading
   */
  public void updateMileage(short mileage) throws Exception {
    short previousMileage = getMileage();

    // Mileage should not decrease
    if (mileage < previousMileage) {
      throw new SecurityException("Mileage rollback detected");
    }

    byte[] data = new byte[4];

    data[0] = (byte) ((mileage >> 8) & 0xFF);
    data[1] = (byte) (mileage & 0xFF);
    data[2] = (byte) ((currentSeqNum >> 8) & 0xFF);
    data[3] = (byte) (currentSeqNum & 0xFF);

    comm.sendCommandChecked(ProtocolConstants.INS_UPDATE_MILEAGE, data);
    currentSeqNum++;

    log.add(new BackendSystem.AuditEntry(
        BackendSystem.EVENT_MILEAGE_UPDATE,
        currentCardId,
        vehicleId,
        null,
        "old=" + previousMileage + ", new=" + mileage));
    }

  /**
   * Reads the current mileage stored on the smart card.
   *
   * @return current mileage value
   */
  public short getMileage() throws Exception {
    byte[] data = comm.sendCommandChecked(ProtocolConstants.INS_GET_MILEAGE);
    return ByteUtil.bytesToShort(data, 0);
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
  public byte[] returnVehicle(short finalMileage, byte[] cardPkc) throws Exception {
    byte[] data = new byte[2];
    data[0] = (byte) ((finalMileage >> 8) & 0xFF);
    data[1] = (byte) (finalMileage & 0xFF);

    byte[] receipt = comm.sendCommandChecked(ProtocolConstants.INS_RETURN_VEHICLE, data);

    // Verify receipt signature: card signed the 2-byte mileage
    int sigLen = receipt.length - 2;
    if (sigLen <= 0) {
      throw new SecurityException("Return receipt missing signature");
    }
    byte[] mileageBytes = new byte[2];
    System.arraycopy(receipt, 0, mileageBytes, 0, 2);
    byte[] sig = new byte[sigLen];
    System.arraycopy(receipt, 2, sig, 0, sigLen);

    PublicKey cardPubKey = CryptoUtil.decodeECPublicKey(cardPkc);
    if (!CryptoUtil.verify(cardPubKey, mileageBytes, sig)) {
      throw new SecurityException("Return receipt signature invalid");
    }

    return receipt;
  }

  /**
   * Get current card state.
   */
  public byte getCardState() throws Exception {
    return comm.sendCommandChecked(ProtocolConstants.INS_GET_STATE)[0];
  }

  
  // Interactive CLI

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
    byte[] pkc = rt.mutualAuth("1234");
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
 * Starts the interactive vehicle terminal menu.
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
            cardPkc = openVehicle();
            System.out.println("Vehicle unlocked.");
            break;
          case "2":
            if (cardPkc == null) {
              System.out.println("Open vehicle first.");
              break;
            }
            System.out.print("Mileage (km): ");
            short m = Short.parseShort(scanner.nextLine().trim());
            updateMileage(m);
            System.out.println("Mileage updated: " + m + " km");
            break;
          case "3":
            if (cardPkc == null) {
              System.out.println("Open vehicle first.");
              break;
            }
            System.out.print("Final mileage (km): ");
            short fm = Short.parseShort(scanner.nextLine().trim());
            returnVehicle(fm, cardPkc);
            System.out.println("Vehicle returned. Card state: ISSUED.");
            cardPkc = null;
            running = false;
            break;
          case "4":
            System.out.println("Mileage: " + getMileage() + " km");
            break;
          case "5":
            byte st = getCardState();
            System.out.println("State: 0x" + String.format("%02X", st));
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