package terminal.reception;

import java.security.*;
import java.util.List;
import java.util.Scanner;

import terminal.backend.BackendSystem;
import terminal.backend.Vehicle;
import terminal.backend.Customer;
import terminal.common.CardComm;
import terminal.common.CryptoUtil;
import terminal.common.ByteUtil;
import terminal.common.ProtocolConstants;

/**
 * Reception terminal: mutual authentication, vehicle assignment, payment.
 * Used both programmatically (tests) and interactively (CLI).
 */
public class ReceptionTerminal extends ReceptionTerminalBase { //TODO: Make two instances of the reception terminal, one for the CLI and one for like UI things so that it is possible to extend it

  public ReceptionTerminal(CardComm comm, BackendSystem backend) {
    super(comm, backend);
  }

  // -------------------------------------------------------------------------
  // Mutual authentication (Figure 4)
  // -------------------------------------------------------------------------

  /**
   * Step 1: get nonce from card.
   */
  public byte[] getCardNonce() throws Exception { //FIXME: the card cannot return a bytearray probs
    return comm.sendCommandChecked(ProtocolConstants.INS_GET_NONCE);
  }

  /**
   * Step 2: terminal signs card nonce, sends terminal signature + certificate.
   * Card verifies certificate against MPK, then verifies nonce signature.
   */
  public void verifyTerminalToCard(byte[] cardNonce) throws Exception {
    KeyPair termKP = backend.getTerminalKeyPair();
    byte[] termCert = backend.getTerminalCertificate();

    byte[] termSig = CryptoUtil.sign(termKP.getPrivate(), cardNonce);

    // Format: [1B sigLen][sig][cert]
    byte[] payload = new byte[1 + termSig.length + termCert.length];
    payload[0] = (byte) termSig.length;
    System.arraycopy(termSig, 0, payload, 1, termSig.length);
    System.arraycopy(termCert, 0, payload, 1 + termSig.length, termCert.length);

    comm.sendCommandChecked(ProtocolConstants.INS_VERIFY_TERMINAL_SIG, payload);
  }

  /**
   * Step 3: verify PIN on card (PIN is hashed client-side).
   */
  public void verifyPin(String pin) throws Exception {
    byte[] pinHash = CryptoUtil.hashPin(pin);
    comm.sendCommandChecked(ProtocolConstants.INS_VERIFY_PIN, pinHash);
  }

  /**
   * Step 4: terminal sends its own nonce, card signs it and returns signature +
   * cert.
   * Terminal verifies card certificate against MPK, then verifies card's
   * signature.
   *
   * @return card public key bytes (65B uncompressed), extracted from cert
   */
  public byte[] verifyCardToTerminal() throws Exception {
    byte[] termNonce = CryptoUtil.generateNonce(ProtocolConstants.NONCE_LENGTH);
    byte[] resp = comm.sendCommandChecked(ProtocolConstants.INS_SIGN_NONCE, termNonce);

    // Parse response: [1B sigLen][sig][cert]
    int sigLen = resp[0] & 0xFF;
    byte[] cardSig = new byte[sigLen];
    System.arraycopy(resp, 1, cardSig, 0, sigLen);
    byte[] cardCert = new byte[resp.length - 1 - sigLen];
    System.arraycopy(resp, 1 + sigLen, cardCert, 0, cardCert.length);

    // Verify card certificate against MPK
    PublicKey mpk = backend.getMasterPublicKey();
    if (!CryptoUtil.verifyCertificate(cardCert, mpk)) {
      throw new SecurityException("Card certificate verification failed");
    }

    // Extract card public key and verify signature of terminal nonce
    PublicKey cardPubKey = CryptoUtil.extractPublicKeyFromCert(cardCert);
    if (!CryptoUtil.verify(cardPubKey, termNonce, cardSig)) {
      throw new SecurityException("Card signature verification failed");
    }

    return CryptoUtil.encodeECPublicKey(cardPubKey);
  }

  /**
   * Get card ID (4 bytes). Returns null if unavailable.
   */
  public byte[] getCardId() {
    try {
      return comm.sendCommandChecked(ProtocolConstants.INS_GET_CARD_ID);
    } catch (Exception e) {
      return null;
    }
  }

  /**
   * Full mutual auth sequence.
   *
   * @param pin card PIN
   * @return card public key bytes (65B uncompressed)
   */
  public byte[] mutualAuth(String pin) throws Exception {
    byte[] cardId = getCardId();
    try {
      byte[] cardNonce = getCardNonce();
      verifyTerminalToCard(cardNonce);
      verifyPin(pin);
      byte[] cardPkc = verifyCardToTerminal();
      backend.logEvent(BackendSystem.EVENT_AUTH_SUCCESS, cardId, null, cardPkc, null);
      return cardPkc;
    } catch (Exception e) {
      backend.logEvent(BackendSystem.EVENT_AUTH_FAIL, cardId, null, null, e.getMessage());
      throw e;
    }
  }

  // -------------------------------------------------------------------------
  // Vehicle assignment (Figure 5)
  // -------------------------------------------------------------------------

  /**
   * Full vehicle assignment flow. Requires prior mutualAuth().
   *
   * @param vehicleId  4-byte vehicle ID
   * @param customerId 4-byte customer ID
   * @param cardPkc    65-byte card public key (from mutualAuth)
   * @param period     8-byte rental period (start + end timestamps)
   */
  public void assignVehicle(byte[] vehicleId, byte[] customerId,
      byte[] cardPkc, byte[] period) throws Exception {
    // Build SIGN_VEHICLE_REQ payload: [4B vehicleId][16B nonce][8B period]
    byte[] nonce = CryptoUtil.generateNonce(ProtocolConstants.NONCE_LENGTH);
    byte[] reqData = ByteUtil.concat(vehicleId, nonce, period);
    byte[] sigma3 = comm.sendCommandChecked(ProtocolConstants.INS_SIGN_VEHICLE_REQ, reqData);

    // Backend signs assignment token: sigma4 = Sign_MSK(sigma3 || pkc)
    byte[] sigma4 = backend.signAssignmentToken(sigma3, cardPkc);

    // Store sigma4 on card -> transitions to ASSIGNED
    comm.sendCommandChecked(ProtocolConstants.INS_STORE_ASSIGNMENT, sigma4);

    // Update backend records
    backend.assignVehicle(vehicleId, customerId);

    byte[] cardId = getCardId();
    backend.logEvent(BackendSystem.EVENT_VEHICLE_ASSIGNED, cardId, vehicleId, sigma4, null);
  }

  // -------------------------------------------------------------------------
  // Payment
  // -------------------------------------------------------------------------

  /**
   * Read mileage from card, process payment in backend, clear mileage on card.
   * Requires prior mutualAuth().
   *
   * @param customerId 4-byte customer ID
   * @return mileage amount that was paid
   */
  public int processMileagePayment(byte[] customerId) throws Exception { //TODO add transaciton
    // Read current mileage
    byte[] mileageData = comm.sendCommandChecked(ProtocolConstants.INS_GET_MILEAGE);
    int mileage = ByteUtil.bytesToShort(mileageData, 0) & 0xFFFF;

    if (mileage > 0) {
      // Backend records payment
      backend.addMileageToCustomer(customerId, mileage);
      backend.processPayment(customerId);

      // Clear mileage on card (requires full auth - must have been done before
      // calling this)
      comm.sendCommandChecked(ProtocolConstants.INS_CLEAR_MILEAGE);

      byte[] cardId = getCardId();
      backend.logEvent(BackendSystem.EVENT_PAYMENT, cardId, null, null, "mileage=" + mileage);
    }

    return mileage;
  }

  /**
   * Get current card state.
   */
  public byte getCardState() throws Exception {
    return comm.sendCommandChecked(ProtocolConstants.INS_GET_STATE)[0];
  }

  // -------------------------------------------------------------------------
  // Interactive CLI
  // -------------------------------------------------------------------------

  /**
   * Interactive CLI entry point. Sets up a simulated card (personalized +
   * issued),
   * then runs the reception terminal menu.
   */
  public static void main(String[] args) throws Exception {
    // --- Backend ---
    BackendSystem.reset();
    BackendSystem backend = BackendSystem.getInstance();
    backend.init();
    byte[] vehicleId1 = { 0x00, 0x00, 0x00, 0x01 };
    byte[] vehicleId2 = { 0x00, 0x00, 0x00, 0x02 };
    backend.registerVehicle(vehicleId1, "AB-123-CD");
    backend.registerVehicle(vehicleId2, "XY-456-EF");
    byte[] customerId = { 0x00, 0x00, 0x00, 0x01 };
    backend.registerCustomer(customerId, "Alice");

    // --- JCardSim ---
    com.licel.jcardsim.smartcardio.CardSimulator simulator = new com.licel.jcardsim.smartcardio.CardSimulator();
    byte[] APPLET_AID = {
        (byte) 0x3B, (byte) 0x29, (byte) 0x72, (byte) 0x65, (byte) 0x6E, (byte) 0x74, (byte) 0x01
    };
    javacard.framework.AID aid = new javacard.framework.AID(
        APPLET_AID, (byte) 0, (byte) APPLET_AID.length);
    simulator.installApplet(aid, applet.RentalCardApplet.class);

    javax.smartcardio.CardTerminals terminals = com.licel.jcardsim.smartcardio.CardTerminalSimulator
        .terminals("ReceptionTerminal");
    javax.smartcardio.CardTerminal terminal = terminals.getTerminal("ReceptionTerminal");
    simulator.assignToTerminal(terminal);

    javax.smartcardio.Card card = terminal.connect("*");
    javax.smartcardio.CardChannel channel = card.getBasicChannel();

    // Select applet
    channel.transmit(new javax.smartcardio.CommandAPDU(
        (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, APPLET_AID));

    CardComm comm = new CardComm(channel);
    // fixme: Card inside should be another function.
    // Personalize + issue card
    terminal.common.ProtocolConstants dummy = null; // ensure import used
    byte[] cardId = { 0x00, 0x00, 0x00, 0x01 };
    byte[] pin = { 0x00 }; // placeholder - PersonalizationTerminal used below
    terminal.personalization.PersonalizationTerminal pt = new terminal.personalization.PersonalizationTerminal(comm,
        backend);
    pt.personalizeCard(cardId, "1234");
    pt.issueCard(customerId);

    System.out.println("Card personalized and issued (PIN: 1234).");
    System.out.println("Customer: Alice [" + ByteUtil.toHex(customerId) + "]");

    // Run CLI
    new ReceptionTerminal(comm, backend).runCLI();
  }

  public void runCLI() {
    Scanner scanner = new Scanner(System.in);
    System.out.println("=== Reception Terminal ===");

    try {
      byte state = getCardState();
      System.out.println("Card state: " + stateToString(state));

      System.out.print("Enter PIN: ");
      String pin = scanner.nextLine().trim();

      System.out.println("Performing mutual authentication...");
      byte[] cardPkc = mutualAuth(pin);
      System.out.println("Authentication successful.");

      boolean running = true;
      while (running) {
        System.out.println("\n1) Assign vehicle");
        System.out.println("2) Process payment");
        System.out.println("3) Get card state");
        System.out.println("0) Exit");
        System.out.print("Choice: ");
        String choice = scanner.nextLine().trim();

        switch (choice) {
          case "1":
            cliAssignVehicle(scanner, cardPkc);
            break;
          case "2":
            cliProcessPayment(scanner);
            break;
          case "3":
            System.out.println("State: " + stateToString(getCardState()));
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

  private void cliAssignVehicle(Scanner scanner, byte[] cardPkc) {
    try {
      // TODO: Don't return the vehicles, let the backend handle that
      List<Vehicle> available = backend.getAvailableVehicles();
      if (available.isEmpty()) {
        System.out.println("No vehicles available.");
        return;
      }
      System.out.println("Available vehicles:");
      for (int i = 0; i < available.size(); i++) {
        Vehicle v = available.get(i);
        System.out.println("  " + i + ") " + v.getPlate()
            + " [" + ByteUtil.toHex(v.getId()) + "]");
      }
      System.out.print("Select vehicle (index): ");
      int idx = Integer.parseInt(scanner.nextLine().trim());
      if (idx < 0 || idx >= available.size()) {
        System.out.println("Invalid selection.");
        return;
      }
      // TODO: to the backend
      Vehicle vehicle = available.get(idx);

      System.out.print("Customer ID (hex, 4 bytes): ");
      byte[] customerId = ByteUtil.fromHex(scanner.nextLine().trim());

      // Use current time as rental period start, +7 days as end
      long now = System.currentTimeMillis() / 1000;
      long end = now + 7 * 24 * 3600;
      byte[] period = new byte[8]; // Think we may need to change this to short???
      period[0] = (byte) ((now >> 24) & 0xFF);
      period[1] = (byte) ((now >> 16) & 0xFF);
      period[2] = (byte) ((now >> 8) & 0xFF);
      period[3] = (byte) (now & 0xFF);
      period[4] = (byte) ((end >> 24) & 0xFF);
      period[5] = (byte) ((end >> 16) & 0xFF);
      period[6] = (byte) ((end >> 8) & 0xFF);
      period[7] = (byte) (end & 0xFF);

      assignVehicle(vehicle.getId(), customerId, cardPkc, period);
      System.out.println("Vehicle assigned: " + vehicle.getPlate());
    } catch (Exception e) {
      System.err.println("Assignment failed: " + e.getMessage());
    }
  }

  private void cliProcessPayment(Scanner scanner) {
    try {
      System.out.print("Customer ID (hex, 4 bytes): ");
      byte[] customerId = ByteUtil.fromHex(scanner.nextLine().trim());
      int mileage = processMileagePayment(customerId);
      System.out.println("Payment processed. Mileage: " + mileage + " km");
    } catch (Exception e) {
      System.err.println("Payment failed: " + e.getMessage());
    }
  }

  private String stateToString(byte state) {
    switch (state) {
      case ProtocolConstants.STATE_BLANK:
        return "BLANK";
      case ProtocolConstants.STATE_PERSONALIZED:
        return "PERSONALIZED";
      case ProtocolConstants.STATE_ISSUED:
        return "ISSUED";
      case ProtocolConstants.STATE_ASSIGNED:
        return "ASSIGNED";
      case ProtocolConstants.STATE_BLOCKED:
        return "BLOCKED";
      default:
        return "UNKNOWN(0x" + String.format("%02X", state) + ")";
    }
  }
}
