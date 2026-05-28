package terminal.backend;

import java.security.*;
import java.util.*;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;

import terminal.common.ByteUtil;
import terminal.common.CryptoUtil;
import terminal.common.TokenUtil;

/**
 * Central authority: CA (MSK/MPK), vehicle DB, customer DB, block list.
 * Singleton. In-memory simulation.
 */
public class BackendSystem {
  // TODO: This backend system is now splitted up into a lot of different methods,
  // this is good, but for the eventual implementation I would
  // say that it is better to split up the different methods, like vehicle
  // selection, and the rest of these functions should then not be public.

  // Audit event types
  public static final String EVENT_AUTH_SUCCESS = "AUTH_SUCCESS";
  public static final String EVENT_AUTH_FAIL = "AUTH_FAIL";
  public static final String EVENT_VEHICLE_ASSIGNED = "VEHICLE_ASSIGNED";
  public static final String EVENT_VEHICLE_OPENED = "VEHICLE_OPENED";
  public static final String EVENT_VEHICLE_OPEN_FAIL = "VEHICLE_OPEN_FAIL";
  public static final String EVENT_MILEAGE_UPDATE = "MILEAGE_UPDATE";
  public static final String EVENT_PAYMENT = "PAYMENT";
  public static final String EVENT_CARD_BLOCKED = "CARD_BLOCKED";
  public static final String EVENT_CARD_EXPIRED = "CARD_EXPIRED";

  public static class AuditEntry {
    public final long timestamp;
    public final String eventType;
    public final byte[] cardId;
    public final byte[] vehicleId;
    public final byte[] cryptoEvidence;
    public final String details;

    public AuditEntry(String eventType, byte[] cardId, byte[] vehicleId,
        byte[] cryptoEvidence, String details) {
      this.timestamp = System.currentTimeMillis();
      this.eventType = eventType;
      this.cardId = cardId;
      this.vehicleId = vehicleId;
      this.cryptoEvidence = cryptoEvidence;
      this.details = details;
    }
  }

  private static BackendSystem instance;

  private KeyPair masterKeyPair; // MSK (private) + MPK (public)
  private KeyPair terminalKeyPair; // skt + pkt for reception terminal
  private byte[] terminalCertificate; // Ct = Sign_MSK(pkt)

  private final Map<String, Vehicle> vehicles = new LinkedHashMap<>();
  private final Map<String, Customer> customers = new LinkedHashMap<>();
  private final Set<String> blockedCardIds = new HashSet<>();
  private final List<AuditEntry> auditLog = new ArrayList<>();

  private BackendSystem() {
  }

  public static BackendSystem getInstance() {
    if (instance == null) {
      instance = new BackendSystem();
    }
    return instance;
  }

  /** Reset for testing. */
  public static void reset() {
    instance = null;
  }

  /**
   * Initialize: generate master key pair and terminal key pair + certificate.
   */
  public void init() throws GeneralSecurityException {
    // TODO: Add transactions here
    masterKeyPair = CryptoUtil.generateKeyPair();
    terminalKeyPair = CryptoUtil.generateKeyPair();

    // Create terminal certificate: Ct = Sign_MSK(terminalId || pkt)
    byte[] terminalId = new byte[] { 0x54, 0x45, 0x52, 0x4D }; // "TERM"
    byte[] pktEncoded = CryptoUtil.encodePublicKey(terminalKeyPair.getPublic());
    terminalCertificate = CryptoUtil.createCertificate(terminalId, pktEncoded, masterKeyPair.getPrivate());
  }

  // CA operations

  public PublicKey getMasterPublicKey() {
    return masterKeyPair.getPublic();
  }

  public byte[] getMasterPublicKeyEncoded() {
    return CryptoUtil.encodePublicKey(masterKeyPair.getPublic());
  }

  public PrivateKey getMasterPrivateKey() {
    return masterKeyPair.getPrivate();
  }

  /**
   * Sign certificate for a card's public key.
   * Returns Cc = certificate TLV bytes.
   */
  public byte[] signCertificate(byte[] cardId, byte[] cardPubKeyEncoded) throws GeneralSecurityException {
    return CryptoUtil.createCertificate(cardId, cardPubKeyEncoded, masterKeyPair.getPrivate());
  }

  public KeyPair getTerminalKeyPair() {
    return terminalKeyPair;
  }

  public byte[] getTerminalCertificate() {
    return terminalCertificate;
  }

  // Vehicle management

  public void registerVehicle(byte[] id, String plate) {
    vehicles.put(ByteUtil.toHex(id), new Vehicle(id, plate));
  }

  public List<Vehicle> getAvailableVehicles() {
    List<Vehicle> available = new ArrayList<>();
    for (Vehicle v : vehicles.values()) {
      if (v.isAvailable())
        available.add(v);
    }
    return available;
  }

  public Vehicle getVehicle(byte[] id) {
    return vehicles.get(ByteUtil.toHex(id));
  }

  public boolean assignVehicle(byte[] vehicleId, byte[] customerId) {
    Vehicle v = vehicles.get(ByteUtil.toHex(vehicleId));
    if (v != null && v.isAvailable()) {
      // Temportarly assign the vehicle, until the correct information is stored on
      // the card, if something goes wrong with the card, we can release the vehicle
      // again.
      v.assign(customerId);
      return true;
    }
    return false;
  }

  public void completeAssignment(byte[] vehicleId, byte[] customerId) {
    Vehicle v = vehicles.get(ByteUtil.toHex(vehicleId));
    if (v != null) {
      v.completeAssignment(customerId);
    }
  }

  public void releaseVehicle(byte[] vehicleId) {
    Vehicle v = vehicles.get(ByteUtil.toHex(vehicleId));
    if (v != null) {
      v.release();
    }
  }

  // Customer management

  public void registerCustomer(byte[] id, String name) {
    customers.put(ByteUtil.toHex(id), new Customer(id, name));
  }

  public Customer getCustomer(byte[] id) {
    return customers.get(ByteUtil.toHex(id));
  }

  public void linkCardToCustomer(byte[] customerId, byte[] cardId) {
    Customer c = customers.get(ByteUtil.toHex(customerId));
    if (c != null) {
      c.setCardId(cardId);
    }
  }

  public void addMileageToCustomer(byte[] customerId, int mileage) {
    Customer c = customers.get(ByteUtil.toHex(customerId));
    if (c != null) {
      c.addMileage(mileage);
    }
  }

  public void processPayment(byte[] customerId) {
    Customer c = customers.get(ByteUtil.toHex(customerId));
    if (c != null) {
      c.clearMileage();
    }
  }

  public void blockCustomer(byte[] customerId) {
    Customer c = customers.get(ByteUtil.toHex(customerId));
    if (c != null) {
      c.block();
    }
  }

  // --- Audit logging ---

  private static final String AUDIT_PROP = "rentalsim.audit.log";
  private static final String AUDIT_DEFAULT = "/tmp/rentalsim-audit.log";
  private PrintWriter auditOut;
  private boolean auditOutTried;
  private final SimpleDateFormat auditTs = new SimpleDateFormat("HH:mm:ss");

  public void logEvent(String eventType, byte[] cardId, byte[] vehicleId,
      byte[] cryptoEvidence, String details) {
    auditLog.add(new AuditEntry(eventType, cardId, vehicleId, cryptoEvidence, details));
    appendAuditFile(eventType, cardId, vehicleId, details);
  }

  /**
   * In-memory only; used by VehicleTerminal flush, which already wrote the file.
   */
  public void appendToAuditLogOnly(AuditEntry e) {
    auditLog.add(e);
  }

  private synchronized void appendAuditFile(String eventType, byte[] cardId,
      byte[] vehicleId, String details) {
    if (!auditOutTried) {
      auditOutTried = true;
      try {
        auditOut = new PrintWriter(
            new FileWriter(System.getProperty(AUDIT_PROP, AUDIT_DEFAULT), true), true);
      } catch (Exception e) {
        auditOut = null;
      }
    }
    if (auditOut == null)
      return;
    try {
      String card = cardId == null ? "-" : ByteUtil.toHex(cardId);
      String veh = vehicleId == null ? "-" : ByteUtil.toHex(vehicleId);
      auditOut.println(auditTs.format(new java.util.Date())
          + " " + eventType + " card=" + card + " vehicle=" + veh
          + (details == null ? "" : " " + details));
    } catch (Exception ignored) {
    }
  }

  public List<AuditEntry> getAuditLog() {
    return Collections.unmodifiableList(auditLog);
  }

  public List<AuditEntry> getAuditLog(byte[] cardId) {
    String key = ByteUtil.toHex(cardId);
    List<AuditEntry> result = new ArrayList<>();
    for (AuditEntry e : auditLog) {
      if (e.cardId != null && ByteUtil.toHex(e.cardId).equals(key)) {
        result.add(e);
      }
    }
    return Collections.unmodifiableList(result);
  }

  /**
   * Marks a smart card as blocked in the backend system.
   *
   * The backend records the card as blocked and logs the event.
   * The reception system periodically fetches the updated blocked-card list
   * and sends a blocking message to the smart card if it appears in that list.
   *
   * @param cardId the identifier of the smart card to be blocked
   */
  public void blockCard(byte[] cardId) {
    blockedCardIds.add(ByteUtil.toHex(cardId));
    logEvent(EVENT_CARD_BLOCKED, cardId, null, null, "Card blocked");
  }

  public boolean isCardBlocked(byte[] cardId) {
    return cardId != null && blockedCardIds.contains(ByteUtil.toHex(cardId));
  }

  // Assignment token (vehicleToken)

  /**
   * Create vehicleToken = [1B reqDataLen][reqData][1B reqVehicleTokenLen][reqVehicleToken][1B
   * pkcLen][pkc][1B sigLen][Sign_MSK(reqVehicleToken||pkc)]
   * reqData = vehicleId || terminalNonce || period, carried in plaintext so
   * the vehicle terminal can check the vehicleId without trusting the card.
   */
  public byte[] signAssignmentToken(byte[] reqData, byte[] reqVehicleToken, byte[] cardPubKeyEncoded)
      throws GeneralSecurityException {
    byte[] dataToSign = ByteUtil.concat(reqVehicleToken, cardPubKeyEncoded);
    byte[] signature = CryptoUtil.sign(masterKeyPair.getPrivate(), dataToSign);

    byte[] rdLen = ByteUtil.shortToBytes((short) reqData.length);
    byte[] reqVehicleTokenLen = ByteUtil.shortToBytes((short) reqVehicleToken.length);
    byte[] pkLen = ByteUtil.shortToBytes((short) cardPubKeyEncoded.length);
    byte[] sigLen = ByteUtil.shortToBytes((short) signature.length);

    return ByteUtil.concat(rdLen, reqData, reqVehicleTokenLen, reqVehicleToken, pkLen, cardPubKeyEncoded, sigLen, signature);
  }

  /**
   * Verify vehicleToken against master public key.
   */
  public boolean verifyAssignmentToken(byte[] vehicleToken) throws GeneralSecurityException {
    byte[][] parts = TokenUtil.parseAssignmentToken(vehicleToken);
    byte[] reqVehicleToken = parts[1];
    byte[] pkc = parts[2];
    byte[] signature = parts[3];

    byte[] dataToVerify = ByteUtil.concat(reqVehicleToken, pkc);
    return CryptoUtil.verify(masterKeyPair.getPublic(), dataToVerify, signature);
  }
}
