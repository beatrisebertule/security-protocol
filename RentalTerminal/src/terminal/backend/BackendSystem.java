package terminal.backend;

import java.security.*;
import java.util.*;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import javax.security.auth.Destroyable;

import terminal.util.ByteUtil;
import terminal.util.CryptoUtil;
import terminal.util.ProtocolConstants;
import terminal.util.TokenUtil;

/**
 * Central authority: CA (MSK/MPK), vehicle DB, customer DB, block list.
 * Singleton. In-memory simulation.
 */
public class BackendSystem {
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

  //FIXME : Add a comment of why this ineeds to be volatile. Short ocmment
  private static volatile BackendSystem instance;

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
      synchronized (BackendSystem.class) {
        if (instance == null) {
          instance = new BackendSystem();
        }
      }
    }
    return instance;
  }

  /** Reset for testing. */
  public static void reset() {
    instance = null;
  }

  /**
   * Initialize the backend by generating the master key pair, terminal key pair,
   * and the terminal certificate signed by the master key.
   */
  public void init() throws GeneralSecurityException {
    masterKeyPair = CryptoUtil.generateKeyPair();
    terminalKeyPair = CryptoUtil.generateKeyPair();

    // Create terminal certificate with 1-year validity period
    byte[] terminalId = CryptoUtil.generateNonce(4);
    byte[] pktEncoded = CryptoUtil.encodePublicKey(terminalKeyPair.getPublic());
    long notAfter = Instant.now().getEpochSecond() + 365L * 24 * 3600;
    terminalCertificate = CryptoUtil.createCertificateWithExpiry(
        terminalId, pktEncoded, notAfter, masterKeyPair.getPrivate());
  }

  /** Sign the current timestamp so the applet can verify it came from the backend. */
  public byte[] signTimestamp(byte[] timestamp) throws GeneralSecurityException {
    return CryptoUtil.sign(masterKeyPair.getPrivate(), timestamp);
  }

  /** Sign a block authorization: Sign_MSK(cardId || INS_BLOCK_CARD). */
  /**
   * FIXME: DO javadocs 
   *
   * @param cardId [TODO:description]
   *
   * @return [TODO:description]
   *
   * @throws GeneralSecurityException [TODO:description]
   */
  public byte[] signBlockAuthorization(byte[] cardId) throws GeneralSecurityException {
    byte[] dataToSign = new byte[cardId.length + 1];
    System.arraycopy(cardId, 0, dataToSign, 0, cardId.length);
    dataToSign[cardId.length] = ProtocolConstants.INS_BLOCK_CARD;
    return CryptoUtil.sign(masterKeyPair.getPrivate(), dataToSign);
  }

  /** Zero MSK private key material. Call on shutdown. */
  public void shutdown() {
    PrivateKey priv = masterKeyPair != null ? masterKeyPair.getPrivate() : null;
    if (priv instanceof Destroyable) {
      try { ((Destroyable) priv).destroy(); } catch (Exception ignored) {}
    }
  }

  // CA operations

  public PublicKey getMasterPublicKey() {
    return masterKeyPair.getPublic();
  }

  public byte[] getMasterPublicKeyEncoded() {
    return CryptoUtil.encodePublicKey(masterKeyPair.getPublic());
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
      v.checkAndReleaseTimeout();
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
    if (v == null) return false;
    v.checkAndReleaseTimeout();
    if (v.isAvailable()) {
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

  //  Audit logging 
  //
  //  FIXME: I DONT LIKE THAT THIS IS DEFINED SO LOW INTO THE FILE. all the attributes should be at the top

  private static final String AUDIT_PROP = "rentalsim.audit.log";
  private static final String AUDIT_DEFAULT = "/tmp/rentalsim-audit.log";
  private PrintWriter auditOut;
  private boolean auditOutTried;
  private final DateTimeFormatter auditTs =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC);

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

  /**
   * FIXME: Add javadoc
   *
   * @param eventType [TODO:description]
   * @param cardId [TODO:description]
   * @param vehicleId [TODO:description]
   * @param details [TODO:description]
   */
  private synchronized void appendAuditFile(String eventType, byte[] cardId,
      byte[] vehicleId, String details) {
    if (!auditOutTried) {
      auditOutTried = true;
      try {
        // Read the configured log path from the JVM system property. If no property
        // is set, fall back to AUDIT_DEFAULT. getCanonicalFile() resolves symlinks
        // and ".." segments so that a path like "/tmp/../etc/passwd" cannot escape
        // the allowed directory. If the resolved path is outside /tmp, we ignore the
        // configured value and fall back to the default to prevent an attacker who
        // controls JVM properties from redirecting audit output to arbitrary files.
        String rawPath = System.getProperty(AUDIT_PROP, AUDIT_DEFAULT);
        File auditFile = new File(rawPath).getCanonicalFile();
        File allowedDir = new File("/tmp").getCanonicalFile();
        if (!auditFile.getPath().startsWith(allowedDir.getPath() + File.separator)) {
          auditFile = new File(AUDIT_DEFAULT).getCanonicalFile();
        }
        auditOut = new PrintWriter(new FileWriter(auditFile, true), true);
      } catch (Exception e) {
        auditOut = null;
      }
    }
    if (auditOut == null)
      return;
    try {
      String card = cardId == null ? "-" : ByteUtil.toHex(cardId);
      String veh = vehicleId == null ? "-" : ByteUtil.toHex(vehicleId);
      auditOut.println(auditTs.format(Instant.now())
          + " " + eventType + " card=" + card + " vehicle=" + veh
          + (details == null ? "" : " " + details));
    } catch (Exception ignored) {
    }
  }

  public List<AuditEntry> getAuditLog() {
    return Collections.unmodifiableList(auditLog);
  }

  /**
   *  FIXME: add javadoc
   *
   * @param cardId [TODO:description]
   *
   * @return [TODO:description]
   */
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
  /**
   * FIXME: DO javadoc
   *
   * @param reqData [TODO:description]
   * @param reqVehicleToken [TODO:description]
   * @param cardPubKeyEncoded [TODO:description]
   *
   * @return [TODO:description]
   *
   * @throws GeneralSecurityException [TODO:description]
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
