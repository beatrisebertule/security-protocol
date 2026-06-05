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
  public static final String EVENT_PAYMENT_FAIL = "PAYMENT_FAIL";
  public static final String EVENT_CARD_BLOCKED = "CARD_BLOCKED";
  public static final String EVENT_CARD_EXPIRED = "CARD_EXPIRED";
  public static final String EVENT_CUSTOMER_REGISTERED = "CUSTOMER_REGISTERED";
  public static final String EVENT_VEHICLE_REGISTERED = "VEHICLE_REGISTERED";
  public static final String EVENT_VEHICLE_RELEASED = "VEHICLE_RELEASED";
  public static final String EVENT_CARD_LINKED = "CARD_LINKED";
  public static final String EVENT_CUSTOMER_BLOCKED = "CUSTOMER_BLOCKED";

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

  // volatile ensures the fully-constructed instance is visible to all threads
  // in the double-checked locking pattern used by getInstance().
  private static volatile BackendSystem instance;

  private KeyPair masterKeyPair; // MSK (private) + MPK (public)
  private KeyPair terminalKeyPair; // skt + pkt for reception terminal
  private byte[] terminalCertificate; // Ct = Sign_MSK(pkt)

  private final Map<String, Vehicle> vehicles = new LinkedHashMap<>();
  private final Map<String, Customer> customers = new LinkedHashMap<>();
  private final Set<String> blockedCardIds = new HashSet<>();
  private final List<AuditEntry> auditLog = new ArrayList<>();

  // Audit file fields
  private static final String AUDIT_PROP = "rentalsim.audit.log";
  private static final String AUDIT_DEFAULT = "/tmp/rentalsim-audit.log";
  private PrintWriter auditOut;
  private boolean auditOutTried;
  private final DateTimeFormatter auditTs =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneOffset.UTC);

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

  /** Sign cardId || timestamp so the applet can verify the timestamp was issued for this card. */
  public byte[] signTimestamp(byte[] cardId, byte[] timestamp) throws GeneralSecurityException {
    byte[] dataToSign = ByteUtil.concat(cardId, timestamp);
    return CryptoUtil.sign(masterKeyPair.getPrivate(), dataToSign);
  }

  /**
   * Produces a block authorization token: Sign_MSK(cardId || INS_BLOCK_CARD).
   * The applet verifies this signature before transitioning to STATE_BLOCKED.
   *
   * @param cardId the card to authorize blocking
   * @return DER-encoded ECDSA signature
   * @throws GeneralSecurityException on signing failure
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
    logEvent(EVENT_VEHICLE_REGISTERED, null, id, null, "plate=" + plate);
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
    if (v == null) {
      return false;
    }
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
      logEvent(EVENT_VEHICLE_RELEASED, null, vehicleId, null, null);
    }
  }

  public void releaseVehicleByCustomer(byte[] customerId) {
    String key = ByteUtil.toHex(customerId);
    for (Vehicle v : vehicles.values()) {
      if (v.getAssignedCustomerId() != null
          && ByteUtil.toHex(v.getAssignedCustomerId()).equals(key)) {
        releaseVehicle(v.getId());
        return;
      }
    }
  }

  // Customer management

  public void registerCustomer(byte[] id, String name) {
    customers.put(ByteUtil.toHex(id), new Customer(id, name));
    logEvent(EVENT_CUSTOMER_REGISTERED, null, null, null, "customerId=" + ByteUtil.toHex(id) + " name=" + name);
  }

  public Customer getCustomer(byte[] id) {
    return customers.get(ByteUtil.toHex(id));
  }

  public Customer getCustomerByCardId(byte[] cardId) {
    if (cardId == null) return null;
    String cardHex = ByteUtil.toHex(cardId);
    for (Customer c : customers.values()) {
      if (c.getCardId() != null && ByteUtil.toHex(c.getCardId()).equals(cardHex)) {
        return c;
      }
    }
    return null;
  }

  public void linkCardToCustomer(byte[] customerId, byte[] cardId) {
    Customer c = customers.get(ByteUtil.toHex(customerId));
    if (c != null) {
      c.setCardId(cardId);
      logEvent(EVENT_CARD_LINKED, cardId, null, null, "customerId=" + ByteUtil.toHex(customerId));
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
      logEvent(EVENT_CUSTOMER_BLOCKED, null, null, null, "customerId=" + ByteUtil.toHex(customerId));
    }
  }

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
   * Appends a single audit event line to the configured log file.
   * Lazy-opens the file on first call; silently does nothing if the file cannot be opened.
   *
   * @param eventType short event code (e.g. AUTH_SUCCESS)
   * @param cardId    card identifier, or null if not applicable
   * @param vehicleId vehicle identifier, or null if not applicable
   * @param details   free-form detail string, or null
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
   * Returns audit entries for a specific card.
   *
   * @param cardId card identifier to filter by
   * @return unmodifiable list of audit entries for that card
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
   * Builds and signs an assignment token: [2B rdLen][reqData][2B reqVehicleTokenLen][reqVehicleToken][2B pkLen][pkc][2B sigLen][sig]
   * where sig = Sign_MSK(reqVehicleToken || pkc).
   * reqData = vehicleId || terminalNonce || period, carried in plaintext so
   * the vehicle terminal can verify the vehicleId without trusting the card.
   *
   * @param reqData            raw assignment request data from the card
   * @param reqVehicleToken    card-signed vehicle request token
   * @param cardPubKeyEncoded  card public key (65-byte uncompressed EC point)
   * @return serialized assignment token bytes
   * @throws GeneralSecurityException on signing failure
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
