package terminal.test;

import javacard.framework.AID;
import javax.smartcardio.*;
import java.util.List;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;

import applet.RentalCardApplet;

import terminal.backend.BackendSystem;
import terminal.common.CardComm;
import terminal.common.CryptoUtil;
import terminal.common.ByteUtil;
import terminal.common.ProtocolConstants;
import terminal.personalization.PersonalizationTerminal;
import terminal.reception.TestReceptionTerminal;
import terminal.vehicle.VehicleTerminal;

/**
 * Protocol / security tests: negative cases, edge conditions.
 */
public class ProtocolTest {

  static final byte[] APPLET_AID = {
      (byte) 0x3B, (byte) 0x29, (byte) 0x72, (byte) 0x65,
      (byte) 0x6E, (byte) 0x74, (byte) 0x01
  };
  static final byte[] CARD_ID = { 0x00, 0x00, 0x00, 0x01 };
  static final byte[] CUSTOMER_ID = { 0x00, 0x00, 0x00, 0x42 };
  static final byte[] VEHICLE_ID   = { 0x00, 0x00, 0x00, 0x05 };
  static final byte[] VEHICLE_ID_B = { 0x00, 0x00, 0x00, 0x06 };
  static final String PIN = "1234";

  // SW constants as ints (protocol uses short, getSW() returns int)
  static final int SW_OK = 0x9000;
  static final int SW_WRONG_STATE = 0x6A80;
  static final int SW_PIN_INCORRECT = 0x6A81;
  static final int SW_PIN_LOCKED = 0x6A82;
  static final int SW_SIGNATURE_INVALID = 0x6A84;
  static final int SW_SEQUENCE_ERROR = 0x6A85;
  static final int SW_CARD_BLOCKED = 0x6A86;
  static final int SW_UNPAID_MILEAGE = 0x6A87;
  static final int SW_CARD_EXPIRED = 0x6A88;

  static int passed = 0;
  static int failed = 0;
  static int testNum = 0;

  static BackendSystem backend;

  public static void main(String[] args) throws Exception {
    System.out.println("=== ProtocolTest: Security / Negative Cases ===\n");

    testWrongStateTransitions();
    testPinLockout();
    testTamperedSignature();
    testBlockedCard();
    testMileageReplay();
    testUnpaidMileageBlocksAssignment();
    testLoggingAuth();
    testLoggingAssignmentAndVehicle();
    testLoggingPaymentAndBlock();
    testEndOfLife();
    testVehicleReopenMidRental();
    testWrongVehicleRejected();
    testFlushLogsToBackend();
    testNoFlushMidRental();
    testFlushAfterReturnIsNoop();

    System.out.println("\n=== Results: " + passed + " passed, " + failed + " failed ===");
    if (failed > 0)
      System.exit(1);
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  static CardComm freshCard() throws Exception {
    BackendSystem.reset();
    backend = BackendSystem.getInstance();
    backend.init();
    backend.registerVehicle(VEHICLE_ID, "TEST-1");
    backend.registerCustomer(CUSTOMER_ID, "Test");

    String termName = "PT-" + (++testNum);
    CardTerminals terminals = CardTerminalSimulator.terminals(termName);
    CardTerminal terminal = terminals.getTerminal(termName);

    CardSimulator simulator = new CardSimulator();
    AID aid = new AID(APPLET_AID, (byte) 0, (byte) APPLET_AID.length);
    simulator.installApplet(aid, RentalCardApplet.class);
    simulator.assignToTerminal(terminal);

    Card card = terminal.connect("*");
    CardChannel channel = card.getBasicChannel();

    CommandAPDU select = new CommandAPDU(
        (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, APPLET_AID);
    channel.transmit(select);

    return new CardComm(channel);
  }

  static CardComm issuedCard() throws Exception {
    CardComm comm = freshCard();
    PersonalizationTerminal pt = new PersonalizationTerminal(comm, backend);
    pt.personalizeCard(CARD_ID, PIN);
    pt.issueCard(CUSTOMER_ID);
    return comm;
  }

  // Helper: unwrap a Result, throw on failure so tests propagate the error.
  static <T> T unwrap(terminal.common.Result<T> r) {
    if (!r.success) throw new RuntimeException("Result.fail: " + r.error.getMessage(), r.error);
    return r.value;
  }

  static byte[] doAssign(CardComm comm) throws Exception {
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);
    byte[] pkc = unwrap(rt.mutualAuth(PIN));
    long now = System.currentTimeMillis() / 1000;
    byte[] period = periodBytes(now, now + 86400);
    unwrap(rt.assignVehicle(VEHICLE_ID, CUSTOMER_ID, pkc, period));
    return pkc;
  }

  // -------------------------------------------------------------------------

  static void testWrongStateTransitions() throws Exception {
    System.out.println("-- Wrong state transitions --");

    CardComm comm = freshCard();

    ResponseAPDU r = comm.sendRaw(ProtocolConstants.INS_ISSUE_CARD, CUSTOMER_ID).value;
    check("ISSUE_CARD on BLANK rejected", r.getSW() == SW_WRONG_STATE);

    r = comm.sendRaw(ProtocolConstants.INS_GET_NONCE).value;
    check("GET_NONCE on BLANK rejected", r.getSW() == SW_WRONG_STATE);

    PersonalizationTerminal pt = new PersonalizationTerminal(comm, backend);
    pt.personalizeCard(CARD_ID, PIN);

    // PERSONALIZE_KEYS again after PERSONALIZED -> wrong state
    r = comm.sendRaw(ProtocolConstants.INS_PERSONALIZE_FINISH, CARD_ID).value;
    check("PERSONALIZE_FINISH on PERSONALIZED rejected", r.getSW() != SW_OK);

    // Issue card, then try SIGN_VEHICLE_REQ without auth
    pt.issueCard(CUSTOMER_ID);
    byte[] reqData = new byte[4 + 16 + 8];
    r = comm.sendRaw(ProtocolConstants.INS_SIGN_VEHICLE_REQ, reqData).value;
    check("SIGN_VEHICLE_REQ without auth rejected", r.getSW() != SW_OK);

    // GET_ASSIGNMENT_DATA in ISSUED state -> wrong state
    r = comm.sendRaw(ProtocolConstants.INS_GET_ASSIGNMENT_DATA).value;
    check("GET_ASSIGNMENT_DATA in ISSUED rejected", r.getSW() == SW_WRONG_STATE);
  }

  static void testPinLockout() throws Exception {
    System.out.println("\n-- PIN lockout --");

    CardComm comm = issuedCard();
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);

    // Terminal auth required before PIN verification
    byte[] cardNonce = unwrap(rt.getCardNonce());
    unwrap(rt.verifyTerminalToCard(cardNonce));

    byte[] wrongHash = CryptoUtil.hashPin("0000");
    ResponseAPDU r;

    r = comm.sendRaw(ProtocolConstants.INS_VERIFY_PIN, wrongHash).value;
    check("Wrong PIN 1 -> SW_PIN_INCORRECT", r.getSW() == SW_PIN_INCORRECT);

    r = comm.sendRaw(ProtocolConstants.INS_VERIFY_PIN, wrongHash).value;
    check("Wrong PIN 2 -> SW_PIN_INCORRECT", r.getSW() == SW_PIN_INCORRECT);

    r = comm.sendRaw(ProtocolConstants.INS_VERIFY_PIN, wrongHash).value;
    check("Wrong PIN 3 -> SW_PIN_LOCKED", r.getSW() == SW_PIN_LOCKED);

    // Correct PIN now also locked
    byte[] correctHash = CryptoUtil.hashPin(PIN);
    r = comm.sendRaw(ProtocolConstants.INS_VERIFY_PIN, correctHash).value;
    check("Correct PIN after lockout -> SW_PIN_LOCKED", r.getSW() == SW_PIN_LOCKED);
  }

  static void testTamperedSignature() throws Exception {
    System.out.println("\n-- Tampered signatures --");

    CardComm comm = issuedCard();
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);

    // Test 1: valid cert, corrupted signature
    byte[] cardNonce = unwrap(rt.getCardNonce());
    java.security.KeyPair termKP = backend.getTerminalKeyPair();
    byte[] termCert = backend.getTerminalCertificate();
    byte[] termSig = CryptoUtil.sign(termKP.getPrivate(), cardNonce);
    termSig[5] ^= 0xFF; // corrupt signature

    byte[] payload = buildVerifyPayload(termSig, termCert);
    ResponseAPDU r = comm.sendRaw(ProtocolConstants.INS_VERIFY_TERMINAL_SIG, payload).value;
    check("Corrupted terminal sig rejected", r.getSW() == SW_SIGNATURE_INVALID);

    // Test 2: cert signed by unknown key (not MSK)
    cardNonce = unwrap(rt.getCardNonce());
    java.security.KeyPair foreignKP = CryptoUtil.generateRSAKeyPair();
    byte[] foreignPkBytes = CryptoUtil.encodeRSAPublicKey(foreignKP.getPublic());
    byte[] fakeCert = CryptoUtil.createCertificate(
        new byte[] { 0x00, 0x01 }, foreignPkBytes, foreignKP.getPrivate());
    byte[] sig2 = CryptoUtil.sign(foreignKP.getPrivate(), cardNonce);

    byte[] payload2 = buildVerifyPayload(sig2, fakeCert);
    r = comm.sendRaw(ProtocolConstants.INS_VERIFY_TERMINAL_SIG, payload2).value;
    check("Cert not signed by MSK rejected", r.getSW() == SW_SIGNATURE_INVALID);
  }

  static void testBlockedCard() throws Exception {
    System.out.println("\n-- Blocked card --");

    CardComm comm = issuedCard();

    unwrap(comm.send(ProtocolConstants.INS_BLOCK_CARD));
    byte state = unwrap(comm.send(ProtocolConstants.INS_GET_STATE))[0];
    check("State BLOCKED after BLOCK_CARD", state == ProtocolConstants.STATE_BLOCKED);

    ResponseAPDU r;
    r = comm.sendRaw(ProtocolConstants.INS_GET_NONCE).value;
    check("GET_NONCE on blocked -> SW_CARD_BLOCKED", r.getSW() == SW_CARD_BLOCKED);

    r = comm.sendRaw(ProtocolConstants.INS_GET_MILEAGE).value;
    check("GET_MILEAGE on blocked -> SW_CARD_BLOCKED", r.getSW() == SW_CARD_BLOCKED);

    r = comm.sendRaw(ProtocolConstants.INS_BLOCK_CARD).value;
    check("BLOCK_CARD again -> SW_CARD_BLOCKED", r.getSW() == SW_CARD_BLOCKED);

    r = comm.sendRaw(ProtocolConstants.INS_GET_STATE).value;
    check("GET_STATE still works on blocked", r.getSW() == SW_OK);
  }

  static void testMileageReplay() throws Exception {
    System.out.println("\n-- Mileage replay --");

    CardComm comm = issuedCard();
    doAssign(comm);

    VehicleTerminal vt = new VehicleTerminal(comm, backend.getMasterPublicKey(), VEHICLE_ID);
    unwrap(vt.openVehicle());

    unwrap(vt.updateMileage((short) 100));
    check("First mileage update (seq=0) accepted", unwrap(vt.getMileage()) == 100);

    // Replay seq=0
    byte[] replay = { 0x00, 0x64, 0x00, 0x00 }; // mileage=100, seq=0
    ResponseAPDU r = comm.sendRaw(ProtocolConstants.INS_UPDATE_MILEAGE, replay).value;
    check("Replay seq=0 rejected", r.getSW() == SW_SEQUENCE_ERROR);

    // seq=1 succeeds
    unwrap(vt.updateMileage((short) 200));
    check("Second update (seq=1) accepted", unwrap(vt.getMileage()) == 200);
  }

  static void testUnpaidMileageBlocksAssignment() throws Exception {
    System.out.println("\n-- Unpaid mileage blocks re-assignment --");

    CardComm comm = issuedCard();
    byte[] pkc = doAssign(comm);

    VehicleTerminal vt = new VehicleTerminal(comm, backend.getMasterPublicKey(), VEHICLE_ID);
    unwrap(vt.openVehicle());
    unwrap(vt.updateMileage((short) 50));
    unwrap(vt.returnVehicle((short) 100, pkc));
    // Card now ISSUED with mileage=100

    // Re-auth (session flags still set from doAssign, but GET_NONCE refreshes
    // lastNonce)
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);
    rt.mutualAuth(PIN);

    // Release vehicle in backend so assignment isn't blocked by availability
    backend.releaseVehicle(VEHICLE_ID);

    // Try to sign vehicle request - should be blocked by unpaid mileage
    byte[] reqData = ByteUtil.concat(
        VEHICLE_ID,
        CryptoUtil.generateNonce(ProtocolConstants.NONCE_LENGTH),
        periodBytes(System.currentTimeMillis() / 1000, System.currentTimeMillis() / 1000 + 86400));

    ResponseAPDU r = comm.sendRaw(ProtocolConstants.INS_SIGN_VEHICLE_REQ, reqData).value;
    check("SIGN_VEHICLE_REQ with unpaid mileage rejected", r.getSW() == SW_UNPAID_MILEAGE);
  }

  // -------------------------------------------------------------------------

  static void testLoggingAuth() throws Exception {
    System.out.println("\n-- Logging: auth events --");

    CardComm comm = issuedCard();
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);
    rt.mutualAuth(PIN);

    check("AUTH_SUCCESS in backend log", hasEvent(backend.getAuditLog(), BackendSystem.EVENT_AUTH_SUCCESS));

    comm = issuedCard();
    rt = new TestReceptionTerminal(comm, backend);
    try {
      rt.mutualAuth("9999");
    } catch (Exception e) {
      /* expected */ }

    check("AUTH_FAIL in backend log after wrong PIN", hasEvent(backend.getAuditLog(), BackendSystem.EVENT_AUTH_FAIL));
  }

  static void testLoggingAssignmentAndVehicle() throws Exception {
    System.out.println("\n-- Logging: assignment and vehicle open --");

    CardComm comm = issuedCard();
    byte[] pkc = doAssign(comm);

    check("VEHICLE_ASSIGNED in backend log with crypto evidence",
        hasEventWithEvidence(backend.getAuditLog(), BackendSystem.EVENT_VEHICLE_ASSIGNED));

    VehicleTerminal vt = new VehicleTerminal(comm, backend.getMasterPublicKey(), VEHICLE_ID);
    vt.openVehicle();

    check("VEHICLE_OPENED in vehicle log with sigma5",
        hasEventWithEvidence(vt.getLog(), BackendSystem.EVENT_VEHICLE_OPENED));

    vt.updateMileage((short) 75);
    check("MILEAGE_UPDATE in vehicle log", hasEvent(vt.getLog(), BackendSystem.EVENT_MILEAGE_UPDATE));
    check("MILEAGE_UPDATE details contain old+new",
        hasEventWithDetails(vt.getLog(), BackendSystem.EVENT_MILEAGE_UPDATE, "old="));
  }

  static void testLoggingPaymentAndBlock() throws Exception {
    System.out.println("\n-- Logging: payment and card block --");

    CardComm comm = issuedCard();
    byte[] pkc = doAssign(comm);
    VehicleTerminal vt = new VehicleTerminal(comm, backend.getMasterPublicKey(), VEHICLE_ID);
    vt.openVehicle();
    vt.updateMileage((short) 30);
    vt.returnVehicle((short) 60, pkc);

    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);
    rt.mutualAuth(PIN);
    rt.processMileagePayment(CUSTOMER_ID);

    check("PAYMENT in backend log", hasEvent(backend.getAuditLog(), BackendSystem.EVENT_PAYMENT));

    comm = issuedCard();
    unwrap(comm.send(ProtocolConstants.INS_BLOCK_CARD));
    backend.blockCard(CARD_ID);

    check("CARD_BLOCKED in backend log", hasEvent(backend.getAuditLog(), BackendSystem.EVENT_CARD_BLOCKED));
  }

  static void testEndOfLife() throws Exception {
    System.out.println("\n-- End-of-life state --");

    CardComm comm = freshCard();
    terminal.personalization.PersonalizationTerminal pt = new terminal.personalization.PersonalizationTerminal(comm,
        backend);
    // Personalize with past expiry: year 2020 = 1577836800000 ms
    pt.personalizeCard(CARD_ID, PIN, 1577836800000L);
    pt.issueCard(CUSTOMER_ID);

    // Check expiry with current time (> 2020)
    long now = System.currentTimeMillis();
    byte[] nowBytes = longToBytes(now);
    ResponseAPDU r = comm.sendRaw(ProtocolConstants.INS_CHECK_EXPIRY, nowBytes).value;
    check("CHECK_EXPIRY with past expiry -> SW_CARD_EXPIRED", r.getSW() == SW_CARD_EXPIRED);

    r = comm.sendRaw(ProtocolConstants.INS_GET_NONCE).value;
    check("GET_NONCE on expired card -> SW_CARD_EXPIRED", r.getSW() == SW_CARD_EXPIRED);

    r = comm.sendRaw(ProtocolConstants.INS_GET_STATE).value;
    check("GET_STATE still works on expired card", r.getSW() == SW_OK);
    check("State is END_OF_LIFE (0x05)", r.getData()[0] == ProtocolConstants.STATE_END_OF_LIFE);
  }

  static void testVehicleReopenMidRental() throws Exception {
    System.out.println("\n-- Re-opening same vehicle mid-rental (mileage > 0) is allowed --");

    CardComm comm = issuedCard();
    byte[] pkc = doAssign(comm);
    VehicleTerminal vt = new VehicleTerminal(comm, backend.getMasterPublicKey(), VEHICLE_ID);
    unwrap(vt.openVehicle());
    unwrap(vt.updateMileage((short) 50));
    // Card is ASSIGNED with mileage=50; should still be openable

    boolean reopened = vt.openVehicle().success;
    check("Same vehicle re-open with mileage > 0 succeeds", reopened);
  }

  static void testWrongVehicleRejected() throws Exception {
    System.out.println("\n-- Card assigned to vehicle A cannot open vehicle B --");

    // Register a second vehicle in the backend (freshCard already registers VEHICLE_ID)
    CardComm comm = issuedCard();
    backend.registerVehicle(VEHICLE_ID_B, "TEST-B");

    // Assign card to VEHICLE_ID (vehicle A)
    byte[] pkc = doAssign(comm);

    // Try to open VEHICLE_ID_B (vehicle B) with the card assigned to vehicle A
    VehicleTerminal vtB = new VehicleTerminal(comm, backend.getMasterPublicKey(), VEHICLE_ID_B);
    boolean rejected = !vtB.openVehicle().success;
    check("Card assigned to vehicle A rejected by vehicle B", rejected);

    // Confirm the correct vehicle terminal still accepts the card
    VehicleTerminal vtA = new VehicleTerminal(comm, backend.getMasterPublicKey(), VEHICLE_ID);
    boolean accepted = vtA.openVehicle().success;
    check("Card assigned to vehicle A accepted by vehicle A", accepted);
  }

  static void testFlushLogsToBackend() throws Exception {
    System.out.println("\n-- flushLogsToBackend: offline log sync --");

    // --- Setup: assign and open vehicle, accumulate local log entries ---
    CardComm comm = issuedCard();
    byte[] pkc = doAssign(comm);

    VehicleTerminal vt = new VehicleTerminal(comm, backend.getMasterPublicKey(), VEHICLE_ID);
    vt.openVehicle();
    vt.updateMileage((short) 42);
    vt.returnVehicle((short) 100, pkc);

    // Capture backend log size before flush - none of the vehicle events should be there yet
    int backendSizeBefore = backend.getAuditLog().size();

    // --- Before flush: vehicle events only in local log, not in backend ---
    check("VEHICLE_OPENED in local log before flush",
        hasEvent(vt.getLog(), BackendSystem.EVENT_VEHICLE_OPENED));
    check("MILEAGE_UPDATE in local log before flush",
        hasEvent(vt.getLog(), BackendSystem.EVENT_MILEAGE_UPDATE));
    check("VEHICLE_OPENED not in backend log before flush",
        !hasEvent(backend.getAuditLog(), BackendSystem.EVENT_VEHICLE_OPENED));
    check("MILEAGE_UPDATE not in backend log before flush",
        !hasEvent(backend.getAuditLog(), BackendSystem.EVENT_MILEAGE_UPDATE));

    // --- Perform flush ---
    vt.flushLogsToBackend(backend);

    // --- After flush: local log is empty ---
    check("Local log is empty after flush", vt.getLog().isEmpty());

    // --- After flush: backend log contains the vehicle events ---
    check("VEHICLE_OPENED in backend log after flush",
        hasEvent(backend.getAuditLog(), BackendSystem.EVENT_VEHICLE_OPENED));
    check("MILEAGE_UPDATE in backend log after flush",
        hasEvent(backend.getAuditLog(), BackendSystem.EVENT_MILEAGE_UPDATE));

    // --- Failure path: VEHICLE_OPEN_FAIL logged locally and flushed to backend ---
    CardComm comm2 = issuedCard();
    backend.registerVehicle(VEHICLE_ID_B, "TEST-B");
    byte[] pkc2 = doAssign(comm2); // assigned to VEHICLE_ID, not VEHICLE_ID_B

    VehicleTerminal vtB = new VehicleTerminal(comm2, backend.getMasterPublicKey(), VEHICLE_ID_B);
    try {
      vtB.openVehicle();
    } catch (Exception e) {
      /* expected - wrong vehicle */ }

    check("VEHICLE_OPEN_FAIL in local log before flush",
        hasEvent(vtB.getLog(), BackendSystem.EVENT_VEHICLE_OPEN_FAIL));
    check("VEHICLE_OPEN_FAIL not in backend log before flush",
        !hasEvent(backend.getAuditLog(), BackendSystem.EVENT_VEHICLE_OPEN_FAIL));

    vtB.flushLogsToBackend(backend);

    check("VEHICLE_OPEN_FAIL in backend log after flush",
        hasEvent(backend.getAuditLog(), BackendSystem.EVENT_VEHICLE_OPEN_FAIL));
    check("Local log empty after flushing failure events", vtB.getLog().isEmpty());
  }

  static void testNoFlushMidRental() throws Exception {
    System.out.println("\n-- Mid-rental: log stays local until return --");

    CardComm comm = issuedCard();
    byte[] pkc = doAssign(comm);
    VehicleTerminal vt = new VehicleTerminal(comm, backend.getMasterPublicKey(), VEHICLE_ID);
    vt.openVehicle();
    vt.updateMileage((short) 50);
    // Vehicle is mid-rental: do NOT flush (simulates exiting vehicle menu without return)

    check("VEHICLE_OPENED in local log mid-rental",
        hasEvent(vt.getLog(), BackendSystem.EVENT_VEHICLE_OPENED));
    check("MILEAGE_UPDATE in local log mid-rental",
        hasEvent(vt.getLog(), BackendSystem.EVENT_MILEAGE_UPDATE));
    check("VEHICLE_OPENED not in backend log mid-rental",
        !hasEvent(backend.getAuditLog(), BackendSystem.EVENT_VEHICLE_OPENED));
    check("MILEAGE_UPDATE not in backend log mid-rental",
        !hasEvent(backend.getAuditLog(), BackendSystem.EVENT_MILEAGE_UPDATE));
  }

  static void testFlushAfterReturnIsNoop() throws Exception {
    System.out.println("\n-- Double flush after return is a no-op --");

    CardComm comm = issuedCard();
    byte[] pkc = doAssign(comm);
    VehicleTerminal vt = new VehicleTerminal(comm, backend.getMasterPublicKey(), VEHICLE_ID);
    vt.openVehicle();
    vt.updateMileage((short) 30);
    vt.returnVehicle((short) 60, pkc);

    // First flush (simulates return path)
    vt.flushLogsToBackend(backend);
    int backendSizeAfterFirst = backend.getAuditLog().size();

    // Second flush (simulates exit-path when sessionPkc == null after return)
    vt.flushLogsToBackend(backend);
    int backendSizeAfterSecond = backend.getAuditLog().size();

    check("Local log empty after first flush", vt.getLog().isEmpty());
    check("Second flush adds nothing to backend", backendSizeAfterFirst == backendSizeAfterSecond);
  }

  // -------------------------------------------------------------------------
  // Logging helpers

  static boolean hasEvent(List<BackendSystem.AuditEntry> log, String eventType) {
    for (BackendSystem.AuditEntry e : log) {
      if (eventType.equals(e.eventType))
        return true;
    }
    return false;
  }

  static boolean hasEventWithEvidence(List<BackendSystem.AuditEntry> log, String eventType) {
    for (BackendSystem.AuditEntry e : log) {
      if (eventType.equals(e.eventType) && e.cryptoEvidence != null)
        return true;
    }
    return false;
  }

  static boolean hasEventWithDetails(List<BackendSystem.AuditEntry> log, String eventType, String substring) {
    for (BackendSystem.AuditEntry e : log) {
      if (eventType.equals(e.eventType) && e.details != null && e.details.contains(substring))
        return true;
    }
    return false;
  }

  static byte[] longToBytes(long v) {
    byte[] b = new byte[8];
    for (int i = 7; i >= 0; i--) {
      b[i] = (byte) (v & 0xFF);
      v >>= 8;
    }
    return b;
  }

  // -------------------------------------------------------------------------

  static byte[] buildVerifyPayload(byte[] sig, byte[] cert) {
    byte[] payload = new byte[2 + sig.length + cert.length];
    payload[0] = (byte) ((sig.length >> 8) & 0xFF);
    payload[1] = (byte) (sig.length & 0xFF);
    System.arraycopy(sig, 0, payload, 2, sig.length);
    System.arraycopy(cert, 0, payload, 2 + sig.length, cert.length);
    return payload;
  }

  static byte[] periodBytes(long start, long end) {
    byte[] buf = new byte[8];
    buf[0] = (byte) ((start >> 24) & 0xFF);
    buf[1] = (byte) ((start >> 16) & 0xFF);
    buf[2] = (byte) ((start >> 8) & 0xFF);
    buf[3] = (byte) (start & 0xFF);
    buf[4] = (byte) ((end >> 24) & 0xFF);
    buf[5] = (byte) ((end >> 16) & 0xFF);
    buf[6] = (byte) ((end >> 8) & 0xFF);
    buf[7] = (byte) (end & 0xFF);
    return buf;
  }

  static void check(String name, boolean condition) {
    if (condition) {
      System.out.println("  PASS: " + name);
      passed++;
    } else {
      System.out.println("  FAIL: " + name);
      failed++;
    }
  }
}
