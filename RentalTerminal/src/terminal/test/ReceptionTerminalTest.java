package terminal.test;

import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;

import applet.RentalCardApplet;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;

import javacard.framework.AID;

import terminal.backend.BackendSystem;
import terminal.util.CardComm;
import terminal.util.ProtocolConstants;
import terminal.logging.Result;
import terminal.personalization.PersonalizationTerminal;

public class ReceptionTerminalTest {
  static final byte[] APPLET_AID = {
      (byte) 0x3B, (byte) 0x29, (byte) 0x72, (byte) 0x65,
      (byte) 0x6E, (byte) 0x74, (byte) 0x01
  };
  static final byte[] CARD_ID = { 0x00, 0x00, 0x00, 0x01 };
  static final byte[] CUSTOMER_ID = { 0x00, 0x00, 0x00, 0x42 };
  static final byte[] VEHICLE_ID = { 0x00, 0x00, 0x00, 0x05 };
  static final String PIN = "1234";

  static int passed = 0;
  static int failed = 0;
  static int testNum = 0;
  static BackendSystem backend;

  public static void main(String[] args) throws Exception {
    System.out.println("=== ReceptionTerminalTest ===");

    testAuthSuccessBufferedLocally();
    testAuthFailBufferedLocally();
    testAssignVehicleBufferedLocally();
    testFlushSendsToBackend();
    testShutdownFlushesRemaining();
    testBlockedCardRejectedInMutualAuth();
    testWrongPinLogsAuthFailWithDetail();
    testMutualAuthSuccessLogsWithEvidence();
    testMileagePaymentZeroMileage();
    testMileagePaymentNonZeroMileage();
    testAssignVehicleAlreadyAssignedLogsFailure();

    System.out.println("\n=== Results: " + passed + " passed, " + failed + " failed ===");
    if (failed > 0) System.exit(1);
  }

  static CardComm issuedCard() throws Exception {
    BackendSystem.reset();
    backend = BackendSystem.getInstance();
    backend.init();
    backend.registerVehicle(VEHICLE_ID, "TEST-1");
    backend.registerCustomer(CUSTOMER_ID, "Test");

    String termName = "RTT-" + (++testNum);
    CardTerminals terminals = CardTerminalSimulator.terminals(termName);
    CardTerminal terminal = terminals.getTerminal(termName);

    CardSimulator simulator = new CardSimulator();
    AID aid = new AID(APPLET_AID, (byte) 0, (byte) APPLET_AID.length);
    simulator.installApplet(aid, RentalCardApplet.class);
    simulator.assignToTerminal(terminal);

    Card card = terminal.connect("*");
    CardChannel channel = card.getBasicChannel();
    channel.transmit(new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, APPLET_AID));

    CardComm comm = new CardComm(channel);
    PersonalizationTerminal pt = new PersonalizationTerminal(comm, backend);
    pt.personalizeCard(CARD_ID, PIN);
    pt.issueCard(CUSTOMER_ID);
    return comm;
  }

  static void testAuthSuccessBufferedLocally() throws Exception {
    System.out.println("\n-- Auth success is buffered locally --");
    CardComm comm = issuedCard();
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);

    rt.mutualAuth(PIN);

    check("AUTH_SUCCESS in local log", hasEvent(rt.auditLog.getLog(), BackendSystem.EVENT_AUTH_SUCCESS));
    check("AUTH_SUCCESS not in backend log yet", !hasEvent(backend.getAuditLog(), BackendSystem.EVENT_AUTH_SUCCESS));

    rt.shutdown();
  }

  static void testAuthFailBufferedLocally() throws Exception {
    System.out.println("\n-- Auth fail is buffered locally --");
    CardComm comm = issuedCard();
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);

    rt.mutualAuth("wrong-pin");

    check("AUTH_FAIL in local log", hasEvent(rt.auditLog.getLog(), BackendSystem.EVENT_AUTH_FAIL));
    check("AUTH_FAIL not in backend log yet", !hasEvent(backend.getAuditLog(), BackendSystem.EVENT_AUTH_FAIL));

    rt.shutdown();
  }

  static void testAssignVehicleBufferedLocally() throws Exception {
    System.out.println("\n-- Vehicle assignment is buffered locally --");
    CardComm comm = issuedCard();
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);

    byte[] pkc = unwrap(rt.mutualAuth(PIN));
    long now = System.currentTimeMillis() / 1000;
    rt.assignVehicle(VEHICLE_ID, CUSTOMER_ID, pkc, periodBytes(now, now + 86400));

    check("VEHICLE_ASSIGNED in local log", hasEvent(rt.auditLog.getLog(), BackendSystem.EVENT_VEHICLE_ASSIGNED));
    check("VEHICLE_ASSIGNED not in backend log yet", !hasEvent(backend.getAuditLog(), BackendSystem.EVENT_VEHICLE_ASSIGNED));

    rt.shutdown();
  }

  static void testFlushSendsToBackend() throws Exception {
    System.out.println("\n-- flushLogsToBackend sends events and clears local log --");
    CardComm comm = issuedCard();
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);

    byte[] pkc = unwrap(rt.mutualAuth(PIN));
    long now = System.currentTimeMillis() / 1000;
    rt.assignVehicle(VEHICLE_ID, CUSTOMER_ID, pkc, periodBytes(now, now + 86400));

    rt.auditLog.flushToBackend(rt.backend);

    check("local log empty after flush", rt.auditLog.getLog().isEmpty());
    check("AUTH_SUCCESS in backend log after flush", hasEvent(backend.getAuditLog(), BackendSystem.EVENT_AUTH_SUCCESS));
    check("VEHICLE_ASSIGNED in backend log after flush", hasEvent(backend.getAuditLog(), BackendSystem.EVENT_VEHICLE_ASSIGNED));

    rt.shutdown();
  }

  static void testShutdownFlushesRemaining() throws Exception {
    System.out.println("\n-- shutdown flushes remaining entries --");
    CardComm comm = issuedCard();
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);

    rt.mutualAuth(PIN);
    check("events buffered before shutdown", !rt.auditLog.getLog().isEmpty());

    rt.shutdown();

    check("AUTH_SUCCESS in backend log after shutdown", hasEvent(backend.getAuditLog(), BackendSystem.EVENT_AUTH_SUCCESS));
  }

  static void testBlockedCardRejectedInMutualAuth() throws Exception {
    System.out.println("\n-- Blocked card is rejected in mutualAuth and CARD_BLOCKED is logged --");
    CardComm comm = issuedCard();
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);

    // Block the card by its known ID (set during personalization in issuedCard())
    backend.blockCard(CARD_ID);

    Result<byte[]> result = rt.mutualAuth(PIN);

    check("mutualAuth fails for blocked card", !result.success);
    check("CARD_BLOCKED in local log", hasEvent(rt.auditLog.getLog(), BackendSystem.EVENT_CARD_BLOCKED));
    // Verify INS_BLOCK_CARD was actually sent: card state must now be BLOCKED.
    Result<byte[]> stateResult = rt.getComm().send(ProtocolConstants.INS_GET_STATE);
    check("card state is BLOCKED after enforceBlocklist", stateResult.success
        && stateResult.value[0] == ProtocolConstants.STATE_BLOCKED);

    rt.shutdown();
  }

  static void testWrongPinLogsAuthFailWithDetail() throws Exception {
    System.out.println("\n-- Wrong PIN logs AUTH_FAIL with error detail --");
    CardComm comm = issuedCard();
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);

    Result<byte[]> result = rt.mutualAuth("wrong-pin");

    check("mutualAuth fails for wrong PIN", !result.success);
    check("AUTH_FAIL in local log", hasEvent(rt.auditLog.getLog(), BackendSystem.EVENT_AUTH_FAIL));
    // Check that the AUTH_FAIL entry contains a non-null details/error message
    BackendSystem.AuditEntry failEntry = findEvent(rt.auditLog.getLog(), BackendSystem.EVENT_AUTH_FAIL);
    check("AUTH_FAIL entry has error detail", failEntry != null && failEntry.details != null && !failEntry.details.isEmpty());

    rt.shutdown();
  }

  static void testMutualAuthSuccessLogsWithEvidence() throws Exception {
    System.out.println("\n-- Successful mutualAuth logs AUTH_SUCCESS with non-null cryptoEvidence --");
    CardComm comm = issuedCard();
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);

    Result<byte[]> result = rt.mutualAuth(PIN);

    check("mutualAuth succeeds", result.success);
    check("returned pkc is non-null and non-empty", result.success && result.value != null && result.value.length > 0);
    BackendSystem.AuditEntry successEntry = findEvent(rt.auditLog.getLog(), BackendSystem.EVENT_AUTH_SUCCESS);
    check("AUTH_SUCCESS entry has non-null cryptoEvidence", successEntry != null && successEntry.cryptoEvidence != null && successEntry.cryptoEvidence.length > 0);

    rt.shutdown();
  }

  static void testMileagePaymentZeroMileage() throws Exception {
    System.out.println("\n-- processMileagePayment with zero mileage returns 0 --");
    CardComm comm = issuedCard();
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);

    // Auth first so session flags are set (required for INS_CLEAR_MILEAGE)
    unwrap(rt.mutualAuth(PIN));

    // Card is ISSUED with mileage=0; processMileagePayment should return 0
    Result<Integer> payResult = rt.processMileagePayment(CUSTOMER_ID);

    check("processMileagePayment succeeds with zero mileage", payResult.success);
    check("processMileagePayment returns 0 for zero mileage", payResult.success && payResult.value == 0);
    // With mutation mileage>=0: the payment block executes and logs EVENT_PAYMENT.
    // With real code mileage>0: the block is skipped, no EVENT_PAYMENT logged.
    check("no PAYMENT event logged for zero mileage", !hasEvent(rt.auditLog.getLog(), BackendSystem.EVENT_PAYMENT));

    rt.shutdown();
  }

  static void testMileagePaymentNonZeroMileage() throws Exception {
    System.out.println("\n-- processMileagePayment with non-zero mileage returns mileage and clears card --");
    CardComm comm = issuedCard();
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);

    // Assign vehicle (mutualAuth + assignVehicle)
    byte[] pkc = unwrap(rt.mutualAuth(PIN));
    long now = System.currentTimeMillis() / 1000;
    unwrap(rt.assignVehicle(VEHICLE_ID, CUSTOMER_ID, pkc, periodBytes(now, now + 86400)));

    // Open and update mileage via vehicle terminal
    TestVehicleTerminal vt = new TestVehicleTerminal(comm, backend.getMasterPublicKey(),
        backend.getTerminalKeyPair(), backend.getTerminalCertificate(), VEHICLE_ID);
    unwrap(vt.open());
    unwrap(vt.updateMileage((short) 42));

    // Return vehicle (card transitions back to ISSUED, mileage=42 remains)
    unwrap(vt.returnVehicle((short) 42, pkc));

    // Session flags still set from earlier auth; processMileagePayment should read 42 and clear it
    Result<Integer> payResult = rt.processMileagePayment(CUSTOMER_ID);

    check("processMileagePayment succeeds with non-zero mileage", payResult.success);
    check("processMileagePayment returns 42", payResult.success && payResult.value == 42);

    // After payment, a second processMileagePayment should return 0 (mileage cleared on card)
    Result<Integer> payResult2 = rt.processMileagePayment(CUSTOMER_ID);
    check("second processMileagePayment returns 0 after clear", payResult2.success && payResult2.value == 0);

    rt.shutdown();
  }

  static void testAssignVehicleAlreadyAssignedLogsFailure() throws Exception {
    System.out.println("\n-- Duplicate assignVehicle (card in ASSIGNED state) logs VEHICLE_ASSIGNED FAILED --");
    CardComm comm = issuedCard();
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);

    // First assignment succeeds
    byte[] pkc = unwrap(rt.mutualAuth(PIN));
    long now = System.currentTimeMillis() / 1000;
    unwrap(rt.assignVehicle(VEHICLE_ID, CUSTOMER_ID, pkc, periodBytes(now, now + 86400)));

    // Second assignment: card is now in ASSIGNED state, so INS_SIGN_VEHICLE_REQ will fail
    Result<Void> secondResult = rt.assignVehicle(VEHICLE_ID, CUSTOMER_ID, pkc, periodBytes(now, now + 86400));

    check("second assignVehicle fails", !secondResult.success);
    // There should be a VEHICLE_ASSIGNED entry with FAILED detail in the local log
    BackendSystem.AuditEntry failEntry = findEventWithDetail(rt.auditLog.getLog(), BackendSystem.EVENT_VEHICLE_ASSIGNED, "FAILED");
    check("VEHICLE_ASSIGNED FAILED in local log", failEntry != null);

    rt.shutdown();
  }

  static boolean hasEvent(List<BackendSystem.AuditEntry> log, String eventType) {
    for (BackendSystem.AuditEntry e : log) {
      if (eventType.equals(e.eventType)) return true;
    }
    return false;
  }

  static BackendSystem.AuditEntry findEvent(List<BackendSystem.AuditEntry> log, String eventType) {
    for (BackendSystem.AuditEntry e : log) {
      if (eventType.equals(e.eventType)) return e;
    }
    return null;
  }

  static BackendSystem.AuditEntry findEventWithDetail(List<BackendSystem.AuditEntry> log, String eventType, String detailSubstring) {
    for (BackendSystem.AuditEntry e : log) {
      if (eventType.equals(e.eventType) && e.details != null && e.details.contains(detailSubstring)) return e;
    }
    return null;
  }

  static <T> T unwrap(Result<T> r) {
    if (!r.success) throw new RuntimeException("Result.fail: " + r.error.getMessage(), r.error);
    return r.value;
  }

  static void check(String name, boolean condition) {
    if (condition) {
      passed++;
      System.out.println("[PASS] " + name);
    } else {
      failed++;
      System.out.println("[FAIL] " + name);
    }
  }

  static byte[] periodBytes(long startSecs, long endSecs) {
    byte[] b = new byte[8];
    b[0] = (byte) ((startSecs >> 24) & 0xFF);
    b[1] = (byte) ((startSecs >> 16) & 0xFF);
    b[2] = (byte) ((startSecs >> 8) & 0xFF);
    b[3] = (byte) (startSecs & 0xFF);
    b[4] = (byte) ((endSecs >> 24) & 0xFF);
    b[5] = (byte) ((endSecs >> 16) & 0xFF);
    b[6] = (byte) ((endSecs >> 8) & 0xFF);
    b[7] = (byte) (endSecs & 0xFF);
    return b;
  }
}
