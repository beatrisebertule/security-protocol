package terminal.test;

import java.security.*;
import java.util.List;

import terminal.backend.BackendSystem;
import terminal.backend.Customer;
import terminal.backend.Vehicle;
import terminal.util.ByteUtil;
import terminal.util.CryptoUtil;
import terminal.util.TokenUtil;

/**
 * BackendSystem unit tests for registry, audit-log, and assignment-token logic.
 *
 * These tests isolate backend behavior from the card simulator so mutations in
 * vehicle lookup, customer lookup, logging, payment clearing, block handling,
 * and token verification are caught without running a full protocol flow.
 */
public class BackendSystemTest {

  static int passed = 0;
  static int failed = 0;

  public static void main(String[] args) throws Exception {
    System.out.println("=== BackendSystemTest ===\n");

    testGetVehicleKnownAndUnknown();
    testGetCustomerKnownAndUnknown();
    testAssignVehicleReturnsTrue();
    testAssignVehicleReturnsFalseWhenUnavailable();
    testCompleteAssignmentUnknownVehicle();
    testLinkCardToCustomerUnknownCustomer();
    testAddMileageToCustomerKnown();
    testAddMileageToCustomerUnknown();
    testProcessPaymentKnown();
    testProcessPaymentUnknown();
    testBlockCustomerKnown();
    testBlockCustomerUnknown();
    testLogEventAppearsInAuditLog();
    testLogEventNullCardId();
    testLogEventNullVehicleId();
    testLogEventTwiceNoThrow();
    testGetAuditLogByCardIdFiltersCorrectly();
    testVerifyAssignmentToken();

    System.out.println("\n=== Results: " + passed + " passed, " + failed + " failed ===");
    if (failed > 0)
      System.exit(1);
  }

  // --- Helpers ---

  static BackendSystem setup() throws Exception {
    BackendSystem.reset();
    BackendSystem b = BackendSystem.getInstance();
    b.init();
    return b;
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

  // --- Test methods ---

  static void testGetVehicleKnownAndUnknown() throws Exception {
    System.out.println("-- getVehicle --");
    BackendSystem b = setup();
    byte[] vid = { 0x01, 0x00, 0x00, 0x01 };
    byte[] unknown = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
    b.registerVehicle(vid, "AB-001-CD");
    check("getVehicle known returns non-null", b.getVehicle(vid) != null);
    check("getVehicle unknown returns null", b.getVehicle(unknown) == null);
  }

  static void testGetCustomerKnownAndUnknown() throws Exception {
    System.out.println("-- getCustomer --");
    BackendSystem b = setup();
    byte[] cid = { 0x02, 0x00, 0x00, 0x01 };
    byte[] unknown = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE };
    b.registerCustomer(cid, "Alice");
    check("getCustomer known returns non-null", b.getCustomer(cid) != null);
    check("getCustomer unknown returns null", b.getCustomer(unknown) == null);
  }

  static void testAssignVehicleReturnsTrue() throws Exception {
    System.out.println("-- assignVehicle returns true --");
    BackendSystem b = setup();
    byte[] vid = { 0x01, 0x00, 0x00, 0x02 };
    byte[] cid = { 0x02, 0x00, 0x00, 0x02 };
    b.registerVehicle(vid, "EF-002-GH");
    boolean result = b.assignVehicle(vid, cid);
    check("assignVehicle known available returns true", result);
  }

  static void testAssignVehicleReturnsFalseWhenUnavailable() throws Exception {
    System.out.println("-- assignVehicle returns false when unavailable --");
    BackendSystem b = setup();
    byte[] vid = { 0x01, 0x00, 0x00, 0x03 };
    byte[] cid = { 0x02, 0x00, 0x00, 0x03 };
    b.registerVehicle(vid, "IJ-003-KL");
    b.assignVehicle(vid, cid);
    // Vehicle is now assigned - isAvailable() returns false
    boolean second = b.assignVehicle(vid, cid);
    check("assignVehicle unavailable returns false", !second);
  }

  static void testCompleteAssignmentUnknownVehicle() throws Exception {
    System.out.println("-- completeAssignment unknown vehicle --");
    BackendSystem b = setup();
    byte[] unknown = { (byte) 0xFF, (byte) 0xFF, 0x00, 0x01 };
    byte[] cid = { 0x02, 0x00, 0x00, 0x04 };
    // Should not throw
    b.completeAssignment(unknown, cid);
    check("completeAssignment unknown vehicle no throw", true);
  }

  static void testLinkCardToCustomerUnknownCustomer() throws Exception {
    System.out.println("-- linkCardToCustomer unknown customer --");
    BackendSystem b = setup();
    byte[] unknown = { (byte) 0xFF, (byte) 0xFF, 0x00, 0x02 };
    byte[] cardId = { 0x10, 0x20, 0x30, 0x40 };
    // Should not throw
    b.linkCardToCustomer(unknown, cardId);
    check("linkCardToCustomer unknown no throw", true);
  }

  static void testAddMileageToCustomerKnown() throws Exception {
    System.out.println("-- addMileageToCustomer known --");
    BackendSystem b = setup();
    byte[] cid = { 0x02, 0x00, 0x00, 0x05 };
    b.registerCustomer(cid, "Bob");
    b.addMileageToCustomer(cid, 100);
    Customer c = b.getCustomer(cid);
    check("addMileageToCustomer known sets mileage", c.getOutstandingMileage() == 100);
  }

  static void testAddMileageToCustomerUnknown() throws Exception {
    System.out.println("-- addMileageToCustomer unknown --");
    BackendSystem b = setup();
    byte[] unknown = { (byte) 0xFF, (byte) 0xFF, 0x00, 0x03 };
    // Should not throw
    b.addMileageToCustomer(unknown, 100);
    check("addMileageToCustomer unknown no throw", true);
  }

  static void testProcessPaymentKnown() throws Exception {
    System.out.println("-- processPayment known --");
    BackendSystem b = setup();
    byte[] cid = { 0x02, 0x00, 0x00, 0x06 };
    b.registerCustomer(cid, "Carol");
    b.addMileageToCustomer(cid, 200);
    b.processPayment(cid);
    Customer c = b.getCustomer(cid);
    check("processPayment clears mileage", c.getOutstandingMileage() == 0);
  }

  static void testProcessPaymentUnknown() throws Exception {
    System.out.println("-- processPayment unknown --");
    BackendSystem b = setup();
    byte[] unknown = { (byte) 0xFF, (byte) 0xFF, 0x00, 0x04 };
    // Should not throw
    b.processPayment(unknown);
    check("processPayment unknown no throw", true);
  }

  static void testBlockCustomerKnown() throws Exception {
    System.out.println("-- blockCustomer known --");
    BackendSystem b = setup();
    byte[] cid = { 0x02, 0x00, 0x00, 0x07 };
    b.registerCustomer(cid, "Dave");
    b.blockCustomer(cid);
    Customer c = b.getCustomer(cid);
    check("blockCustomer marks customer blocked", c.isBlocked());
  }

  static void testBlockCustomerUnknown() throws Exception {
    System.out.println("-- blockCustomer unknown --");
    BackendSystem b = setup();
    byte[] unknown = { (byte) 0xFF, (byte) 0xFF, 0x00, 0x05 };
    // Should not throw
    b.blockCustomer(unknown);
    check("blockCustomer unknown no throw", true);
  }

  static void testLogEventAppearsInAuditLog() throws Exception {
    System.out.println("-- logEvent appears in audit log --");
    BackendSystem b = setup();
    byte[] cardId = { 0x0A, 0x0B, 0x0C, 0x0D };
    byte[] vehicleId = { 0x01, 0x02, 0x03, 0x04 };
    b.logEvent(BackendSystem.EVENT_AUTH_SUCCESS, cardId, vehicleId, null, "test");
    List<BackendSystem.AuditEntry> log = b.getAuditLog();
    check("logEvent adds entry to audit log", log.size() == 1);
    check("logEvent entry has correct eventType", BackendSystem.EVENT_AUTH_SUCCESS.equals(log.get(0).eventType));
  }

  static void testLogEventNullCardId() throws Exception {
    System.out.println("-- logEvent null cardId --");
    BackendSystem b = setup();
    // Should not throw
    b.logEvent(BackendSystem.EVENT_AUTH_FAIL, null, new byte[] { 0x01 }, null, "no card");
    check("logEvent null cardId no throw", b.getAuditLog().size() == 1);
  }

  static void testLogEventNullVehicleId() throws Exception {
    System.out.println("-- logEvent null vehicleId --");
    BackendSystem b = setup();
    // Should not throw
    b.logEvent(BackendSystem.EVENT_PAYMENT, new byte[] { 0x01 }, null, null, "no vehicle");
    check("logEvent null vehicleId no throw", b.getAuditLog().size() == 1);
  }

  static void testLogEventTwiceNoThrow() throws Exception {
    System.out.println("-- logEvent twice --");
    BackendSystem b = setup();
    b.logEvent(BackendSystem.EVENT_AUTH_SUCCESS, new byte[] { 0x01 }, new byte[] { 0x02 }, null, "first");
    b.logEvent(BackendSystem.EVENT_AUTH_SUCCESS, new byte[] { 0x01 }, new byte[] { 0x02 }, null, "second");
    check("logEvent twice no throw, two entries", b.getAuditLog().size() == 2);
  }

  static void testGetAuditLogByCardIdFiltersCorrectly() throws Exception {
    System.out.println("-- getAuditLog(cardId) filters --");
    BackendSystem b = setup();
    byte[] card1 = { 0x01, 0x01, 0x01, 0x01 };
    byte[] card2 = { 0x02, 0x02, 0x02, 0x02 };
    b.logEvent(BackendSystem.EVENT_AUTH_SUCCESS, card1, null, null, "card1-event1");
    b.logEvent(BackendSystem.EVENT_AUTH_SUCCESS, card2, null, null, "card2-event1");
    b.logEvent(BackendSystem.EVENT_AUTH_FAIL, card1, null, null, "card1-event2");
    List<BackendSystem.AuditEntry> card1Log = b.getAuditLog(card1);
    check("getAuditLog(card1) returns 2 entries", card1Log.size() == 2);
    check("getAuditLog(card1) all have card1", card1Log.get(0).cardId != null
        && ByteUtil.toHex(card1Log.get(0).cardId).equals(ByteUtil.toHex(card1))
        && card1Log.get(1).cardId != null
        && ByteUtil.toHex(card1Log.get(1).cardId).equals(ByteUtil.toHex(card1)));
    List<BackendSystem.AuditEntry> card2Log = b.getAuditLog(card2);
    check("getAuditLog(card2) returns 1 entry", card2Log.size() == 1);
  }

  static void testVerifyAssignmentToken() throws Exception {
    System.out.println("-- verifyAssignmentToken --");
    BackendSystem b = setup();
    KeyPair cardKP = CryptoUtil.generateKeyPair();
    byte[] cardPubEncoded = CryptoUtil.encodePublicKey(cardKP.getPublic());
    byte[] reqData = { 0x01, 0x02, 0x03, 0x04 };
    byte[] reqVehicleToken = CryptoUtil.sign(cardKP.getPrivate(), reqData);
    byte[] token = b.signAssignmentToken(reqData, reqVehicleToken, cardPubEncoded);
    boolean valid = b.verifyAssignmentToken(token);
    check("verifyAssignmentToken valid token returns true", valid);

    // Tamper the signature bytes (last 4 bytes) - must return false.
    byte[] tampered = token.clone();
    tampered[tampered.length - 1] ^= (byte) 0xFF;
    tampered[tampered.length - 2] ^= (byte) 0xFF;
    boolean invalid = b.verifyAssignmentToken(tampered);
    check("verifyAssignmentToken tampered token returns false", !invalid);
  }
}
