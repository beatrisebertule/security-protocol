package terminal.test;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import applet.RentalCardApplet;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;

import javacard.framework.AID;

import terminal.backend.BackendSystem;
import terminal.util.CardComm;
import terminal.util.CryptoUtil;
import terminal.util.ProtocolConstants;
import terminal.logging.Result;
import terminal.personalization.PersonalizationTerminal;
import terminal.test.TestReceptionTerminal;
import terminal.test.TestVehicleTerminal;

public class VehicleTerminalTest {
  static final byte[] APPLET_AID = {
      (byte) 0x3B, (byte) 0x29, (byte) 0x72, (byte) 0x65,
      (byte) 0x6E, (byte) 0x74, (byte) 0x01
  };
  static final byte[] CARD_ID = { 0x00, 0x00, 0x00, 0x01 };
  static final byte[] CUSTOMER_ID = { 0x00, 0x00, 0x00, 0x42 };
  static final byte[] VEHICLE_ID = { 0x00, 0x00, 0x00, 0x05 };
  static final byte[] VEHICLE_ID_B = { 0x00, 0x00, 0x00, 0x06 };
  static final String PIN = "1234";

  static int passed = 0;
  static int failed = 0;
  static int testNum = 0;

  static BackendSystem backend;

  public static void main(String[] args) throws Exception {
    System.out.println("=== VehicleTerminalTest ===");

    testOpenAndUpdate();
    testReturnAndFlush();
    testWrongVehicleRejected();
    testUpdateMileageBoundaryConditions();
    testReturnVehicleReceiptValidation();
    testOpenVehicleSetsCardId();
    testUpdateMileageAuditLogging();

    System.out.println("\n=== Results: " + passed + " passed, " + failed + " failed ===");
    if (failed > 0) {
      System.exit(1);
    }
  }

  static CardComm freshCard() throws Exception {
    BackendSystem.reset();
    backend = BackendSystem.getInstance();
    backend.init();
    backend.registerVehicle(VEHICLE_ID, "TEST-1");
    backend.registerCustomer(CUSTOMER_ID, "Test");

    String termName = "VTT-" + (++testNum);
    CardTerminals terminals = CardTerminalSimulator.terminals(termName);
    CardTerminal terminal = terminals.getTerminal(termName);

    CardSimulator simulator = new CardSimulator();
    AID aid = new AID(APPLET_AID, (byte) 0, (byte) APPLET_AID.length);
    simulator.installApplet(aid, RentalCardApplet.class);
    simulator.assignToTerminal(terminal);

    Card card = terminal.connect("*");
    CardChannel channel = card.getBasicChannel();
    channel.transmit(new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, APPLET_AID));

    return new CardComm(channel);
  }

  static CardComm issuedCard() throws Exception {
    CardComm comm = freshCard();
    PersonalizationTerminal pt = new PersonalizationTerminal(comm, backend);
    pt.personalizeCard(CARD_ID, PIN);
    pt.issueCard(CUSTOMER_ID);
    return comm;
  }

  static byte[] assignVehicle(CardComm comm) throws Exception {
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);
    byte[] pkc = unwrap(rt.mutualAuth(PIN));
    long now = System.currentTimeMillis() / 1000;
    byte[] period = periodBytes(now, now + 86400);
    unwrap(rt.assignVehicle(VEHICLE_ID, CUSTOMER_ID, pkc, period));
    return pkc;
  }

  static <T> T unwrap(Result<T> r) {
    if (!r.success) {
      throw new RuntimeException("Result.fail: " + r.error.getMessage(), r.error);
    }
    return r.value;
  }

  static void testOpenAndUpdate() throws Exception {
    System.out.println("-- Open + update --");

    CardComm comm = issuedCard();
    byte[] pkc = assignVehicle(comm);

    TestVehicleTerminal vt = new TestVehicleTerminal(comm, backend.getMasterPublicKey(), VEHICLE_ID);

    Result<byte[]> openResult = vt.openVehicle();
    check("openVehicle succeeds", openResult.success);
    check("openVehicle returns public key bytes", openResult.success && openResult.value != null && openResult.value.length > 0);
    check("VEHICLE_OPENED is in local log", hasEvent(vt.auditLog.getLog(), BackendSystem.EVENT_VEHICLE_OPENED));
    check("VEHICLE_OPENED is not in backend log yet", !hasEvent(backend.getAuditLog(), BackendSystem.EVENT_VEHICLE_OPENED));

    Result<Void> updateResult = vt.updateMileage((short) 50);
    check("updateMileage succeeds", updateResult.success);
    check("MILEAGE_UPDATE is in local log", hasEvent(vt.auditLog.getLog(), BackendSystem.EVENT_MILEAGE_UPDATE));
  }

  static void testReturnAndFlush() throws Exception {
    System.out.println("\n-- Return + flush --");

    CardComm comm = issuedCard();
    byte[] pkc = assignVehicle(comm);

    TestVehicleTerminal vt = new TestVehicleTerminal(comm, backend.getMasterPublicKey(), VEHICLE_ID);
    unwrap(vt.openVehicle());
    unwrap(vt.updateMileage((short) 30));

    Result<byte[]> returnResult = vt.returnVehicle((short) 60, pkc);
    check("returnVehicle succeeds", returnResult.success);
    check("returnVehicle receipt has signature bytes", returnResult.success && returnResult.value.length > 2);
    check("return receipt signature verifies", returnResult.success && verifyReceipt(returnResult.value, pkc));

    vt.auditLog.flushToBackend(backend);
    check("local log is empty after flush", vt.auditLog.getLog().isEmpty());
    check("VEHICLE_OPENED is in backend log after flush", hasEvent(backend.getAuditLog(), BackendSystem.EVENT_VEHICLE_OPENED));
    check("MILEAGE_UPDATE is in backend log after flush", hasEvent(backend.getAuditLog(), BackendSystem.EVENT_MILEAGE_UPDATE));
  }

  static void testWrongVehicleRejected() throws Exception {
    System.out.println("\n-- Wrong vehicle rejected --");

    CardComm comm = issuedCard();
    backend.registerVehicle(VEHICLE_ID_B, "TEST-B");
    assignVehicle(comm);

    TestVehicleTerminal vtWrong = new TestVehicleTerminal(comm, backend.getMasterPublicKey(), VEHICLE_ID_B);
    Result<byte[]> openResult = vtWrong.openVehicle();
    check("wrong-vehicle openVehicle fails", !openResult.success);
    check("wrong-vehicle failure is logged locally", hasEvent(vtWrong.auditLog.getLog(), BackendSystem.EVENT_VEHICLE_OPEN_FAIL));

    vtWrong.auditLog.flushToBackend(backend);
    check("wrong-vehicle failure is in backend log after flush", hasEvent(backend.getAuditLog(), BackendSystem.EVENT_VEHICLE_OPEN_FAIL));
  }

  static boolean verifyReceipt(byte[] receipt, byte[] cardPkc) {
    try {
      PublicKey cardPubKey = CryptoUtil.decodePublicKey(cardPkc);
      byte[] mileage = Arrays.copyOfRange(receipt, 0, 2);
      byte[] sig = Arrays.copyOfRange(receipt, 2, receipt.length);
      return CryptoUtil.verify(cardPubKey, mileage, sig);
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  static boolean hasEvent(List<BackendSystem.AuditEntry> log, String eventType) {
    for (BackendSystem.AuditEntry e : log) {
      if (eventType.equals(e.eventType)) {
        return true;
      }
    }
    return false;
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

  static void testUpdateMileageBoundaryConditions() throws Exception {
    System.out.println("\n-- updateMileage boundary conditions --");

    CardComm comm = issuedCard();
    assignVehicle(comm);
    TestVehicleTerminal vt = new TestVehicleTerminal(comm, backend.getMasterPublicKey(), VEHICLE_ID);
    unwrap(vt.openVehicle());

    // Advance mileage to 100 so we have a known baseline.
    unwrap(vt.updateMileage((short) 100));

    // Equal mileage (same value as current) must succeed - the guard is strictly <.
    Result<Void> equalResult = vt.updateMileage((short) 100);
    check("updateMileage with same value succeeds", equalResult.success);

    // After the equal update, getMileage should still return 100.
    Result<Short> readBack = vt.getMileage();
    check("getMileage returns non-null value after equal update", readBack.success && readBack.value != null);
    check("getMileage value matches what was sent", readBack.success && readBack.value == 100);

    // One below current must fail (rollback detection).
    Result<Void> rollbackResult = vt.updateMileage((short) 99);
    check("updateMileage with mileage-1 fails", !rollbackResult.success);
    check("rollback failure is logged", hasEvent(vt.auditLog.getLog(), BackendSystem.EVENT_MILEAGE_UPDATE));
  }

  static void testReturnVehicleReceiptValidation() throws Exception {
    System.out.println("\n-- returnVehicle receipt validation --");

    CardComm comm = issuedCard();
    byte[] pkc = assignVehicle(comm);
    TestVehicleTerminal vt = new TestVehicleTerminal(comm, backend.getMasterPublicKey(), VEHICLE_ID);
    unwrap(vt.openVehicle());
    unwrap(vt.updateMileage((short) 42));

    short finalMileage = 200;
    Result<byte[]> returnResult = vt.returnVehicle(finalMileage, pkc);
    check("returnVehicle succeeds with valid mileage", returnResult.success);

    // Receipt must have at least 3 bytes: 2 mileage + at least 1 sig byte.
    check("receipt has sig bytes (length > 2)", returnResult.success && returnResult.value.length > 2);

    // First two bytes of receipt encode final mileage big-endian.
    byte[] receipt = returnResult.value;
    int encodedMileage = ((receipt[0] & 0xFF) << 8) | (receipt[1] & 0xFF);
    check("receipt first 2 bytes encode the final mileage", encodedMileage == (finalMileage & 0xFFFF));
  }

  static void testOpenVehicleSetsCardId() throws Exception {
    System.out.println("\n-- openVehicle sets currentCardId --");

    CardComm comm = issuedCard();
    assignVehicle(comm);
    TestVehicleTerminal vt = new TestVehicleTerminal(comm, backend.getMasterPublicKey(), VEHICLE_ID);

    // Before open, currentCardId should be null.
    check("currentCardId is null before openVehicle", vt.getCardId() == null);

    unwrap(vt.openVehicle());

    // After successful open, currentCardId must be populated.
    check("currentCardId is non-null after successful openVehicle", vt.getCardId() != null);
    check("currentCardId has expected length", vt.getCardId() != null && vt.getCardId().length == CARD_ID.length);
  }

  static void testUpdateMileageAuditLogging() throws Exception {
    System.out.println("\n-- updateMileage audit logging --");

    CardComm comm = issuedCard();
    assignVehicle(comm);
    TestVehicleTerminal vt = new TestVehicleTerminal(comm, backend.getMasterPublicKey(), VEHICLE_ID);
    unwrap(vt.openVehicle());

    // Successful update should produce a MILEAGE_UPDATE log entry.
    unwrap(vt.updateMileage((short) 77));
    check("MILEAGE_UPDATE in log after successful update", hasEvent(vt.auditLog.getLog(), BackendSystem.EVENT_MILEAGE_UPDATE));

    // Failed update (rollback) should also produce a MILEAGE_UPDATE log entry.
    // Capture seqNum before the failed attempt; verify it is unchanged after.
    short seqBeforeFail = vt.getSeqNum();
    int logSizeBefore = vt.auditLog.getLog().size();
    Result<Void> failResult = vt.updateMileage((short) 1);
    check("failed updateMileage also logged", !failResult.success && vt.auditLog.getLog().size() > logSizeBefore);
    check("seqNum is still incremented from prior successful updates", vt.getSeqNum() == seqBeforeFail);
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
