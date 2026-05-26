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
import terminal.common.CardComm;
import terminal.common.CryptoUtil;
import terminal.common.ProtocolConstants;
import terminal.common.Result;
import terminal.personalization.PersonalizationTerminal;
import terminal.reception.TestReceptionTerminal;
import terminal.vehicle.TestVehicleTerminal;

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
    check("VEHICLE_OPENED is in local log", hasEvent(vt.getLog(), BackendSystem.EVENT_VEHICLE_OPENED));
    check("VEHICLE_OPENED is not in backend log yet", !hasEvent(backend.getAuditLog(), BackendSystem.EVENT_VEHICLE_OPENED));

    Result<Void> updateResult = vt.updateMileage((short) 50);
    check("updateMileage succeeds", updateResult.success);
    check("MILEAGE_UPDATE is in local log", hasEvent(vt.getLog(), BackendSystem.EVENT_MILEAGE_UPDATE));
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

    vt.flushLogsToBackend(backend);
    check("local log is empty after flush", vt.getLog().isEmpty());
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
    check("wrong-vehicle failure is logged locally", hasEvent(vtWrong.getLog(), BackendSystem.EVENT_VEHICLE_OPEN_FAIL));

    vtWrong.flushLogsToBackend(backend);
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
