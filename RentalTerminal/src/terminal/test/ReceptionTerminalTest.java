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
import terminal.common.CardComm;
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

  static boolean hasEvent(List<BackendSystem.AuditEntry> log, String eventType) {
    for (BackendSystem.AuditEntry e : log) {
      if (eventType.equals(e.eventType)) return true;
    }
    return false;
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
