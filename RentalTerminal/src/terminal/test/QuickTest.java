package terminal.test;

import javacard.framework.AID;
import javax.smartcardio.*;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;

import applet.RentalCardApplet;

import terminal.backend.BackendSystem;
import terminal.common.CardComm;
import terminal.common.ProtocolConstants;
import terminal.common.ByteUtil;
import terminal.personalization.PersonalizationTerminal;
import terminal.reception.ReceptionTerminal;
import terminal.vehicle.VehicleTerminal;

/**
 * Full lifecycle integration test.
 * blank -> personalized -> issued -> assigned -> mileage -> return -> pay
 * No user interaction required.
 */
public class QuickTest {

  static final byte[] APPLET_AID = {
      (byte) 0x3B, (byte) 0x29, (byte) 0x72, (byte) 0x65,
      (byte) 0x6E, (byte) 0x74, (byte) 0x01
  };
  static final byte[] CARD_ID = { 0x00, 0x00, 0x00, 0x01 };
  static final byte[] CUSTOMER_ID = { 0x00, 0x00, 0x00, 0x42 };
  static final byte[] VEHICLE_ID = { 0x00, 0x00, 0x00, 0x05 };
  static final String PIN = "1234";
  static final String VEHICLE_PLATE = "AB-123-CD";

  static int passed = 0;
  static int failed = 0;

  public static void main(String[] args) throws Exception {
    System.out.println("=== QuickTest: Full Lifecycle Integration ===\n");

    // --- Setup backend ---
    BackendSystem.reset();
    BackendSystem backend = BackendSystem.getInstance();
    backend.init();
    backend.registerVehicle(VEHICLE_ID, VEHICLE_PLATE);
    backend.registerCustomer(CUSTOMER_ID, "Test Customer");

    // --- Setup JCardSim ---
    CardTerminals terminals = CardTerminalSimulator.terminals("RentalTerminal");
    CardTerminal terminal = terminals.getTerminal("RentalTerminal");

    CardSimulator simulator = new CardSimulator();
    AID aid = new AID(APPLET_AID, (byte) 0, (byte) APPLET_AID.length);
    simulator.installApplet(aid, RentalCardApplet.class);
    simulator.assignToTerminal(terminal);

    Card card = terminal.connect("*");
    CardChannel channel = card.getBasicChannel();

    // Select applet
    CommandAPDU select = new CommandAPDU(
        (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, APPLET_AID);
    ResponseAPDU selResp = channel.transmit(select);
    if (selResp.getSW() != 0x9000) {
      throw new RuntimeException("Applet select failed: " + String.format("%04X", selResp.getSW()));
    }

    CardComm comm = new CardComm(channel);

    // --- Test phases ---
    testPersonalization(comm, backend);
    testMutualAuthAndAssignment(comm, backend);
    testVehicleAccess(comm, backend);
    testPaymentAndReassign(comm, backend, channel, card, simulator, aid, terminal);

    // Summary
    System.out.println("\n=== Results: " + passed + " passed, " + failed + " failed ===");
    if (failed > 0)
      System.exit(1);
  }

  // -------------------------------------------------------------------------

  static void testPersonalization(CardComm comm, BackendSystem backend) throws Exception {
    System.out.println("-- Personalization --");

    PersonalizationTerminal pt = new PersonalizationTerminal(comm, backend);

    check("Initial state BLANK", pt.getCardState() == ProtocolConstants.STATE_BLANK);

    pt.personalizeCard(CARD_ID, PIN);
    check("State PERSONALIZED after personalizeCard", pt.getCardState() == ProtocolConstants.STATE_PERSONALIZED);

    pt.issueCard(CUSTOMER_ID);
    check("State ISSUED after issueCard", pt.getCardState() == ProtocolConstants.STATE_ISSUED);
  }

  static byte[] cardPkc;

  static void testMutualAuthAndAssignment(CardComm comm, BackendSystem backend) throws Exception {
    System.out.println("\n-- Mutual Auth + Vehicle Assignment --");

    ReceptionTerminal rt = new ReceptionTerminal(comm, backend);

    cardPkc = rt.mutualAuth(PIN);
    check("Mutual auth succeeded, got pkc", cardPkc != null && cardPkc.length == 65);

    // Rental period: now to now+24h
    long now = System.currentTimeMillis() / 1000;
    long end = now + 86400;
    byte[] period = longPairToBytes(now, end);

    rt.assignVehicle(VEHICLE_ID, CUSTOMER_ID, cardPkc, period);

    byte state = comm.sendCommandChecked(ProtocolConstants.INS_GET_STATE)[0];
    check("State ASSIGNED after assignVehicle", state == ProtocolConstants.STATE_ASSIGNED);

    check("Vehicle marked unavailable in backend",
        backend.getAvailableVehicles().isEmpty());
  }

  static void testVehicleAccess(CardComm comm, BackendSystem backend) throws Exception {
    System.out.println("\n-- Vehicle Access (open, mileage, return) --");

    VehicleTerminal vt = new VehicleTerminal(comm, backend.getMasterPublicKey(), VEHICLE_ID);

    byte[] pkc = vt.openVehicle();
    check("openVehicle succeeded, got pkc", pkc != null && pkc.length == 65);

    vt.updateMileage((short) 100);
    check("Mileage = 100 after update", vt.getMileage() == 100);

    vt.updateMileage((short) 200);
    check("Mileage = 200 after second update", vt.getMileage() == 200);

    vt.returnVehicle((short) 250, pkc);
    check("State ISSUED after return", vt.getCardState() == ProtocolConstants.STATE_ISSUED);

    // Mileage should be 250 (stored on card after return)
    byte[] mileageData = comm.sendCommandChecked(ProtocolConstants.INS_GET_MILEAGE);
    short mileage = ByteUtil.bytesToShort(mileageData, 0);
    check("Mileage = 250 after return", mileage == 250);
  }

  static void testPaymentAndReassign(CardComm comm, BackendSystem backend,
      CardChannel channel, Card card,
      CardSimulator simulator, AID aid,
      CardTerminal terminal) throws Exception {
    System.out.println("\n-- Payment + Re-assignment --");

    ReceptionTerminal rt = new ReceptionTerminal(comm, backend);

    // Must re-auth for payment (session was cleared during vehicle
    // return/reconnect)
    // Re-select applet to get fresh session
    CommandAPDU select = new CommandAPDU(
        (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, APPLET_AID);
    channel.transmit(select);

    cardPkc = rt.mutualAuth(PIN);
    check("Re-auth for payment succeeded", cardPkc != null);

    int mileagePaid = rt.processMileagePayment(CUSTOMER_ID);
    check("Mileage paid = 250", mileagePaid == 250);

    byte[] mileageData = comm.sendCommandChecked(ProtocolConstants.INS_GET_MILEAGE);
    short mileage = ByteUtil.bytesToShort(mileageData, 0);
    check("Mileage = 0 after payment", mileage == 0);

    // Release vehicle in backend
    backend.releaseVehicle(VEHICLE_ID);
    check("Vehicle available again", !backend.getAvailableVehicles().isEmpty());

    // Re-assign vehicle
    long now = System.currentTimeMillis() / 1000;
    byte[] period = longPairToBytes(now, now + 86400);
    rt.assignVehicle(VEHICLE_ID, CUSTOMER_ID, cardPkc, period);

    byte state = comm.sendCommandChecked(ProtocolConstants.INS_GET_STATE)[0];
    check("Re-assignment to ASSIGNED succeeded", state == ProtocolConstants.STATE_ASSIGNED);
  }

  // -------------------------------------------------------------------------

  static byte[] longPairToBytes(long a, long b) {
    byte[] buf = new byte[8];
    buf[0] = (byte) ((a >> 24) & 0xFF);
    buf[1] = (byte) ((a >> 16) & 0xFF);
    buf[2] = (byte) ((a >> 8) & 0xFF);
    buf[3] = (byte) (a & 0xFF);
    buf[4] = (byte) ((b >> 24) & 0xFF);
    buf[5] = (byte) ((b >> 16) & 0xFF);
    buf[6] = (byte) ((b >> 8) & 0xFF);
    buf[7] = (byte) (b & 0xFF);
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
