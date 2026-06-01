package terminal.test;

import javacard.framework.AID;
import javax.smartcardio.*;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import applet.RentalCardApplet;
import terminal.backend.BackendSystem;
import terminal.util.CardComm;

/** JUnit4 wrapper around QuickTest for PIT mutation testing. */
public class QuickTestJUnit {

  @Test
  public void fullLifecycle() throws Exception {
    QuickTest.passed = 0;
    QuickTest.failed = 0;

    BackendSystem.reset();
    BackendSystem backend = BackendSystem.getInstance();
    backend.init();
    backend.registerVehicle(QuickTest.VEHICLE_ID, QuickTest.VEHICLE_PLATE);
    backend.registerCustomer(QuickTest.CUSTOMER_ID, "Test Customer");

    CardTerminals terminals = CardTerminalSimulator.terminals("QT-JUNIT");
    CardTerminal terminal = terminals.getTerminal("QT-JUNIT");
    CardSimulator simulator = new CardSimulator();
    AID aid = new AID(QuickTest.APPLET_AID, (byte) 0, (byte) QuickTest.APPLET_AID.length);
    simulator.installApplet(aid, RentalCardApplet.class);
    simulator.assignToTerminal(terminal);
    Card card = terminal.connect("*");
    CardChannel channel = card.getBasicChannel();
    channel.transmit(new CommandAPDU(
        (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, QuickTest.APPLET_AID));
    CardComm comm = new CardComm(channel);

    QuickTest.testPersonalization(comm, backend);
    QuickTest.testMutualAuthAndAssignment(comm, backend);
    QuickTest.testVehicleAccess(comm, backend);
    QuickTest.testPaymentAndReassign(comm, backend, channel, card, simulator, aid, terminal);
    assertEquals(0, QuickTest.failed);
  }
}
