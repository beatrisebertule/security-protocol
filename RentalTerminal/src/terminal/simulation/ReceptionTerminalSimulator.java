package terminal.simulation;

import java.util.Scanner;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import javacard.framework.AID;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;

import applet.RentalCardApplet;
import terminal.backend.BackendSystem;
import terminal.logging.Result;
import terminal.personalization.PersonalizationTerminal;
import terminal.reception.ReceptionTerminal;
import terminal.util.ByteUtil;
import terminal.util.CardComm;

public class ReceptionTerminalSimulator {

  static final byte[] APPLET_AID = {
      (byte) 0x3B, (byte) 0x29, (byte) 0x72, (byte) 0x65,
      (byte) 0x6E, (byte) 0x74, (byte) 0x01
  };

  public static void main(String[] args) throws Exception {
    BackendSystem.reset();
    BackendSystem backend = BackendSystem.getInstance();
    backend.init();

    byte[] vehicleId1 = { 0x00, 0x00, 0x00, 0x01 };
    byte[] vehicleId2 = { 0x00, 0x00, 0x00, 0x02 };
    backend.registerVehicle(vehicleId1, "AB-123-CD");
    backend.registerVehicle(vehicleId2, "XY-456-EF");
    byte[] customerId = { 0x00, 0x00, 0x00, 0x01 };
    backend.registerCustomer(customerId, "Alice");

    CardSimulator simulator = new CardSimulator();
    AID aid = new AID(APPLET_AID, (byte) 0, (byte) APPLET_AID.length);
    simulator.installApplet(aid, RentalCardApplet.class);

    CardTerminals terminals = CardTerminalSimulator.terminals("ReceptionTerminal");
    CardTerminal terminal = terminals.getTerminal("ReceptionTerminal");
    simulator.assignToTerminal(terminal);

    Card card = terminal.connect("*");
    CardChannel channel = card.getBasicChannel();
    channel.transmit(new CommandAPDU(
        (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, APPLET_AID));

    CardComm comm = new CardComm(channel);
    byte[] cardId = { 0x00, 0x00, 0x00, 0x01 };

    Scanner setupScanner = new Scanner(System.in);
    System.out.print("Set card PIN: ");
    String setupPin = setupScanner.nextLine().trim();

    Result<Void> setupRes = personalizeAndIssue(comm, backend, cardId, customerId, setupPin);
    if (!setupRes.success) {
      System.err.println("Error: " + setupRes.error.getMessage());
      return;
    }

    System.out.println("Card personalized and issued.");
    System.out.println("Customer: Alice [" + ByteUtil.toHex(customerId) + "]");

    new ReceptionTerminal(comm, backend).runCLI();
  }

  private static Result<Void> personalizeAndIssue(CardComm comm, BackendSystem backend,
      byte[] cardId, byte[] customerId, String pin) {
    PersonalizationTerminal pt = new PersonalizationTerminal(comm, backend);
    Result<Void> res = pt.personalizeCard(cardId, pin);
    if (!res.success) return res;
    return pt.issueCard(customerId);
  }
}
