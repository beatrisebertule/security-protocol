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
import terminal.vehicle.VehicleTerminal;

public class VehicleTerminalSimulator {

  static final byte[] APPLET_AID = {
      (byte) 0x3B, (byte) 0x29, (byte) 0x72, (byte) 0x65,
      (byte) 0x6E, (byte) 0x74, (byte) 0x01
  };

  public static void main(String[] args) throws Exception {
    BackendSystem.reset();
    BackendSystem backend = BackendSystem.getInstance();
    backend.init();

    byte[] vehicleId = { 0x00, 0x00, 0x00, 0x01 };
    backend.registerVehicle(vehicleId, "AB-123-CD");
    byte[] customerId = { 0x00, 0x00, 0x00, 0x01 };
    backend.registerCustomer(customerId, "Alice");

    CardSimulator simulator = new CardSimulator();
    AID aid = new AID(APPLET_AID, (byte) 0, (byte) APPLET_AID.length);
    simulator.installApplet(aid, RentalCardApplet.class);

    CardTerminals terminals = CardTerminalSimulator.terminals("VehicleTerminal");
    CardTerminal terminal = terminals.getTerminal("VehicleTerminal");
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

    PersonalizationTerminal pt = new PersonalizationTerminal(comm, backend);
    pt.personalizeCard(cardId, setupPin);
    pt.issueCard(customerId);

    ReceptionTerminal rt = new ReceptionTerminal(comm, backend);
    Result<byte[]> authR = rt.mutualAuth(setupPin);
    if (!authR.success)
      throw new RuntimeException("mutualAuth failed: " + authR.error.getMessage());
    byte[] pkc = authR.value;

    long now = System.currentTimeMillis() / 1000;
    long end = now + 86400;
    byte[] period = new byte[8];
    period[0] = (byte) ((now >> 24) & 0xFF);
    period[1] = (byte) ((now >> 16) & 0xFF);
    period[2] = (byte) ((now >> 8) & 0xFF);
    period[3] = (byte) (now & 0xFF);
    period[4] = (byte) ((end >> 24) & 0xFF);
    period[5] = (byte) ((end >> 16) & 0xFF);
    period[6] = (byte) ((end >> 8) & 0xFF);
    period[7] = (byte) (end & 0xFF);
    rt.assignVehicle(vehicleId, customerId, pkc, period);

    System.out.println("Card assigned to vehicle AB-123-CD.");
    System.out.println("Vehicle ID: " + ByteUtil.toHex(vehicleId));

    new VehicleTerminal(comm, backend.getMasterPublicKey(),
        backend.getTerminalKeyPair(), backend.getTerminalCertificate(),
        vehicleId).runCLI();
  }
}
