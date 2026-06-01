package terminal.vehicle;

import java.security.PublicKey;
import java.util.Scanner;

import terminal.backend.BackendSystem;
import terminal.util.CardComm;
import terminal.util.ByteUtil;
import terminal.util.CardUtil;
import terminal.logging.Result;

/**
 * Vehicle terminal: offline authentication, mileage tracking, vehicle return.
 * Verifies card cryptographically using MPK. No backend connection during
 * operation.
 */
public class VehicleTerminal extends VehicleTerminalBase {

  /**
   * Constructs a VehicleTerminal bound to a specific vehicle and card channel.
   *
   * @param comm            channel used to send APDU commands to the smart card
   * @param masterPublicKey MPK used to verify assignment tokens (vehicleToken)
   * @param vehicleId       identifier of this vehicle, checked against tokens
   *                        during {@link #openVehicle()}
   */
  public VehicleTerminal(CardComm comm, PublicKey masterPublicKey, byte[] vehicleId) {
    super(comm, masterPublicKey, vehicleId);
  }

  /**
   * Entry point. Sets up a simulated card (personalized, issued, assigned),
   * then runs the vehicle terminal menu.
   */
  public static void main(String[] args) throws Exception {
    BackendSystem.reset();
    BackendSystem backend = BackendSystem.getInstance();
    backend.init();

    byte[] vehicleId = { 0x00, 0x00, 0x00, 0x01 };
    backend.registerVehicle(vehicleId, "AB-123-CD");
    byte[] customerId = { 0x00, 0x00, 0x00, 0x01 };
    backend.registerCustomer(customerId, "Alice");

    com.licel.jcardsim.smartcardio.CardSimulator simulator = new com.licel.jcardsim.smartcardio.CardSimulator();
    byte[] APPLET_AID = {
        (byte) 0x3B, (byte) 0x29, (byte) 0x72, (byte) 0x65, (byte) 0x6E, (byte) 0x74, (byte) 0x01
    };
    javacard.framework.AID aid = new javacard.framework.AID(
        APPLET_AID, (byte) 0, (byte) APPLET_AID.length);
    simulator.installApplet(aid, applet.RentalCardApplet.class);

    javax.smartcardio.CardTerminals terminals = com.licel.jcardsim.smartcardio.CardTerminalSimulator
        .terminals("VehicleTerminal");
    javax.smartcardio.CardTerminal terminal = terminals.getTerminal("VehicleTerminal");
    simulator.assignToTerminal(terminal);

    javax.smartcardio.Card card = terminal.connect("*");
    javax.smartcardio.CardChannel channel = card.getBasicChannel();

    channel.transmit(new javax.smartcardio.CommandAPDU(
        (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, APPLET_AID));

    CardComm comm = new CardComm(channel);

    byte[] cardId = { 0x00, 0x00, 0x00, 0x01 };
    terminal.personalization.PersonalizationTerminal pt = new terminal.personalization.PersonalizationTerminal(comm,
        backend);
    pt.personalizeCard(cardId, "1234");
    pt.issueCard(customerId);

    terminal.reception.ReceptionTerminal rt = new terminal.reception.ReceptionTerminal(comm, backend);
    Result<byte[]> authR = rt.mutualAuth("1234");
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

    new VehicleTerminal(comm, backend.getMasterPublicKey(), vehicleId).runCLI();
  }

  /**
   * Starts the interactive vehicle terminal menu on stdin/stdout.
   * Options: open vehicle (1), update mileage (2), return vehicle (3),
   * get mileage (4), get card state (5), exit (0). Exits automatically
   * after a successful vehicle return.
   */
  @Override
  public void runCLI() {
    Scanner scanner = new Scanner(System.in);
    System.out.println("=== Vehicle Terminal [" + ByteUtil.toHex(vehicleId) + "] ===");
    byte[] cardPkc = null;

    try {
      boolean running = true;
      while (running) {
        System.out.println("\n1) Open vehicle (verify card)");
        System.out.println("2) Update mileage");
        System.out.println("3) Return vehicle");
        System.out.println("4) Get mileage");
        System.out.println("5) Get card state");
        System.out.println("0) Exit");
        System.out.print("Choice: ");
        String choice = scanner.nextLine().trim();

        switch (choice) {
          case "1":
            System.out.println("Verifying card...");
            Result<byte[]> openR = openVehicle();
            if (!openR.success) {
              System.err.println("Open failed: " + openR.error.getMessage());
              break;
            }
            cardPkc = openR.value;
            System.out.println("Vehicle unlocked.");
            break;
          case "2":
            if (cardPkc == null) {
              System.out.println("Open vehicle first.");
              break;
            }
            System.out.print("Mileage (km): ");
            short m = Short.parseShort(scanner.nextLine().trim());
            Result<Void> updR = updateMileage(m);
            if (!updR.success) {
              System.err.println("Update failed: " + updR.error.getMessage());
              break;
            }
            System.out.println("Mileage updated: " + m + " km");
            break;
          case "3":
            if (cardPkc == null) {
              System.out.println("Open vehicle first.");
              break;
            }
            System.out.print("Final mileage (km): ");
            short fm = Short.parseShort(scanner.nextLine().trim());
            Result<byte[]> retR = returnVehicle(fm, cardPkc);
            if (!retR.success) {
              System.err.println("Return failed: " + retR.error.getMessage());
              break;
            }
            System.out.println("Vehicle returned. Card state: ISSUED.");
            cardPkc = null;
            running = false;
            break;
          case "4":
            Result<Short> milR = getMileage();
            if (!milR.success) {
              System.err.println("Mileage read failed: " + milR.error.getMessage());
            } else {
              System.out.println("Mileage: " + milR.value + " km");
            }
            break;
          case "5":
            Result<Byte> stR = CardUtil.getCardState(comm);
            if (!stR.success) {
              System.err.println("State read failed: " + stR.error.getMessage());
            } else {
              System.out.println("State: 0x" + String.format("%02X", stR.value));
            }
            break;
          case "0":
            running = false;
            break;
          default:
            System.out.println("Unknown option.");
        }
      }
    } catch (Exception e) {
      System.err.println("Error: " + e.getMessage());
    }
  }
}
