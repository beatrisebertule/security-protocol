package terminal.reception;

import java.util.List;
import java.util.Scanner;

import terminal.backend.BackendSystem;
import terminal.backend.Vehicle;
import terminal.common.CardComm;
import terminal.common.CardUtil;
import terminal.common.ByteUtil;
import terminal.common.ProtocolConstants;

/**
 * CLI reception terminal: implements UI-specific behavior (menu, input,
 * output).
 * Delegates protocol logic to ReceptionTerminalBase.
 */
public class ReceptionTerminal extends ReceptionTerminalBase {

  private final Scanner scanner = new Scanner(System.in);

  public ReceptionTerminal(CardComm comm, BackendSystem backend) {
    super(comm, backend);
  }

  // UI Implementation (Abstract Method Implementations)

  @Override
  protected void showMainMenu() {
    System.out.println("\n1) Assign vehicle");
    System.out.println("2) Process payment");
    System.out.println("3) Get card state");
    System.out.println("0) Exit");
  }

  @Override
  protected void showAvailableVehicles(List<Vehicle> vehicles) {
    System.out.println("Available vehicles:");
    for (int i = 0; i < vehicles.size(); i++) {
      Vehicle v = vehicles.get(i);
      System.out.println("  " + i + ") " + v.getPlate()
          + " [" + ByteUtil.toHex(v.getId()) + "]");
    }
  }

  @Override
  protected Vehicle chooseVehicle(List<Vehicle> vehicles) {
    System.out.print("Select vehicle (index, or -1 to cancel): ");
    try {
      int idx = Integer.parseInt(scanner.nextLine().trim());
      if (idx == -1) {
        return null;
      }
      if (idx < 0 || idx >= vehicles.size()) {
        System.out.println("Invalid selection.");
        return null;
      }
      return vehicles.get(idx);
    } catch (NumberFormatException e) {
      System.out.println("Invalid input.");
      return null;
    }
  }

  @Override
  protected byte[] getCustomerId() {
    System.out.print("Customer ID (hex, 4 bytes, or -1 to cancel): ");
    String input = scanner.nextLine().trim();
    if (input.equals("-1")) {
      return null;
    }
    try {
      return ByteUtil.fromHex(input);
    } catch (Exception e) {
      System.out.println("Invalid hex input.");
      return null;
    }
  }

  @Override
  protected void showMessage(String message) {
    System.out.println(message);
  }

  @Override
  protected void showError(String message) {
    System.err.println("Error: " + message);
  }

  /**
   * Interactive CLI entry point. Sets up a simulated card (personalized +
   * issued),
   * then runs the reception terminal menu.
   */
  public static void main(String[] args) throws Exception {
    // --- Backend ---
    BackendSystem.reset();
    BackendSystem backend = BackendSystem.getInstance();
    backend.init();
    byte[] vehicleId1 = { 0x00, 0x00, 0x00, 0x01 };
    byte[] vehicleId2 = { 0x00, 0x00, 0x00, 0x02 };
    backend.registerVehicle(vehicleId1, "AB-123-CD");
    backend.registerVehicle(vehicleId2, "XY-456-EF");
    byte[] customerId = { 0x00, 0x00, 0x00, 0x01 };
    backend.registerCustomer(customerId, "Alice");

    // JCardSim
    com.licel.jcardsim.smartcardio.CardSimulator simulator = new com.licel.jcardsim.smartcardio.CardSimulator();
    byte[] APPLET_AID = {
        (byte) 0x3B, (byte) 0x29, (byte) 0x72, (byte) 0x65, (byte) 0x6E, (byte) 0x74, (byte) 0x01
    };
    javacard.framework.AID aid = new javacard.framework.AID(
        APPLET_AID, (byte) 0, (byte) APPLET_AID.length);
    simulator.installApplet(aid, applet.RentalCardApplet.class);

    javax.smartcardio.CardTerminals terminals = com.licel.jcardsim.smartcardio.CardTerminalSimulator
        .terminals("ReceptionTerminal");
    javax.smartcardio.CardTerminal terminal = terminals.getTerminal("ReceptionTerminal");
    simulator.assignToTerminal(terminal);

    javax.smartcardio.Card card = terminal.connect("*");
    javax.smartcardio.CardChannel channel = card.getBasicChannel();

    // Select applet
    channel.transmit(new javax.smartcardio.CommandAPDU(
        (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, APPLET_AID));

    CardComm comm = new CardComm(channel);
    byte[] cardId = { 0x00, 0x00, 0x00, 0x01 };
    terminal.common.Result<Void> setupRes = personalizeAndIssue(comm, backend, cardId, customerId);
    if (!setupRes.success) {
      System.err.println("Error: " + setupRes.error.getMessage());
      return;
    }

    System.out.println("Card personalized and issued (PIN: 1234).");
    System.out.println("Customer: Alice [" + ByteUtil.toHex(customerId) + "]");

    // Run CLI
    new ReceptionTerminal(comm, backend).runCLI();
  }

  private static terminal.common.Result<Void> personalizeAndIssue(CardComm comm, BackendSystem backend, byte[] cardId, byte[] customerId) {
    terminal.personalization.PersonalizationTerminal pt = new terminal.personalization.PersonalizationTerminal(comm, backend);
    terminal.common.Result<Void> res = pt.personalizeCard(cardId, "1234");
    if (!res.success) return res;
    return pt.issueCard(customerId);
  }

  public void runCLI() {
    System.out.println("=== Reception Terminal ===");

    try {
      terminal.common.Result<Byte> stateRes = CardUtil.getCardState(comm);
      if (!stateRes.success) {
        showError(stateRes.error.getMessage());
        return;
      }
      showMessage("Card state: " + stateToString(stateRes.value));

      System.out.print("Enter PIN: ");
      String pin = scanner.nextLine().trim();

      showMessage("Performing mutual authentication...");
      terminal.common.Result<byte[]> authRes = mutualAuth(pin);
      if (!authRes.success) {
        showError("Authentication failed: " + authRes.error.getMessage());
        return;
      }
      byte[] cardPkc = authRes.value;
      showMessage("Authentication successful.");

      boolean running = true;
      while (running) {
        showMainMenu();
        System.out.print("Choice: ");
        String choice = scanner.nextLine().trim();

        switch (choice) {
          case "1":
            vehicleSelection(cardPkc);
            break;
          case "2":
            paymentFlow();
            break;
          case "3":
            terminal.common.Result<Byte> s = CardUtil.getCardState(comm);
            if (!s.success) {
              showError(s.error.getMessage());
            } else {
              showMessage("State: " + stateToString(s.value));
            }
            break;
          case "0":
            running = false;
            break;
          default:
            showMessage("Unknown option.");
        }
      }
    } catch (Exception e) {
      showError(e.getMessage());
    }
  }
}
