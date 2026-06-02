package terminal.reception;

import java.util.List;
import java.util.Scanner;

import terminal.backend.BackendSystem;
import terminal.backend.Vehicle;
import terminal.logging.Result;
import terminal.util.CardComm;
import terminal.util.CardUtil;
import terminal.util.ByteUtil;

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
    showMessage("\n1) Assign vehicle");
    showMessage("2) Process payment");
    showMessage("3) Get card state");
    showMessage("0) Exit");
  }

  @Override
  protected void showAvailableVehicles(List<Vehicle> vehicles) {
    StringBuilder sb = new StringBuilder("Available vehicles:\n");
    for (int i = 0; i < vehicles.size(); i++) {
      Vehicle v = vehicles.get(i);
      sb.append("  ").append(i).append(") ").append(v.getPlate())
          .append(" [").append(ByteUtil.toHex(v.getId())).append("]\n");
    }
    showMessage(sb.toString());
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

  public void runCLI() {
    System.out.println("=== Reception Terminal ===");

    try {
      Result<Byte> stateRes = CardUtil.getCardState(comm);
      if (!stateRes.success) {
        showError(stateRes.error.getMessage());
        return;
      }
      showMessage("Card state: " + stateToString(stateRes.value));

      System.out.print("Enter PIN: ");
      String pin = scanner.nextLine().trim();

      showMessage("Performing mutual authentication...");
      Result<byte[]> authRes = mutualAuth(pin);
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
            Result<Byte> s = CardUtil.getCardState(comm);
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
