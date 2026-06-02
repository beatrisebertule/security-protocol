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
    // FIXME: Lets change all the system.out.prints into adedicated function for printing. that we can modify. Lets add thsi into the utils folder. Write a find and replace command that changes them all for the new print()
    System.out.println("\n1) Assign vehicle");
    System.out.println("2) Process payment");
    System.out.println("3) Get card state");
    System.out.println("0) Exit");
  }

  @Override
  //FIXME: use stringbuilder. it is much cleaner like this. Actually , run a subagent haiky for string builder everywhere possible
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
  // FIXME: ALl the try and catch should be Results<>. Runa a haikyu agent ahat checks this in all files
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
