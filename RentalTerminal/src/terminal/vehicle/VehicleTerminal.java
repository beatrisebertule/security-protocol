package terminal.vehicle;

import java.security.PublicKey;
import java.util.Scanner;

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
   *                        during {@link #open()}
   */
  public VehicleTerminal(CardComm comm, PublicKey masterPublicKey,
      java.security.KeyPair terminalKeyPair, byte[] terminalCertificate,
      byte[] vehicleId) {
    super(comm, masterPublicKey, terminalKeyPair, terminalCertificate, vehicleId);
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
    showMessage("=== Vehicle Terminal [" + ByteUtil.toHex(vehicleId) + "] ===");
    byte[] cardPkc = null;

    try {
      boolean running = true;
      while (running) {
        showMessage("\n1) Open vehicle (verify card)");
        showMessage("2) Update mileage");
        showMessage("3) Return vehicle");
        showMessage("4) Get mileage");
        showMessage("5) Get card state");
        showMessage("0) Exit");
        System.out.print("Choice: ");
        String choice = scanner.nextLine().trim();

        switch (choice) {
          case "1":
            showMessage("Verifying card...");
            Result<byte[]> openR = open();
            if (!openR.success) {
              showError("Open failed: " + openR.error.getMessage());
              break;
            }
            cardPkc = openR.value;
            showMessage("Vehicle unlocked.");
            break;
          case "2":
            if (cardPkc == null) {
              showMessage("Open vehicle first.");
              break;
            }
            System.out.print("Mileage (km): ");
            short m = Short.parseShort(scanner.nextLine().trim());
            Result<Void> updR = updateMileage(m);
            if (!updR.success) {
              showError("Update failed: " + updR.error.getMessage());
              break;
            }
            showMessage("Mileage updated: " + m + " km");
            break;
          case "3":
            if (cardPkc == null) {
              showMessage("Open vehicle first.");
              break;
            }
            System.out.print("Final mileage (km): ");
            short fm = Short.parseShort(scanner.nextLine().trim());
            Result<byte[]> retR = returnVehicle(fm, cardPkc);
            if (!retR.success) {
              showError("Return failed: " + retR.error.getMessage());
              break;
            }
            showMessage("Vehicle returned. Card state: ISSUED.");
            cardPkc = null;
            running = false;
            break;
          case "4":
            Result<Short> milR = getMileage();
            if (!milR.success) {
              showError("Mileage read failed: " + milR.error.getMessage());
            } else {
              showMessage("Mileage: " + milR.value + " km");
            }
            break;
          case "5":
            Result<Byte> stR = CardUtil.getCardState(comm);
            if (!stR.success) {
              showError("State read failed: " + stR.error.getMessage());
            } else {
              showMessage("State: 0x" + String.format("%02X", stR.value));
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
