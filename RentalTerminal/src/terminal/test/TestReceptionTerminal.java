package terminal.test;

import java.util.List;

import terminal.backend.BackendSystem;
import terminal.reception.ReceptionTerminalBase;
import terminal.backend.Vehicle;
import terminal.util.CardComm;

/**
 * Test implementation of ReceptionTerminal for unit/integration testing.
 * Provides minimal UI implementations (no-op or auto-select) to allow tests
 * to call protocol methods without requiring user input (Scanner blocking).
 */
public class TestReceptionTerminal extends ReceptionTerminalBase {

  private Vehicle selectedVehicle;
  private byte[] selectedCustomerId;

  public TestReceptionTerminal(CardComm comm, BackendSystem backend) {
    super(comm, backend);
    this.selectedVehicle = null;
    this.selectedCustomerId = null;
  }

  /**
   * Set the vehicle and customer to use for automated test flows.
   */
  public void setTestSelection(Vehicle vehicle, byte[] customerId) {
    this.selectedVehicle = vehicle;
    this.selectedCustomerId = customerId;
  }

  // --- UI Implementation (Abstract Method Implementations) ---

  @Override
  protected void showMainMenu() {
    // No-op: test doesn't display menu
  }

  @Override
  protected void showAvailableVehicles(List<Vehicle> vehicles) {
    // No-op: test doesn't display vehicles
  }

  @Override
  protected Vehicle chooseVehicle(List<Vehicle> vehicles) {
    // Return pre-configured test vehicle, or first available
    if (selectedVehicle != null) {
      return selectedVehicle;
    }
    return vehicles.isEmpty() ? null : vehicles.get(0);
  }

  @Override
  protected byte[] getCustomerId() {
    // Return pre-configured test customer ID
    return selectedCustomerId;
  }

  @Override
  protected void showMessage(String message) {
    // No-op: test doesn't display messages
  }

  @Override
  protected void showError(String message) {
    // No-op: test doesn't display errors
  }
}
