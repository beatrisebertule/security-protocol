package terminal.test;

import java.security.PublicKey;

import terminal.util.CardComm;
import terminal.vehicle.VehicleTerminalBase;

/**
 * Test implementation of VehicleTerminalBase for unit/integration testing.
 *
 * This class provides a non-interactive shell around the vehicle terminal
 * protocol logic so tests can invoke the vehicle operations directly without
 * blocking on the interactive CLI.
 */
public class TestVehicleTerminal extends VehicleTerminalBase {

  public TestVehicleTerminal(CardComm comm, PublicKey masterPublicKey,
      java.security.KeyPair terminalKeyPair, byte[] terminalCertificate,
      byte[] vehicleId) {
    super(comm, masterPublicKey, terminalKeyPair, terminalCertificate, vehicleId);
  }

  @Override
  public void runCLI() {
    // No-op: tests invoke the protocol methods directly.
  }

  public byte[] getCardId() {
    return currentCardId;
  }

  public short getSeqNum() {
    return currentSeqNum;
  }
}
