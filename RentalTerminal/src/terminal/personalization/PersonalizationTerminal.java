package terminal.personalization;

import terminal.backend.BackendSystem;
import terminal.logging.VerboseLogger;
import terminal.util.CardComm;

/**
 * Implementation of {@link PersonalizationTerminalBase} with user-facing
 * display.
 */
public class PersonalizationTerminal extends PersonalizationTerminalBase {

  /**
   * Constructor for PersonalizationTerminal.
   */
  public PersonalizationTerminal(CardComm comm, BackendSystem backend) {
    super(comm, backend);
  }

  /**
   *
   * In this implementation, simply prints the message to standard output.
   * In a real terminal, this would update the display for the user.
   */

  @Override
  protected void showMessage(String message) {
    VerboseLogger.get().step(message);
  }

  @Override
  protected void showError(String message) {
    VerboseLogger.get().step("ERROR: " + message);
  }
}
