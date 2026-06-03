package terminal.personalization;

import terminal.backend.BackendSystem;
import terminal.util.CardComm;

/**
 * Implementation of {@link PersonalizationTerminalBase} with user-facing
 * display.
 */
public class PersonalizationTerminal extends PersonalizationTerminalBase {

  public PersonalizationTerminal(CardComm comm, BackendSystem backend) {
    super(comm, backend);
  }
}
