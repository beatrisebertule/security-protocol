package terminal;

import terminal.logging.VerboseLogger;
import terminal.util.CardComm;

/**
 * Common base for all terminal types: holds the card communication channel
 * and provides unified output that logs every message to VerboseLogger and
 * writes it to stdout/stderr.
 */
public abstract class TerminalBase {

  protected final CardComm comm;

  protected TerminalBase(CardComm comm) {
    this.comm = comm;
  }

  protected void showMessage(String message) {
    VerboseLogger.get().step(message);
    System.out.println(message);
  }

  protected void showError(String message) {
    VerboseLogger.get().step("ERROR: " + message);
    System.err.println("Error: " + message);
  }
}
