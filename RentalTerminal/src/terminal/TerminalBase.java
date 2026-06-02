package terminal;

import terminal.util.CardComm;

/**
 * Common base for all terminal types: holds the card communication channel
 * and defines the output contract that concrete implementations must provide.
 */
public abstract class TerminalBase {

  protected final CardComm comm;

  protected TerminalBase(CardComm comm) {
    this.comm = comm;
  }

  /** Display an informational message to the user. */
  protected abstract void showMessage(String message);

  /** Display an error to the user. */
  protected abstract void showError(String message);
}
