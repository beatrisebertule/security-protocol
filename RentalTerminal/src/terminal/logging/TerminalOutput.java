package terminal.logging;

/** Static output helpers shared by Result and TerminalBase. */
public final class TerminalOutput {

  private TerminalOutput() {}

  /**
   * Logs an error message to the terminal and prints it to stderr. If the message is null, does nothing.
   */
  public static void showError(String message) {
    if (message == null) return;
    VerboseLogger.get().term("ERROR: " + message);
    System.err.println("Error: " + message);
  }

  /**
   * Logs a message to the terminal and prints it to stdout. If the message is null, does nothing.
   */
  public static void showMessage(String message) {
    if (message == null) return;
    VerboseLogger.get().term(message);
    System.out.println(message);
  }
}
