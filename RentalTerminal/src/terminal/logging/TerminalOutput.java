package terminal.logging;

/** Static output helpers shared by Result and TerminalBase. */
public final class TerminalOutput {

  private TerminalOutput() {}

  public static void showError(String message) {
    if (message == null) return;
    VerboseLogger.get().term("ERROR: " + message);
    System.err.println("Error: " + message);
  }

  public static void showMessage(String message) {
    if (message == null) return;
    VerboseLogger.get().term(message);
    System.out.println(message);
  }
}
