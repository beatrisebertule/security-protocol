package terminal.logging;

/** Static output helpers shared by Result and TerminalBase. */
public final class TerminalOutput {

  private TerminalOutput() {}

  public static void showError(String message) {
    VerboseLogger.get().step("ERROR: " + message);
    System.err.println("Error: " + message);
  }

  public static void showMessage(String message) {
    VerboseLogger.get().step(message);
    System.out.println(message);
  }
}
