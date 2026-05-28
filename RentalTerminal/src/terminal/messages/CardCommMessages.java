package terminal.messages;

/** Result message strings for CardComm operations. */
public final class CardCommMessages {

  private CardCommMessages() {}

  public static String errApduTransmit(String cause) {
    return "APDU transmit failed: " + cause;
  }

  public static String errCardSw(int sw) {
    return "Card returned SW: " + String.format("%04X", sw);
  }
}
