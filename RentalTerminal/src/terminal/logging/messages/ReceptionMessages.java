package terminal.logging.messages;

/** Result message strings for ReceptionTerminalBase operations. */
public final class ReceptionMessages {

  private ReceptionMessages() {}

  public static final String ERR_TERMINAL_NONCE_SIGNING =
      "terminal nonce signing failed";
  public static final String ERR_PIN_HASHING =
      "PIN hashing failed";
  public static final String ERR_CARD_CERT_VERIFICATION =
      "card cert verification failed";
  public static final String ERR_CARD_SIG_VERIFICATION =
      "card sig verification failed";
  public static final String ERR_CARD_BLOCKED =
      "card is blocked";
  public static final String ERR_ASSIGNMENT_TOKEN_SIGNING =
      "assignment token signing failed";
  public static final String ERR_INSUFFICIENT_BALANCE =
      "Insufficient balance";
}
