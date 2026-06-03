package terminal.logging.messages;

/** Result message strings for CardComm operations. */
public final class CardCommMessages {

  private CardCommMessages() {}

  public static String errApduTransmit(String cause) {
    return "APDU transmit failed: " + cause;
  }

  public static String errCardSw(int sw) {
    String description = getSwDescription(sw);
    if (description != null) {
      return "Card error [0x" + String.format("%04X", sw) + "]: " + description;
    }
    return "Card returned SW: " + String.format("%04X", sw);
  }

  // Map custom status words to human-readable error descriptions
  private static String getSwDescription(int sw) {
    switch (sw) {
      case 0x6A80:
        return "Wrong state - card is not in the expected state for this operation";
      case 0x6A81:
        return "PIN incorrect - the PIN provided does not match";
      case 0x6A82:
        return "PIN locked - too many failed PIN attempts (card is locked)";
      case 0x6A83:
        return "Authentication required - terminal authentication needed";
      case 0x6A84:
        return "Signature invalid - cryptographic signature verification failed";
      case 0x6A85:
        return "Sequence error - mileage update sequence number mismatch (possible replay attempt)";
      case 0x6A86:
        return "Card blocked - this card has been blocked by the backend";
      case 0x6A87:
        return "Unpaid mileage - customer has unpaid mileage charges from previous rental";
      case 0x6A88:
        return "Card expired - rental card has expired";
      case 0x9000:
        return "Success";
      default:
        return null;
    }
  }
}
