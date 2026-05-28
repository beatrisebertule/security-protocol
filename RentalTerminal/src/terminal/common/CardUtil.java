package terminal.common;

/**
 * Stateless utility methods shared across all terminal types.
 */
public class CardUtil {

  private CardUtil() {}

  /**
   * Reads the current lifecycle state byte from the smart card.
   *
   * @param comm channel used to send APDU commands to the smart card
   *
   * @return {@code Result.ok(state)} with the raw state byte (one of the
   *         {@code ProtocolConstants.STATE_*} constants) on success;
   *         {@code Result.fail} if the card rejects {@code INS_GET_STATE}
   */
  public static Result<Byte> getCardState(CardComm comm) {
    Result<byte[]> r = comm.send(ProtocolConstants.INS_GET_STATE);
    if (!r.success) {
      return Result.fail(r.error);
    }
    return Result.ok(r.value[0]);
  }
}
