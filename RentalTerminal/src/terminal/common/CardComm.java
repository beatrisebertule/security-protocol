package terminal.common;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import terminal.logging.Result;
import terminal.logging.VerboseLogger;
import terminal.logging.messages.CardCommMessages;

/**
 * Helper class for sending APDU commands to the smart card.
 * All methods return Result<T> instead of throwing - protocol failures (bad SW,
 * transmit errors) flow through Result.error rather than stack unwinding so the
 * caller can pair each failure with an audit log entry.
 */
// TODO: avoid creating communication objects repeatedly
public class CardComm {
  private final CardChannel channel;

  public CardComm(CardChannel channel) {
    this.channel = channel;
  }

  /**
   * Sends a command APDU without payload data.
   *
   * @param ins instruction byte
   * @return response APDU from the card
   */
  public ResponseAPDU sendCommand(byte ins) throws Exception {
    Result<ResponseAPDU> result = transmit(
        new CommandAPDU(ProtocolConstants.CLA_RENTAL, ins, 0x00, 0x00, 256));
    if (!result.success) {
      throw new Exception(result.error.getMessage(), result.error);
    }
    return result.value;
  }

  /**
   * Sends a command APDU with payload data.
   *
   * @param ins  instruction byte
   * @param data APDU payload
   * @return response APDU from the card
   */
  public ResponseAPDU sendCommand(byte ins, byte[] data) throws Exception {
    Result<ResponseAPDU> result = transmit(
        new CommandAPDU(ProtocolConstants.CLA_RENTAL, ins, 0x00, 0x00, data, 0, data.length, 256));
    if (!result.success) {
      throw new Exception(result.error.getMessage(), result.error);
    }
    return result.value;
  }

  /**
   * Send APDU with P1/P2 and data payload. Raw - does not check SW.
   */
  public Result<ResponseAPDU> sendRaw(byte ins, byte p1, byte p2, byte[] data) {
    return transmit(new CommandAPDU(
        ProtocolConstants.CLA_RENTAL, ins, p1, p2, data, 0, data.length, 256));
  }

  public Result<ResponseAPDU> sendRaw(byte ins) {
    return sendRaw(ins, (byte) 0x00, (byte) 0x00, new byte[0]);
  }

  public Result<ResponseAPDU> sendRaw(byte ins, byte[] data) {
    return sendRaw(ins, (byte) 0x00, (byte) 0x00, data);
  }

  /**
   * Send and check SW == 0x9000. Returns response data on success,
   * Result.fail with the SW hex on any other status word.
   */
  public Result<byte[]> send(byte ins) {
    return checkAndExtract(sendRaw(ins));
  }

  /**
   * Send with data and check SW == 0x9000.
   */
  public Result<byte[]> send(byte ins, byte[] data) {
    return checkAndExtract(sendRaw(ins, data));
  }

  /**
   * Send with P1/P2/data and check SW == 0x9000.
   */
  public Result<byte[]> send(byte ins, byte p1, byte p2, byte[] data) {
    return checkAndExtract(sendRaw(ins, p1, p2, data));
  }

  // Wraps CardChannel.transmit, which throws CardException on I/O failure.
  // Caught here so the public API stays exception-free.
  private Result<ResponseAPDU> transmit(CommandAPDU cmd) {
    VerboseLogger.get().apdu("TX",
        new byte[] { (byte) cmd.getCLA(), (byte) cmd.getINS(),
            (byte) cmd.getP1(), (byte) cmd.getP2() },
        -1);
    byte[] body = cmd.getData();
    if (body != null && body.length > 0) {
      VerboseLogger.get().apdu("TX-DATA", body, -1);
    }
    try {
      ResponseAPDU resp = channel.transmit(cmd);
      VerboseLogger.get().apdu("RX", resp.getData(), resp.getSW());
      return Result.ok(resp);
    } catch (CardException e) {
      VerboseLogger.get().event(CardCommMessages.errApduTransmit(e.getMessage()));
      return Result.fail(CardCommMessages.errApduTransmit(e.getMessage()), e);
    }
  }

  // Shared SW check used by all send() variants.
  private Result<byte[]> checkAndExtract(Result<ResponseAPDU> r) {
    if (!r.success) {
      return Result.fail(r.error);
    }
    int sw = r.value.getSW();
    if (sw != 0x9000) {
      return Result.fail(CardCommMessages.errCardSw(sw));
    }
    return Result.ok(r.value.getData());
  }

  /**
   * Get status word from response.
   */
  public static int getSW(ResponseAPDU resp) {
    return resp.getSW();
  }

  /**
   * Verifies that the response status word equals 0x9000.
   *
   * @param resp response APDU from the card
   */
  public static void checkSW(ResponseAPDU resp) throws CardCommException {
    int sw = resp.getSW();
    if (sw != 0x9000) {
      throw new CardCommException(sw);
    }
  }

  public static class CardCommException extends Exception {

    // TODO: maybe replace exceptions with explicit result objects later
    public final int sw;

    public CardCommException(int sw) {
      super(CardCommMessages.errCardSw(sw));
      this.sw = sw;
    }
  }
}
