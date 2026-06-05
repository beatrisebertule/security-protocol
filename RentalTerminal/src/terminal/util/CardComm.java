package terminal.util;

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
public class CardComm {
  private final CardChannel channel;

  /**
   * Creates a communication wrapper around a Java smart-card channel.
   *
   * @param channel selected card channel used for all APDU transmission
   */
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
   * Sends an APDU with P1/P2 and data payload without interpreting the status
   * word.
   *
   * Raw sends are used by negative tests that must assert exact failure status
   * words instead of treating every non-0x9000 response as a generic failure.
   *
   * @param ins instruction byte
   * @param p1 first APDU parameter byte
   * @param p2 second APDU parameter byte
   * @param data command payload
   * @return raw response APDU wrapped in a Result
   */
  public Result<ResponseAPDU> sendRaw(byte ins, byte p1, byte p2, byte[] data) {
    return transmit(new CommandAPDU(
        ProtocolConstants.CLA_RENTAL, ins, p1, p2, data, 0, data.length, 256));
  }

  /**
   * Send APDU without payload data.
   */
  public Result<ResponseAPDU> sendRaw(byte ins) {
    return sendRaw(ins, (byte) 0x00, (byte) 0x00, new byte[0]);
  }
  
  /**
   * Send APDU with data payload and P1/P2 = 0.
   */
  public Result<ResponseAPDU> sendRaw(byte ins, byte[] data) {
    return sendRaw(ins, (byte) 0x00, (byte) 0x00, data);
  }

  /**
   * Sends a command and accepts only SW == 0x9000.
   *
   * @param ins instruction byte
   * @return response data on success, or Result.fail containing the status word
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
      byte ins = (byte) cmd.getINS();
      // PIN-carrying APDUs are excluded from the verbose log because their payload
      // is the PIN hash, which is effectively a credential. Anyone with read access
      // to the log file would obtain that hash and could replay it directly against
      // the card (the card compares hashes, so knowing the hash is enough to authenticate).
      if (ins != ProtocolConstants.INS_VERIFY_PIN && ins != ProtocolConstants.INS_PERSONALIZE_PIN) {
        VerboseLogger.get().apdu("TX-DATA", body, -1);
      }
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
   * Returns the status word from a response APDU.
   *
   * @param resp response APDU from the card
   * @return two-byte status word as an int
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

  /**
   * Exception wrapper for legacy call sites that expect checked exceptions
   * instead of Result failures.
   */
  public static class CardCommException extends Exception {
    public final int sw;

    public CardCommException(int sw) {
      super(CardCommMessages.errCardSw(sw));
      this.sw = sw;
    }
  }
}
