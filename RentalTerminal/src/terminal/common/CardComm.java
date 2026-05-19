package terminal.common;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Card communication abstraction. Wraps CardChannel, builds APDUs, checks SW.
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
   * Send APDU with no data, expect response data. Raw - does not check SW.
   */
  public Result<ResponseAPDU> sendRaw(byte ins) {
    CommandAPDU command =
        new CommandAPDU(ProtocolConstants.CLA_RENTAL, ins, 0x00, 0x00, 256);
    return transmit(command);
  }

  /**
   * Send APDU with data payload. Raw - does not check SW.
   */
  public Result<ResponseAPDU> sendRaw(byte ins, byte[] data) {
    CommandAPDU cmd =
        new CommandAPDU(
            ProtocolConstants.CLA_RENTAL,
            ins,
            0x00,
            0x00,
            data,
            0,
            data.length,
            256);
    return transmit(cmd);
  }

  /**
   * Send APDU with P1/P2 and data payload. Raw - does not check SW.
   */
  public Result<ResponseAPDU> sendRaw(byte ins, byte p1, byte p2, byte[] data) {
    CommandAPDU command =
        new CommandAPDU(
            ProtocolConstants.CLA_RENTAL,
            ins,
            p1,
            p2,
            data,
            0,
            data.length,
            256);
    return transmit(command);
  }

  /**
   * Send and check SW == 0x9000. Returns response data on success,
   * Result.fail with the SW hex on any other status word.
   */
  public Result<byte[]> send(byte ins) {
    Result<ResponseAPDU> r = sendRaw(ins);
    return checkAndExtract(r);
  }

  /**
   * Send with data and check SW == 0x9000.
   */
  public Result<byte[]> send(byte ins, byte[] data) {
    Result<ResponseAPDU> r = sendRaw(ins, data);
    return checkAndExtract(r);
  }

  /**
   * Send with P1/P2/data and check SW == 0x9000.
   */
  public Result<byte[]> send(byte ins, byte p1, byte p2, byte[] data) {
    Result<ResponseAPDU> r = sendRaw(ins, p1, p2, data);
    return checkAndExtract(r);
  }

  // Wraps CardChannel.transmit, which throws CardException on I/O failure.
  // Caught here so the public API stays exception-free.
  private Result<ResponseAPDU> transmit(CommandAPDU cmd) {
    try {
      return Result.ok(channel.transmit(cmd));
    } catch (CardException e) {
      return Result.fail("APDU transmit failed: " + e.getMessage(), e);
    }
  }

  // Shared SW check used by all send() variants.
  private Result<byte[]> checkAndExtract(Result<ResponseAPDU> r) {
    if (!r.success) {
      return Result.fail(r.error);
    }
    int sw = r.value.getSW();
    if (sw != 0x9000) {
      return Result.fail("Card returned SW: " + String.format("%04X", sw));
    }
    return Result.ok(r.value.getData());
  }

  /**
   * Get status word from response.
   */
  public static int getSW(ResponseAPDU resp) {
    return resp.getSW();
  }

  // ====================================================================
  // Deprecated throwing API - kept temporarily so existing callers still
  // compile during the Result<T> migration. Remove in Phase 5 once every
  // caller has been ported to send()/sendRaw().
  // ====================================================================

  /** @deprecated use {@link #sendRaw(byte)} */
  @Deprecated
  public ResponseAPDU sendCommand(byte ins) throws Exception {
    Result<ResponseAPDU> r = sendRaw(ins);
    if (!r.success) throw r.error;
    return r.value;
  }

  /** @deprecated use {@link #sendRaw(byte, byte[])} */
  @Deprecated
  public ResponseAPDU sendCommand(byte ins, byte[] data) throws Exception {
    Result<ResponseAPDU> r = sendRaw(ins, data);
    if (!r.success) throw r.error;
    return r.value;
  }

  /** @deprecated use {@link #sendRaw(byte, byte, byte, byte[])} */
  @Deprecated
  public ResponseAPDU sendCommand(byte ins, byte p1, byte p2, byte[] data)
      throws Exception {
    Result<ResponseAPDU> r = sendRaw(ins, p1, p2, data);
    if (!r.success) throw r.error;
    return r.value;
  }

  /** @deprecated use {@link #send(byte)} */
  @Deprecated
  public byte[] sendCommandChecked(byte ins) throws Exception {
    Result<byte[]> r = send(ins);
    if (!r.success) throw r.error;
    return r.value;
  }

  /** @deprecated use {@link #send(byte, byte[])} */
  @Deprecated
  public byte[] sendCommandChecked(byte ins, byte[] data) throws Exception {
    Result<byte[]> r = send(ins, data);
    if (!r.success) throw r.error;
    return r.value;
  }

  /** @deprecated use {@link #send(byte, byte, byte, byte[])} */
  @Deprecated
  public byte[] sendCommandChecked(byte ins, byte p1, byte p2, byte[] data)
      throws Exception {
    Result<byte[]> r = send(ins, p1, p2, data);
    if (!r.success) throw r.error;
    return r.value;
  }

  /** @deprecated SW now surfaces via Result.fail in {@link #send}. */
  @Deprecated
  public static void checkSW(ResponseAPDU resp) throws CardCommException {
    int sw = resp.getSW();
    if (sw != 0x9000) {
      throw new CardCommException(sw);
    }
  }

  /** @deprecated kept only so the throwing wrappers above can compile. */
  @Deprecated
  public static class CardCommException extends Exception {
    public final int sw;

    public CardCommException(int sw) {
      super("Card returned SW: " + String.format("%04X", sw));
      this.sw = sw;
    }
  }
}
