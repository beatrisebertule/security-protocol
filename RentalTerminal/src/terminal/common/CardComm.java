package terminal.common;

import javax.smartcardio.CardChannel;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Helper class for sending APDU commands to the smart card.
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
    CommandAPDU command =
        new CommandAPDU(ProtocolConstants.CLA_RENTAL, ins, 0x00, 0x00, 256);

    return channel.transmit(command);
  }

 /**
 * Sends a command APDU with payload data.
 *
 * @param ins instruction byte
 * @param data APDU payload
 * @return response APDU from the card
 */
  public ResponseAPDU sendCommand(byte ins, byte[] data) throws Exception {
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

    return channel.transmit(cmd);
  }

  /**
   * Send APDU with P1/P2 and data payload.
   */
  public ResponseAPDU sendCommand(byte ins, byte p1, byte p2, byte[] data)
      throws Exception {

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

    return channel.transmit(command);
  }

  /**
   * Send and check SW == 0x9000. Throws on error.
   */
  public byte[] sendCommandChecked(byte ins) throws Exception {
    ResponseAPDU response = sendCommand(ins);

    checkSW(response);

    return response.getData();
  }

  /**
   * Send with data and check SW == 0x9000. Throws on error.
   */
  public byte[] sendCommandChecked(byte ins, byte[] data) throws Exception {
    ResponseAPDU resp = sendCommand(ins, data);

    checkSW(resp);

    return resp.getData();
  }

  /**
   * Send with P1/P2/data and check SW == 0x9000. Throws on error.
   */
  public byte[] sendCommandChecked(byte ins, byte p1, byte p2, byte[] data)
      throws Exception {

    ResponseAPDU response = sendCommand(ins, p1, p2, data);

    checkSW(response);

    return response.getData();
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
      super("Card returned SW: " + String.format("%04X", sw));
      this.sw = sw;
    }
  }
}