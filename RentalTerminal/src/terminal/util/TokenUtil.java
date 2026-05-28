package terminal.util;

/**
 * Utilities for parsing and working with token structures.
 */
public class TokenUtil {

  /**
   * Parse vehicleToken. Returns: [0] = reqData, [1] = reqVehicleToken, [2] = pkc, [3] =
   * signature.
   */
  public static byte[][] parseAssignmentToken(byte[] vehicleToken) {
    int offset = 0;

    int rdLen = ByteUtil.bytesToShort(vehicleToken, offset) & 0xFFFF;
    offset += 2;
    byte[] reqData = new byte[rdLen];
    System.arraycopy(vehicleToken, offset, reqData, 0, rdLen);
    offset += rdLen;

    int reqVehicleTokenLen = ByteUtil.bytesToShort(vehicleToken, offset) & 0xFFFF;
    offset += 2;
    byte[] reqVehicleToken = new byte[reqVehicleTokenLen];
    System.arraycopy(vehicleToken, offset, reqVehicleToken, 0, reqVehicleTokenLen);
    offset += reqVehicleTokenLen;

    int pkLen = ByteUtil.bytesToShort(vehicleToken, offset) & 0xFFFF;
    offset += 2;
    byte[] pkc = new byte[pkLen];
    System.arraycopy(vehicleToken, offset, pkc, 0, pkLen);
    offset += pkLen;

    int sigLen = ByteUtil.bytesToShort(vehicleToken, offset) & 0xFFFF;
    offset += 2;
    byte[] signature = new byte[sigLen];
    System.arraycopy(vehicleToken, offset, signature, 0, sigLen);

    return new byte[][] { reqData, reqVehicleToken, pkc, signature };
  }
}
