package terminal.common;

public class ByteUtil {

  public static String toHex(byte[] bytes) {// TODO: Add here restriction not used by card
    if (bytes == null)
      return "null";
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02X", b));
    }
    return sb.toString();
  }

  public static byte[] fromHex(String hex) {
    if (hex == null || hex.length() % 2 != 0) {
      throw new IllegalArgumentException("Invalid hex string");
    }
    byte[] result = new byte[hex.length() / 2];
    for (int i = 0; i < result.length; i++) {
      result[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return result;
  }

  public static byte[] concat(byte[]... arrays) {
    int totalLen = 0;
    for (byte[] a : arrays) {
      totalLen += a.length;
    }
    byte[] result = new byte[totalLen];
    int offset = 0;
    for (byte[] a : arrays) {
      System.arraycopy(a, 0, result, offset, a.length);
      offset += a.length;
    }
    return result;
  }

  public static byte[] shortToBytes(short val) {//TODO: Add resitiction that card cannot use this!
    return new byte[] {
        (byte) ((val >> 8) & 0xFF),
        (byte) (val & 0xFF)
    };
  }

  public static short bytesToShort(byte[] bytes, int offset) {
    return (short) (((bytes[offset] & 0xFF) << 8) | (bytes[offset + 1] & 0xFF));
  }
}
