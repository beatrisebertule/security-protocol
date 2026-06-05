package terminal.util;

import java.math.BigInteger;

/** Utility methods for byte array manipulation. */
public class ByteUtil {

  /**
   * Encode a byte array as an uppercase hex string.
   *
   * @param bytes the bytes to encode, or {@code null}
   * @return hex string, or {@code "null"} if the input is null
   */
  public static String toHex(byte[] bytes) {
    if (bytes == null)
      return "null";
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
      sb.append(String.format("%02X", b));
    }
    return sb.toString();
  }

  /**
   * Decode an uppercase or lowercase hex string into a byte array.
   *
   * @param hex even-length hex string
   * @return decoded bytes
   * @throws IllegalArgumentException if the string is null or has odd length
   */
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

  /**
   * Concatenate any number of byte arrays into one.
   *
   * @param arrays the arrays to concatenate
   * @return a new array containing all input bytes in order
   */
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

  /**
   * Encode a short as a 2-byte big-endian array.
   *
   * @param val the value to encode
   * @return 2-byte big-endian representation
   */
  public static byte[] shortToBytes(short val) {
    return new byte[] {
        (byte) ((val >> 8) & 0xFF),
        (byte) (val & 0xFF)
    };
  }

  /**
   * Decode a 2-byte big-endian short from a byte array.
   *
   * @param bytes  source array
   * @param offset start offset
   * @return decoded short value
   */
  public static short bytesToShort(byte[] bytes, int offset) {
    return (short) (((bytes[offset] & 0xFF) << 8) | (bytes[offset + 1] & 0xFF));
  }

  /**
   * Encode a non-negative {@link BigInteger} as a fixed-length big-endian byte
   * array. Strips the leading zero byte that Java's two's-complement encoding
   * may add, and left-pads with zeros if the value encodes to fewer bytes than
   * {@code len}.
   *
   * @param val the non-negative integer to encode
   * @param len desired output length in bytes
   * @return big-endian byte array of exactly {@code len} bytes
   */
  public static byte[] toBigIntBytes(BigInteger val, int len) {
    byte[] bytes = val.toByteArray();
    if (bytes.length == len) return bytes;
    byte[] result = new byte[len];
    if (bytes.length > len) {
      System.arraycopy(bytes, bytes.length - len, result, 0, len);
    } else {
      System.arraycopy(bytes, 0, result, len - bytes.length, bytes.length);
    }
    return result;
  }

  /**
   * Encode an int as a 4-byte big-endian array.
   *
   * @param val the value to encode
   * @return 4-byte big-endian representation
   */
  public static byte[] intToBytes(int val) {
    return new byte[] {
        (byte) ((val >> 24) & 0xFF),
        (byte) ((val >> 16) & 0xFF),
        (byte) ((val >> 8) & 0xFF),
        (byte) (val & 0xFF)
    };
  }

  /**
   * Decode a 4-byte big-endian int from a byte array.
   *
   * @param bytes  source array
   * @param offset start offset
   * @return decoded int value
   */
  public static int bytesToInt(byte[] bytes, int offset) {
    return ((bytes[offset] & 0xFF) << 24) | 
           ((bytes[offset + 1] & 0xFF) << 16) | 
           ((bytes[offset + 2] & 0xFF) << 8) | 
           (bytes[offset + 3] & 0xFF);
  }

  /**
   * Encode a long as an 8-byte big-endian array.
   *
   * @param v the value to encode
   * @return 8-byte big-endian representation
   */
  public static byte[] longToBytes(long v) {
    byte[] b = new byte[8];
    for (int i = 7; i >= 0; i--) {
      b[i] = (byte) (v & 0xFF);
      v >>= 8;
    }
    return b;
  }
}
