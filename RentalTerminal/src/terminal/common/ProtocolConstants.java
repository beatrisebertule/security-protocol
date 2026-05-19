package terminal.common;

/**
 * Protocol constants mirroring AppletConstants from the card side.
 * Values MUST match exactly.
 */
public final class ProtocolConstants {
  // CLA byte
  public static final byte CLA_RENTAL = (byte) 0x00;

  // Lifecycle states
  public static final byte STATE_BLANK = (byte) 0x00;
  public static final byte STATE_PERSONALIZED = (byte) 0x01;
  public static final byte STATE_ISSUED = (byte) 0x02;
  public static final byte STATE_ASSIGNED = (byte) 0x03;
  public static final byte STATE_BLOCKED = (byte) 0x04;
  public static final byte STATE_END_OF_LIFE = (byte) 0x05;

  // Personalization instructions
  public static final byte INS_PERSONALIZE_KEYS = (byte) 0x10;
  public static final byte INS_PERSONALIZE_PIN = (byte) 0x11;
  public static final byte INS_PERSONALIZE_FINISH = (byte) 0x12;
  public static final byte INS_ISSUE_CARD = (byte) 0x13;

  // Authentication instructions
  public static final byte INS_GET_NONCE = (byte) 0x20;
  public static final byte INS_VERIFY_TERMINAL_SIG = (byte) 0x21;
  public static final byte INS_VERIFY_PIN = (byte) 0x22;
  public static final byte INS_SIGN_NONCE = (byte) 0x23;
  public static final byte INS_GET_CERTIFICATE = (byte) 0x24;

  // Vehicle assignment instructions
  public static final byte INS_SIGN_VEHICLE_REQ = (byte) 0x30;
  public static final byte INS_STORE_ASSIGNMENT = (byte) 0x31;

  // Vehicle access instructions
  public static final byte INS_GET_ASSIGNMENT_DATA = (byte) 0x40;
  public static final byte INS_SIGN_VEHICLE_CHALL = (byte) 0x41;

  // Mileage instructions
  public static final byte INS_UPDATE_MILEAGE = (byte) 0x50;
  public static final byte INS_GET_MILEAGE = (byte) 0x51;

  // Vehicle return
  public static final byte INS_RETURN_VEHICLE = (byte) 0x60;

  // State and admin
  public static final byte INS_GET_STATE = (byte) 0x70;
  public static final byte INS_GET_CARD_ID = (byte) 0x71;
  public static final byte INS_BLOCK_CARD = (byte) 0x72;
  public static final byte INS_CLEAR_MILEAGE = (byte) 0x73;
  public static final byte INS_CHECK_EXPIRY = (byte) 0x74;

  // Custom status words
  public static final short SW_WRONG_STATE = (short) 0x6A80;
  public static final short SW_PIN_INCORRECT = (short) 0x6A81;
  public static final short SW_PIN_LOCKED = (short) 0x6A82;
  public static final short SW_AUTH_REQUIRED = (short) 0x6A83;
  public static final short SW_SIGNATURE_INVALID = (short) 0x6A84;
  public static final short SW_SEQUENCE_ERROR = (short) 0x6A85;
  public static final short SW_CARD_BLOCKED = (short) 0x6A86;
  public static final short SW_UNPAID_MILEAGE = (short) 0x6A87;
  public static final short SW_CARD_EXPIRED = (short) 0x6A88;

  // Standard ISO status words
  public static final short SW_OK = (short) 0x9000;
  public static final short SW_UNKNOWN = (short) 0x6F00;

  // Sizes
  public static final int NONCE_LENGTH = 16;
  public static final int EXPIRY_DATE_LENGTH = 8;
  public static final int PIN_HASH_LENGTH = 32;
  public static final int CARD_ID_LENGTH = 4;
  public static final int VEHICLE_ID_LENGTH = 4;
  public static final int RENTAL_PERIOD_LENGTH = 8;
  public static final int EC_PUB_KEY_LENGTH = 65;
  public static final int EC_PRIV_KEY_LENGTH = 32;
  public static final int MAX_PIN_TRIES = 3;
}
