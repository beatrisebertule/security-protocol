package terminal.common;

/**
 * Protocol constants mirroring AppletConstants from the card side.
 * Values MUST match exactly.
 */
public interface ProtocolConstants {

    // CLA byte
    byte CLA_RENTAL = (byte) 0x00;

    // Lifecycle states
    byte STATE_BLANK        = (byte) 0x00;
    byte STATE_PERSONALIZED = (byte) 0x01;
    byte STATE_ISSUED       = (byte) 0x02;
    byte STATE_ASSIGNED     = (byte) 0x03;
    byte STATE_BLOCKED      = (byte) 0x04;
    byte STATE_END_OF_LIFE  = (byte) 0x05;

    // Personalization instructions
    byte INS_PERSONALIZE_KEYS   = (byte) 0x10;
    byte INS_PERSONALIZE_PIN    = (byte) 0x11;
    byte INS_PERSONALIZE_FINISH = (byte) 0x12;
    byte INS_ISSUE_CARD         = (byte) 0x13;

    // Authentication instructions
    byte INS_GET_NONCE           = (byte) 0x20;
    byte INS_VERIFY_TERMINAL_SIG = (byte) 0x21;
    byte INS_VERIFY_PIN          = (byte) 0x22;
    byte INS_SIGN_NONCE          = (byte) 0x23;
    byte INS_GET_CERTIFICATE     = (byte) 0x24;

    // Vehicle assignment instructions
    byte INS_SIGN_VEHICLE_REQ  = (byte) 0x30;
    byte INS_STORE_ASSIGNMENT  = (byte) 0x31;

    // Vehicle access instructions
    byte INS_GET_ASSIGNMENT_DATA = (byte) 0x40;
    byte INS_SIGN_VEHICLE_CHALL  = (byte) 0x41;

    // Mileage instructions
    byte INS_UPDATE_MILEAGE = (byte) 0x50;
    byte INS_GET_MILEAGE    = (byte) 0x51;

    // Vehicle return
    byte INS_RETURN_VEHICLE = (byte) 0x60;

    // State and admin
    byte INS_GET_STATE     = (byte) 0x70;
    byte INS_GET_CARD_ID   = (byte) 0x71;
    byte INS_BLOCK_CARD    = (byte) 0x72;
    byte INS_CLEAR_MILEAGE = (byte) 0x73;
    byte INS_CHECK_EXPIRY  = (byte) 0x74;

    // Custom status words
    short SW_WRONG_STATE          = (short) 0x6A80;
    short SW_PIN_INCORRECT        = (short) 0x6A81;
    short SW_PIN_LOCKED           = (short) 0x6A82;
    short SW_AUTH_REQUIRED        = (short) 0x6A83;
    short SW_SIGNATURE_INVALID    = (short) 0x6A84;
    short SW_SEQUENCE_ERROR       = (short) 0x6A85;
    short SW_CARD_BLOCKED         = (short) 0x6A86;
    short SW_UNPAID_MILEAGE       = (short) 0x6A87;
    short SW_CARD_EXPIRED         = (short) 0x6A88;

    // Standard ISO status words
    short SW_OK                   = (short) 0x9000;
    short SW_UNKNOWN              = (short) 0x6F00;

    // Sizes
    int NONCE_LENGTH         = 16;
    int EXPIRY_DATE_LENGTH   = 8;
    int PIN_HASH_LENGTH   = 32;
    int CARD_ID_LENGTH    = 4;
    int EC_PUB_KEY_LENGTH = 65;
    int EC_PRIV_KEY_LENGTH = 32;
    int MAX_PIN_TRIES     = 3;
}
