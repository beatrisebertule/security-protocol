package terminal.personalization;

import terminal.backend.BackendSystem;
import terminal.common.CardComm;
import terminal.common.CryptoUtil;
import terminal.common.ProtocolConstants;

/**
 * Personalization terminal: initializes a blank card with keys, certificate, PIN.
 * Transitions: BLANK -> PERSONALIZED -> ISSUED.
 */
public class PersonalizationTerminal {

    private final CardComm comm;
    private final BackendSystem backend;

    public PersonalizationTerminal(CardComm comm, BackendSystem backend) {
        this.comm = comm;
        this.backend = backend;
    }

    /**
     * Full card personalization: BLANK -> PERSONALIZED.
     * Uses default expiry of year 2100.
     *
     * @param cardId 4-byte card identifier
     * @param pin    PIN string (will be SHA-256 hashed)
     */
    public void personalizeCard(byte[] cardId, String pin) throws Exception {
        personalizeCard(cardId, pin, 4102444800000L);
    }

    /**
     * Full card personalization with explicit expiry date.
     *
     * @param cardId      4-byte card identifier
     * @param pin         PIN string (will be SHA-256 hashed)
     * @param expiryMillis expiry timestamp in milliseconds since epoch
     */
    public void personalizeCard(byte[] cardId, String pin, long expiryMillis) throws Exception {
        // Step 1: send MPK, trigger on-card keypair generation, receive pkc
        byte[] mpk = backend.getMasterPublicKeyEncoded();
        byte[] pkc = comm.sendCommandChecked(
            ProtocolConstants.INS_PERSONALIZE_KEYS, (byte) 0x00, (byte) 0x00, mpk);

        // Step 2: backend signs certificate, store on card
        byte[] cert = backend.signCertificate(cardId, pkc);
        comm.sendCommandChecked(
            ProtocolConstants.INS_PERSONALIZE_KEYS, (byte) 0x01, (byte) 0x00, cert);

        // Step 3: set PIN hash
        byte[] pinHash = CryptoUtil.hashPin(pin);
        comm.sendCommandChecked(ProtocolConstants.INS_PERSONALIZE_PIN, pinHash);

        // Step 4: finalize - store card ID + expiry, transition to PERSONALIZED
        byte[] expiry = longToBytes(expiryMillis);
        byte[] payload = new byte[ProtocolConstants.CARD_ID_LENGTH + ProtocolConstants.EXPIRY_DATE_LENGTH];
        System.arraycopy(cardId, 0, payload, 0, ProtocolConstants.CARD_ID_LENGTH);
        System.arraycopy(expiry, 0, payload, ProtocolConstants.CARD_ID_LENGTH, ProtocolConstants.EXPIRY_DATE_LENGTH);
        comm.sendCommandChecked(ProtocolConstants.INS_PERSONALIZE_FINISH, payload);
    }

    private static byte[] longToBytes(long v) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) { b[i] = (byte)(v & 0xFF); v >>= 8; }
        return b;
    }

    /**
     * Issue card to customer: PERSONALIZED -> ISSUED.
     *
     * @param customerId 4-byte customer identifier
     */
    public void issueCard(byte[] customerId) throws Exception {
        comm.sendCommandChecked(ProtocolConstants.INS_ISSUE_CARD, customerId);
    }

    /**
     * Get current card state.
     */
    public byte getCardState() throws Exception {
        byte[] data = comm.sendCommandChecked(ProtocolConstants.INS_GET_STATE);
        return data[0];
    }
}
