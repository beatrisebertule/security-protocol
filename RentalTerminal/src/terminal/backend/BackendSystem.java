package terminal.backend;

import java.security.*;
import java.util.*;

import terminal.common.ByteUtil;
import terminal.common.CryptoUtil;

/**
 * Central authority: CA (MSK/MPK), vehicle DB, customer DB, block list.
 * Singleton. In-memory simulation.
 */
public class BackendSystem {

    private static BackendSystem instance;

    private KeyPair masterKeyPair;      // MSK (private) + MPK (public)
    private KeyPair terminalKeyPair;    // skt + pkt for reception terminal
    private byte[] terminalCertificate; // Ct = Sign_MSK(pkt)

    private final Map<String, Vehicle> vehicles = new LinkedHashMap<>();
    private final Map<String, Customer> customers = new LinkedHashMap<>();

    private BackendSystem() {}

    public static BackendSystem getInstance() {
        if (instance == null) {
            instance = new BackendSystem();
        }
        return instance;
    }

    /** Reset for testing. */
    public static void reset() {
        instance = null;
    }

    /**
     * Initialize: generate master key pair and terminal key pair + certificate.
     */
    public void init() throws GeneralSecurityException {
        masterKeyPair = CryptoUtil.generateECKeyPair();
        terminalKeyPair = CryptoUtil.generateECKeyPair();

        // Create terminal certificate: Ct = Sign_MSK(terminalId || pkt)
        byte[] terminalId = new byte[] { 0x54, 0x45, 0x52, 0x4D }; // "TERM"
        byte[] pktEncoded = CryptoUtil.encodeECPublicKey(terminalKeyPair.getPublic());
        terminalCertificate = CryptoUtil.createCertificate(terminalId, pktEncoded, masterKeyPair.getPrivate());
    }

    // --- CA operations ---

    public PublicKey getMasterPublicKey() {
        return masterKeyPair.getPublic();
    }

    public byte[] getMasterPublicKeyEncoded() {
        return CryptoUtil.encodeECPublicKey(masterKeyPair.getPublic());
    }

    public PrivateKey getMasterPrivateKey() {
        return masterKeyPair.getPrivate();
    }

    /**
     * Sign certificate for a card's public key.
     * Returns Cc = certificate TLV bytes.
     */
    public byte[] signCertificate(byte[] cardId, byte[] cardPubKeyEncoded) throws GeneralSecurityException {
        return CryptoUtil.createCertificate(cardId, cardPubKeyEncoded, masterKeyPair.getPrivate());
    }

    public KeyPair getTerminalKeyPair() {
        return terminalKeyPair;
    }

    public byte[] getTerminalCertificate() {
        return terminalCertificate;
    }

    // --- Vehicle management ---

    public void registerVehicle(byte[] id, String plate) {
        vehicles.put(ByteUtil.toHex(id), new Vehicle(id, plate));
    }

    public List<Vehicle> getAvailableVehicles() {
        List<Vehicle> available = new ArrayList<>();
        for (Vehicle v : vehicles.values()) {
            if (v.isAvailable()) available.add(v);
        }
        return available;
    }

    public Vehicle getVehicle(byte[] id) {
        return vehicles.get(ByteUtil.toHex(id));
    }

    public void assignVehicle(byte[] vehicleId, byte[] customerId) {
        Vehicle v = vehicles.get(ByteUtil.toHex(vehicleId));
        if (v != null) {
            v.assign(customerId);
        }
    }

    public void releaseVehicle(byte[] vehicleId) {
        Vehicle v = vehicles.get(ByteUtil.toHex(vehicleId));
        if (v != null) {
            v.release();
        }
    }

    // --- Customer management ---

    public void registerCustomer(byte[] id, String name) {
        customers.put(ByteUtil.toHex(id), new Customer(id, name));
    }

    public Customer getCustomer(byte[] id) {
        return customers.get(ByteUtil.toHex(id));
    }

    public void linkCardToCustomer(byte[] customerId, byte[] cardId) {
        Customer c = customers.get(ByteUtil.toHex(customerId));
        if (c != null) {
            c.setCardId(cardId);
        }
    }

    public void addMileageToCustomer(byte[] customerId, int mileage) {
        Customer c = customers.get(ByteUtil.toHex(customerId));
        if (c != null) {
            c.addMileage(mileage);
        }
    }

    public void processPayment(byte[] customerId) {
        Customer c = customers.get(ByteUtil.toHex(customerId));
        if (c != null) {
            c.clearMileage();
        }
    }

    public void blockCustomer(byte[] customerId) {
        Customer c = customers.get(ByteUtil.toHex(customerId));
        if (c != null) {
            c.block();
        }
    }

    // --- Assignment token (sigma4) ---

    /**
     * Create sigma4 = [1B sigma3Len][sigma3][1B pkcLen][pkc][1B sigLen][Sign_MSK(sigma3||pkc)]
     */
    public byte[] signAssignmentToken(byte[] sigma3, byte[] cardPubKeyEncoded) throws GeneralSecurityException {
        byte[] dataToSign = ByteUtil.concat(sigma3, cardPubKeyEncoded);
        byte[] signature = CryptoUtil.sign(masterKeyPair.getPrivate(), dataToSign);

        byte[] s3Len = new byte[] { (byte) sigma3.length };
        byte[] pkLen = new byte[] { (byte) cardPubKeyEncoded.length };
        byte[] sigLen = new byte[] { (byte) signature.length };

        return ByteUtil.concat(s3Len, sigma3, pkLen, cardPubKeyEncoded, sigLen, signature);
    }

    /**
     * Parse sigma4 token. Returns: [0] = sigma3, [1] = pkc, [2] = signature.
     */
    public static byte[][] parseAssignmentToken(byte[] sigma4) {
        int offset = 0;

        int s3Len = sigma4[offset] & 0xFF;
        offset += 1;
        byte[] sigma3 = new byte[s3Len];
        System.arraycopy(sigma4, offset, sigma3, 0, s3Len);
        offset += s3Len;

        int pkLen = sigma4[offset] & 0xFF;
        offset += 1;
        byte[] pkc = new byte[pkLen];
        System.arraycopy(sigma4, offset, pkc, 0, pkLen);
        offset += pkLen;

        int sigLen = sigma4[offset] & 0xFF;
        offset += 1;
        byte[] signature = new byte[sigLen];
        System.arraycopy(sigma4, offset, signature, 0, sigLen);

        return new byte[][] { sigma3, pkc, signature };
    }

    /**
     * Verify sigma4 against master public key.
     */
    public boolean verifyAssignmentToken(byte[] sigma4) throws GeneralSecurityException {
        byte[][] parts = parseAssignmentToken(sigma4);
        byte[] sigma3 = parts[0];
        byte[] pkc = parts[1];
        byte[] signature = parts[2];

        byte[] dataToVerify = ByteUtil.concat(sigma3, pkc);
        return CryptoUtil.verify(masterKeyPair.getPublic(), dataToVerify, signature);
    }
}
