package terminal.vehicle;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import terminal.backend.BackendSystem;
import terminal.common.ByteUtil;
import terminal.common.CardComm;
import terminal.common.CryptoUtil;
import terminal.common.ProtocolConstants;
import terminal.common.Result;
import terminal.common.VerboseLogger;

/**
 * Base class for vehicle terminal. This class can be extended to create specific vehicle terminals.
 */
public abstract class VehicleTerminalBase {
    protected final CardComm comm;
    protected final PublicKey masterPublicKey;
    protected final byte[] vehicleId;
    protected short currentSeqNum = 0;
    protected byte[] currentCardId = null;
    protected final List<BackendSystem.AuditEntry> log = new ArrayList<>();

    public VehicleTerminalBase(CardComm comm, PublicKey masterPublicKey, byte[] vehicleId) {
        this.comm = comm;
        this.masterPublicKey = masterPublicKey;
        this.vehicleId = vehicleId;
    }

    /**
     * Start the interactive vehicle terminal menu. This method should be implemented by subclasses to provide specific CLI functionality.
     */
    public abstract void runCLI();

    /**
     * Returns local audit log entries stored on the vehicle terminal.
     *
     * @return immutable view of audit log
     */
    public List<BackendSystem.AuditEntry> getLog() {
        return Collections.unmodifiableList(log);
    }

    /**
     * Sends locally stored log entries to the backend system.
     *
     * @param backend backend instance receiving the logs
     */  
    public void flushLogsToBackend(BackendSystem backend) {
        // Skip re-emitting to the audit file: localAudit already wrote each entry
        // when the event happened. We only need to populate the backend in-memory
        // auditLog so post-rental queries (e.g. backend.getAuditLog(cardId)) see them.
        for (BackendSystem.AuditEntry e : log) {
        backend.appendToAuditLogOnly(e);
        }
        log.clear();
    }
    
    /**
     * Reads the current mileage stored on the smart card.
     *
     * @return current mileage value
     */
    public Result<Short> getMileage() {
        Result<byte[]> r = comm.send(ProtocolConstants.INS_GET_MILEAGE);
        if (!r.success) {
            return Result.fail(r.error);
        }
        return Result.ok(ByteUtil.bytesToShort(r.value, 0));
    }

    /**
     * Get current card state.
     */
    public Result<Byte> getCardState() {
        Result<byte[]> r = comm.send(ProtocolConstants.INS_GET_STATE);
        if (!r.success) {
            return Result.fail(r.error);
        }
        return Result.ok(r.value[0]);
    }

    /**
     * Verify the card is authorized to use this vehicle.
     * Checks vehicleToken (assignment token) and ephemeralVehicleToken (card signs vehicleToken + nonce).
     *
     * @return Result wrapping card public key bytes if authorized; Result.fail
     *         otherwise. Every failure path is buffered to the offline log as
     *         EVENT_VEHICLE_OPEN_FAIL before returning.
     */
    public Result<byte[]> openVehicle() {
        byte[] cardId = null;
        Result<byte[]> idResult = comm.send(ProtocolConstants.INS_GET_CARD_ID);
        if (idResult.success) {
            cardId = idResult.value;
        }

        Result<byte[]> r = doOpenVehicle(cardId);
        if (!r.success) {
            localAudit(BackendSystem.EVENT_VEHICLE_OPEN_FAIL, cardId, null, r.error.getMessage());
        }
        return r;
    }

    /**
     * Return vehicle: send final mileage, get signed receipt, card goes back to
     * ISSUED.
     *
     * @param finalMileage final odometer reading
     * @param cardPkc      card public key bytes (from openVehicle)
     * @return signed receipt bytes: [2B mileage][signature]
     */
    public Result<byte[]> returnVehicle(short finalMileage, byte[] cardPkc) {
        byte[] data = new byte[2];
        data[0] = (byte) ((finalMileage >> 8) & 0xFF);
        data[1] = (byte) (finalMileage & 0xFF);

        VerboseLogger.get().step("return command sent to card");
        Result<byte[]> sendResult = comm.send(ProtocolConstants.INS_RETURN_VEHICLE, data);
        if (!sendResult.success) {
            return Result.fail(sendResult.error);
        }
        byte[] receipt = sendResult.value;
        VerboseLogger.get().step("receipt signature received (" + (receipt.length - 2) + " bytes)");

        // Verify receipt signature: card signed the 2-byte mileage
        int sigLen = receipt.length - 2;
        if (sigLen <= 0) {
            return Result.fail("Return receipt missing signature");
        }
        byte[] mileageBytes = new byte[2];
        System.arraycopy(receipt, 0, mileageBytes, 0, 2);
        byte[] sig = new byte[sigLen];
        System.arraycopy(receipt, 2, sig, 0, sigLen);

        try {
            PublicKey cardPubKey = CryptoUtil.decodePublicKey(cardPkc);
            if (!CryptoUtil.verify(cardPubKey, mileageBytes, sig)) {
                return Result.fail("Return receipt signature invalid");
            }
        } catch (GeneralSecurityException e) {
            return Result.fail("Return receipt verification crypto failure", e);
        }

        return Result.ok(receipt);
    }

    /**
     * Send mileage update to card.
     *
     * @param mileage current odometer reading
     */
    public Result<Void> updateMileage(short mileage) {
        Result<Short> prevResult = getMileage();
        if (!prevResult.success) {
            localAudit(BackendSystem.EVENT_MILEAGE_UPDATE, currentCardId, null,
                "FAILED: read previous mileage: " + prevResult.error.getMessage());
            return Result.fail(prevResult.error);
        }
        short previousMileage = prevResult.value;

        // Mileage should not decrease
        if (mileage < previousMileage) {
            localAudit(BackendSystem.EVENT_MILEAGE_UPDATE, currentCardId, null,
                "FAILED: rollback detected (old=" + previousMileage + ", new=" + mileage + ")");
            return Result.fail("Mileage rollback detected");
        }

        byte[] data = new byte[4];

        data[0] = (byte) ((mileage >> 8) & 0xFF);
        data[1] = (byte) (mileage & 0xFF);
        data[2] = (byte) ((currentSeqNum >> 8) & 0xFF);
        data[3] = (byte) (currentSeqNum & 0xFF);

        VerboseLogger.get().step("mileage update sent to card (new=" + mileage + ")");
        Result<byte[]> sendResult = comm.send(ProtocolConstants.INS_UPDATE_MILEAGE, data);
        if (!sendResult.success) {
            localAudit(BackendSystem.EVENT_MILEAGE_UPDATE, currentCardId, null,
                "FAILED: " + sendResult.error.getMessage());
            return Result.fail(sendResult.error);
        }
        currentSeqNum++;

        localAudit(BackendSystem.EVENT_MILEAGE_UPDATE, currentCardId, null,
            "old=" + previousMileage + ", new=" + mileage);
        return Result.ok();
    }

    private Result<byte[]> doOpenVehicle(byte[] cardId) {
        // Check card is ASSIGNED
        Result<byte[]> stateResult = comm.send(ProtocolConstants.INS_GET_STATE);
        if (!stateResult.success) {
            return Result.fail(stateResult.error);
        }
        byte state = stateResult.value[0];
        if (state != ProtocolConstants.STATE_ASSIGNED) {
            return Result.fail("Card not in ASSIGNED state (state=0x"
                + String.format("%02X", state) + ")");
        }

        // Get assignment token (vehicleToken)
        Result<byte[]> vehicleTokenResult = comm.send(ProtocolConstants.INS_GET_ASSIGNMENT_DATA);
        if (!vehicleTokenResult.success) {
            return Result.fail(vehicleTokenResult.error);
        }
        byte[] vehicleToken = vehicleTokenResult.value;
        VerboseLogger.get().step("vehicleToken read from card (" + vehicleToken.length + " bytes)");

        byte[][] vehicleTokenParts = BackendSystem.parseAssignmentToken(vehicleToken);
        byte[] reqData = vehicleTokenParts[0];
        byte[] reqVehicleToken = vehicleTokenParts[1];
        byte[] pkc = vehicleTokenParts[2];
        byte[] sig = vehicleTokenParts[3];

        // Verify vehicleToken against MPK: verify(MSK, reqVehicleToken || pkc)
        byte[] dataToVerify = ByteUtil.concat(reqVehicleToken, pkc);
        try {
            if (!CryptoUtil.verify(masterPublicKey, dataToVerify, sig)) {
                return Result.fail("Assignment token (vehicleToken) invalid");
            }
        } catch (GeneralSecurityException e) {
            return Result.fail("vehicleToken verification crypto failure", e);
        }
        VerboseLogger.get().step("vehicleToken verified against MPK");

        // Check vehicleId in reqData matches this vehicle
        byte[] assignedVehicleId = Arrays.copyOf(reqData, ProtocolConstants.VEHICLE_ID_LENGTH);
        // Prevent cards assigned to other vehicles from being reused here
        if (!Arrays.equals(assignedVehicleId, this.vehicleId)) {
            return Result.fail("Card not assigned to this vehicle");
        }

        // Verify reqVehicleToken: card signed reqData with skc
        PublicKey cardPubKey;
        try {
            cardPubKey = CryptoUtil.decodePublicKey(pkc);
            if (!CryptoUtil.verify(cardPubKey, reqData, reqVehicleToken)) {
                return Result.fail("Assignment request signature (reqVehicleToken) invalid");
            }
        } catch (GeneralSecurityException e) {
            return Result.fail("reqVehicleToken verification crypto failure", e);
        }

        // Generate vehicle nonce, get card to sign (vehicleToken || vehicleNonce)
        byte[] vehicleNonce = CryptoUtil.generateNonce(ProtocolConstants.NONCE_LENGTH);
        VerboseLogger.get().step("vehicle nonce generated");
        Result<byte[]> ephemeralVehicleTokenResult = comm.send(ProtocolConstants.INS_SIGN_VEHICLE_CHALL, vehicleNonce);
        if (!ephemeralVehicleTokenResult.success) {
            return Result.fail(ephemeralVehicleTokenResult.error);
        }
        byte[] ephemeralVehicleToken = ephemeralVehicleTokenResult.value;
        VerboseLogger.get().step("ephemeralVehicleToken received from card (" + ephemeralVehicleToken.length + " bytes)");

        // Verify ephemeralVehicleToken: card signed (vehicleToken || vehicleNonce) with skc
        byte[] challengeData = ByteUtil.concat(vehicleToken, vehicleNonce);
        try {
            if (!CryptoUtil.verify(cardPubKey, challengeData, ephemeralVehicleToken)) {
                return Result.fail("Vehicle challenge signature (ephemeralVehicleToken) invalid");
            }
        } catch (GeneralSecurityException e) {
            return Result.fail("ephemeralVehicleToken verification crypto failure", e);
        }
        VerboseLogger.get().step("ephemeralVehicleToken verified against pkc");

        currentSeqNum = 0;
        currentCardId = cardId;
        localAudit(BackendSystem.EVENT_VEHICLE_OPENED, cardId, ephemeralVehicleToken, null);
        return Result.ok(pkc);
    }

    // Buffers offline audit + emits to verbose audit stream immediately so the
    // tmux red pane shows vehicle events in real time, not just on flush.
    private void localAudit(String eventType, byte[] cardId, byte[] evidence, String details) {
        log.add(new BackendSystem.AuditEntry(eventType, cardId, vehicleId, evidence, details));
        VerboseLogger.get().audit(eventType, cardId, vehicleId, details);
    }
}