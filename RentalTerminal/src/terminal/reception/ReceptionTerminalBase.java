package terminal.reception;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;

import terminal.backend.BackendSystem;
import terminal.backend.Vehicle;
import terminal.common.CardComm;
import terminal.common.CryptoUtil;
import terminal.common.ByteUtil;
import terminal.common.ProtocolConstants;

/**
 * Abstract base for reception terminals: provides shared protocol logic and
 * defines UI extension points for different implementations (CLI, web, etc).
 */
public abstract class ReceptionTerminalBase {
  protected final CardComm comm;
  protected final BackendSystem backend;

  public ReceptionTerminalBase(CardComm comm, BackendSystem backend) {
    this.comm = comm;
    this.backend = backend;
  }

  // --- UI Extension Points ---

  /**
   * Display main menu and return next action. Implemented by UI (CLI, web, etc).
   */
  protected abstract void showMainMenu();

  /**
   * Display a list of available vehicles to the user. Implemented by UI.
   */
  protected abstract void showAvailableVehicles(List<Vehicle> vehicles);

  /**
   * Let user choose a vehicle from the available list. Return null if cancelled.
   */
  protected abstract Vehicle chooseVehicle(List<Vehicle> vehicles);

  /**
   * Let user enter a customer ID (or return associated customer). Implemented by UI.
   * @return 4-byte customer ID, or null if cancelled
   */
  protected abstract byte[] getCustomerId();

  /**
   * Display a message to the user.
   */
  protected abstract void showMessage(String message);

  /**
   * Display an error message to the user.
   */
  protected abstract void showError(String message);

  // --- Shared helpers ---

  protected List<Vehicle> getAvailableVehicles() {
    return backend.getAvailableVehicles();
  }

  public byte[] getCardNonce() throws Exception {
    return comm.sendCommandChecked(ProtocolConstants.INS_GET_NONCE);
  }

  public void verifyTerminalToCard(byte[] cardNonce) throws Exception {
    KeyPair termKP = backend.getTerminalKeyPair();
    byte[] termCert = backend.getTerminalCertificate();

    byte[] termSig = CryptoUtil.sign(termKP.getPrivate(), cardNonce);
    byte[] payload = new byte[1 + termSig.length + termCert.length];
    payload[0] = (byte) termSig.length;
    System.arraycopy(termSig, 0, payload, 1, termSig.length);
    System.arraycopy(termCert, 0, payload, 1 + termSig.length, termCert.length);

    comm.sendCommandChecked(ProtocolConstants.INS_VERIFY_TERMINAL_SIG, payload);
  }

  public void verifyPin(String pin) throws Exception {
    byte[] pinHash = CryptoUtil.hashPin(pin);
    comm.sendCommandChecked(ProtocolConstants.INS_VERIFY_PIN, pinHash);
  }

  protected byte[] verifyCardToTerminal() throws Exception {
    byte[] termNonce = CryptoUtil.generateNonce(ProtocolConstants.NONCE_LENGTH);
    byte[] resp = comm.sendCommandChecked(ProtocolConstants.INS_SIGN_NONCE, termNonce);

    int sigLen = resp[0] & 0xFF;
    byte[] cardSig = new byte[sigLen];
    System.arraycopy(resp, 1, cardSig, 0, sigLen);
    byte[] cardCert = new byte[resp.length - 1 - sigLen];
    System.arraycopy(resp, 1 + sigLen, cardCert, 0, cardCert.length);

    PublicKey mpk = backend.getMasterPublicKey();
    if (!CryptoUtil.verifyCertificate(cardCert, mpk)) {
      throw new SecurityException("Card certificate verification failed");
    }

    PublicKey cardPubKey = CryptoUtil.extractPublicKeyFromCert(cardCert);
    if (!CryptoUtil.verify(cardPubKey, termNonce, cardSig)) {
      throw new SecurityException("Card signature verification failed");
    }

    return CryptoUtil.encodeECPublicKey(cardPubKey);
  }

  protected byte[] getCardId() {
    try {
      return comm.sendCommandChecked(ProtocolConstants.INS_GET_CARD_ID);
    } catch (Exception e) {
      return null;
    }
  }

  public byte[] mutualAuth(String pin) throws Exception {
    byte[] cardId = getCardId();
    try {
      byte[] cardNonce = getCardNonce();
      verifyTerminalToCard(cardNonce);
      verifyPin(pin);
      byte[] cardPkc = verifyCardToTerminal();
      backend.logEvent(BackendSystem.EVENT_AUTH_SUCCESS, cardId, null, cardPkc, null);
      return cardPkc;
    } catch (Exception e) {
      backend.logEvent(BackendSystem.EVENT_AUTH_FAIL, cardId, null, null, e.getMessage());
      throw e;
    }
  }

  public void assignVehicle(byte[] vehicleId, byte[] customerId, byte[] cardPkc,
      byte[] period) throws Exception {
    byte[] nonce = CryptoUtil.generateNonce(ProtocolConstants.NONCE_LENGTH);
    byte[] reqData = ByteUtil.concat(vehicleId, nonce, period);
    byte[] sigma3 = comm.sendCommandChecked(ProtocolConstants.INS_SIGN_VEHICLE_REQ, reqData);

    byte[] sigma4 = backend.signAssignmentToken(sigma3, cardPkc);
    comm.sendCommandChecked(ProtocolConstants.INS_STORE_ASSIGNMENT, sigma4);

    backend.assignVehicle(vehicleId, customerId);

    byte[] cardId = getCardId();
    backend.logEvent(BackendSystem.EVENT_VEHICLE_ASSIGNED, cardId, vehicleId, sigma4, null);
  }

  public int processMileagePayment(byte[] customerId) throws Exception {
    byte[] mileageData = comm.sendCommandChecked(ProtocolConstants.INS_GET_MILEAGE);
    int mileage = ByteUtil.bytesToShort(mileageData, 0) & 0xFFFF;

    if (mileage > 0) {
      backend.addMileageToCustomer(customerId, mileage);
      backend.processPayment(customerId);
      comm.sendCommandChecked(ProtocolConstants.INS_CLEAR_MILEAGE);
      byte[] cardId = getCardId();
      backend.logEvent(BackendSystem.EVENT_PAYMENT, cardId, null, null, "mileage=" + mileage);
    }

    return mileage;
  }

  public byte getCardState() throws Exception {
    return comm.sendCommandChecked(ProtocolConstants.INS_GET_STATE)[0];
  }

  // --- Shared workflow template methods ---

  /**
   * Orchestrate vehicle selection flow using UI-specific implementations.
   * @param cardPkc card public key (from prior mutualAuth)
   */
  protected void vehicleSelection(byte[] cardPkc) {
    try {
      List<Vehicle> available = getAvailableVehicles();
      if (available.isEmpty()) {
        showMessage("No vehicles available.");
        return;
      }
      showAvailableVehicles(available);
      Vehicle selected = chooseVehicle(available);
      if (selected == null) {
        showMessage("Vehicle selection cancelled.");
        return;
      }
      byte[] customerId = getCustomerId();
      if (customerId == null) {
        showMessage("Customer ID entry cancelled.");
        return;
      }
      // Use current time as rental period start, +7 days as end
      long now = System.currentTimeMillis() / 1000;
      long end = now + 7 * 24 * 3600;
      byte[] period = new byte[8];
      period[0] = (byte) ((now >> 24) & 0xFF);
      period[1] = (byte) ((now >> 16) & 0xFF);
      period[2] = (byte) ((now >> 8) & 0xFF);
      period[3] = (byte) (now & 0xFF);
      period[4] = (byte) ((end >> 24) & 0xFF);
      period[5] = (byte) ((end >> 16) & 0xFF);
      period[6] = (byte) ((end >> 8) & 0xFF);
      period[7] = (byte) (end & 0xFF);
      assignVehicle(selected.getId(), customerId, cardPkc, period);
      showMessage("Vehicle assigned: " + selected.getPlate());
    } catch (Exception e) {
      showError("Assignment failed: " + e.getMessage());
    }
  }

  /**
   * Orchestrate payment flow using UI-specific implementations.
   */
  protected void paymentFlow() {
    try {
      byte[] customerId = getCustomerId();
      if (customerId == null) {
        showMessage("Payment cancelled.");
        return;
      }
      int mileage = processMileagePayment(customerId);
      showMessage("Payment processed. Mileage: " + mileage + " km");
    } catch (Exception e) {
      showError("Payment failed: " + e.getMessage());
    }
  }

  /**
   * Helper: format card state byte to string.
   */
  protected String stateToString(byte state) {
    switch (state) {
      case ProtocolConstants.STATE_BLANK:
        return "BLANK";
      case ProtocolConstants.STATE_PERSONALIZED:
        return "PERSONALIZED";
      case ProtocolConstants.STATE_ISSUED:
        return "ISSUED";
      case ProtocolConstants.STATE_ASSIGNED:
        return "ASSIGNED";
      case ProtocolConstants.STATE_BLOCKED:
        return "BLOCKED";
      default:
        return "UNKNOWN(0x" + String.format("%02X", state) + ")";
    }
  }
}
