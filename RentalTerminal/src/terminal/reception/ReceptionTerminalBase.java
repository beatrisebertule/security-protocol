package terminal.reception;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.List;
import java.security.SecureRandom;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import terminal.TerminalBase;
import terminal.backend.BackendSystem;
import terminal.backend.Customer;
import terminal.backend.Vehicle;
import terminal.util.CardComm;
import terminal.util.CryptoUtil;
import terminal.util.ByteUtil;
import terminal.util.ProtocolConstants;
import terminal.logging.LocalAuditLog;
import terminal.logging.Result;
import terminal.logging.messages.ReceptionMessages;

/**
 * Abstract base for reception terminals: provides shared protocol logic and
 * defines UI extension points for different implementations (CLI, web, etc).
 */
public abstract class ReceptionTerminalBase extends TerminalBase {
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  public final BackendSystem backend;
  public final LocalAuditLog auditLog = new LocalAuditLog();
  // Daemon thread: JVM won't wait for this thread to finish before exiting.
  // Without this, the JVM hangs after main() returns (e.g. in tests) until the
  // 60s schedule fires and the thread dies on its own.
  private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
    Thread t = new Thread(r, "audit-flush");
    t.setDaemon(true);
    return t;
  });

  public ReceptionTerminalBase(CardComm comm, BackendSystem backend) {
    super(comm);
    this.backend = backend;
    int interval = ProtocolConstants.AUDIT_FLUSH_INTERVAL_SECONDS;
    scheduler.scheduleAtFixedRate(() -> auditLog.flushToBackend(backend), interval, interval, TimeUnit.SECONDS);
  }

  /**
   * Stops the periodic flush scheduler and performs a final flush of any
   * buffered audit entries. This must be called when the terminal is going offline so no
   * events are lost between the last scheduled flush and shutdown.
   */
  public void shutdown() {
    scheduler.shutdown();
    auditLog.flushToBackend(backend);
  }

  //  UI Extension Points

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
   * Let user enter a customer ID (or return associated customer). Implemented by
   * UI.
   *
   * @return 4-byte customer ID, or null if cancelled
   */
  protected abstract byte[] getCustomerId();

  /**
   * Let user choose a payment method. Returns "cash" or "card". Implemented by UI.
   */
  protected abstract String choosePaymentMethod();

  //  Shared helpers

  /**
   * Return available vehicles from the backend.
   *
   * @return list of available vehicles
   */
  protected List<Vehicle> getAvailableVehicles() {
    return backend.getAvailableVehicles();
  }

  /**
   * Request a fresh nonce from the smart-card for terminal authentication.
   *
   * @return nonce bytes if successful
   */
  public Result<byte[]> getCardNonce() {
    return comm.send(ProtocolConstants.INS_GET_NONCE);
  }

  /**
   * Authenticate the reception terminal to the smart-card.
   *
   * @param cardNonce nonce provided by the smart-card
   * @return success if terminal authentication succeeds
   */
  public Result<Void> verifyTerminalToCard(byte[] cardNonce) {
    return sendTerminalAuth(cardNonce, backend.getTerminalKeyPair(), backend.getTerminalCertificate());
  }

  /**
   * Verify the provided customer PIN by hashing it and sending the result to the
   * card for authentication.
   *
   * @param pin plain-text customer PIN code
   * @param sessionNonce nonce from the card for session binding
   * @return success if the card accepts the PIN hash
   */
  public Result<Void> verifyPin(String pin, byte[] sessionNonce) {
    return sendPinVerification(pin, sessionNonce);
  }

  /**
   * Authenticate the smart-card to the terminal by sending a fresh nonce,
   * receiving the signed response, and verifying the card certificate and
   * signature against the master public key.
   *
   * @return the encoded card public key if verification succeeds
   */
  protected Result<byte[]> verifyCardToTerminal() {
    // generate nonce
    byte[] termNonce = CryptoUtil.generateNonce(ProtocolConstants.NONCE_LENGTH);
    // send nonce to the smart-card, process = INS_SIGN_NONCE
    Result<byte[]> r = comm.send(ProtocolConstants.INS_SIGN_NONCE, termNonce);
    if (!r.success)
      return Result.fail(r.error);
    byte[] resp = r.value;

    int sigLen = ((resp[0] & 0xFF) << 8) | (resp[1] & 0xFF);
    byte[] cardSig = new byte[sigLen];
    System.arraycopy(resp, 2, cardSig, 0, sigLen);
    byte[] cardCert = new byte[resp.length - 2 - sigLen];
    System.arraycopy(resp, 2 + sigLen, cardCert, 0, cardCert.length);

    // verify the certificate with the master public key
    PublicKey mpk = backend.getMasterPublicKey();
    try {
      if (!CryptoUtil.verifyCertificate(cardCert, mpk)) {
        return Result.fail(ReceptionMessages.ERR_CARD_CERT_VERIFICATION);
      }
    } catch (GeneralSecurityException e) {
      return Result.fail(ReceptionMessages.ERR_CARD_CERT_VERIFICATION, e);
    }

    // verify signature of teh signed nonce
    PublicKey cardPubKey;
    try {
      cardPubKey = CryptoUtil.extractPublicKeyFromCert(cardCert);
    } catch (GeneralSecurityException e) {
      return Result.fail(ReceptionMessages.ERR_CARD_SIG_VERIFICATION, e);
    }
    try {
      if (!CryptoUtil.verify(cardPubKey, termNonce, cardSig)) {
        return Result.fail(ReceptionMessages.ERR_CARD_SIG_VERIFICATION);
      }
    } catch (GeneralSecurityException e) {
      return Result.fail(ReceptionMessages.ERR_CARD_SIG_VERIFICATION, e);
    }
    return Result.ok(CryptoUtil.encodePublicKey(cardPubKey));
  }

  /**
   * Best-effort card ID lookup for audit logging. Returns null on any
   * failure (card not personalized, transmit error) - audit entries are
   * still written, just with cardId=null.
   *
   * @return card ID bytes if available, otherwise null
   */
  protected byte[] getCardId() {
    Result<byte[]> r = comm.send(ProtocolConstants.INS_GET_CARD_ID);
    return r.success ? r.value : null;
  }

  /**
   * Enforce backend blocklist policy for the given card.
   *
   * @param cardId card identifier to check against the backend blocklist
   * @return failure if the card is blocked, success otherwise
   */
  public Result<Void> enforceBlocklist(byte[] cardId) {
    if (backend.isCardBlocked(cardId)) {
      if (cardId != null) {
        try {
          byte[] blockSig = backend.signBlockAuthorization(cardId);
          byte[] payload = new byte[2 + blockSig.length];
          payload[0] = (byte)((blockSig.length >> 8) & 0xFF);
          payload[1] = (byte)(blockSig.length & 0xFF);
          System.arraycopy(blockSig, 0, payload, 2, blockSig.length);
          comm.send(ProtocolConstants.INS_BLOCK_CARD, payload);
        } catch (GeneralSecurityException e) {
          return Result.fail(ReceptionMessages.ERR_CARD_BLOCKED);
        }
      }
      auditLog.record(BackendSystem.EVENT_CARD_BLOCKED, cardId, null, null, "Blocked by backend blocklist");
      return Result.fail(ReceptionMessages.ERR_CARD_BLOCKED);
    }
    return Result.ok();
  }

  /**
   * Perform mutual authentication between the terminal and the card,
   * including terminal authentication, PIN verification, and card authentication.
   *
   * @param pin plain-text customer PIN code to verify on the card
   * @return encoded card public key if mutual authentication succeeds
   */
  public Result<byte[]> mutualAuth(String pin) {
    // Read card's ID for audit logging (done before auth so we can log failures
    // too)
    byte[] cardId = getCardId();

    // STEP 1 & 2: Card generates nonce
    // Card generates a random nonce and sends it to the terminal.
    // Purpose: terminal must sign this nonce to prove it holds the master-trusted
    // private key.
    Result<byte[]> nonceResult = getCardNonce();
    if (!nonceResult.success) {
      auditLog.record(BackendSystem.EVENT_AUTH_FAIL, cardId, null, null, nonceResult.error.getMessage());
      showError("[Auth FAIL] Mutual authentication failed at: " + nonceResult.error.getMessage());
      return Result.fail(nonceResult.error);
    }
    byte[] cardNonce = nonceResult.value;
    log("1-2: Smart-card generated a random nonce and sent it to the reception terminal.");

    // STEP 3-7: Terminal authenticates itself to the card
    // Terminal signs the nonce with its private key (sk_t) and sends back:
    // - sigma_1 = Sign_sk_t(nonce)
    // - C_t = terminal certificate (pk_t signed by master key MPK)
    // Card verifies C_t against MPK (is this terminal trusted by the company?)
    // Card extracts pk_t from C_t, then verifies sigma_1 (did this terminal sign
    // our nonce?)
    // If both pass, the card sets FLAG_TERMINAL_AUTH = true internally.
    Result<Void> termAuthResult = verifyTerminalToCard(cardNonce);
    if (!termAuthResult.success) {
      auditLog.record(BackendSystem.EVENT_AUTH_FAIL, cardId, null, null, termAuthResult.error.getMessage());
      showError("[Auth FAIL] Mutual authentication failed at: " + termAuthResult.error.getMessage());
      return Result.fail(termAuthResult.error);
    }
    log("3-7: Terminal signed the nonce with sk_t and sent sigma_1 + certificate C_t to card.");
    log("5-7: Card verified C_t against MPK and sigma_1 - reception terminal is authentic.");

    // Blocklist check after terminal auth so card accepts INS_BLOCK_CARD
    // (card requires FLAG_TERMINAL_AUTH to execute INS_BLOCK_CARD).
    Result<Void> blockCheck = enforceBlocklist(cardId);
    if (!blockCheck.success) {
      return Result.fail(blockCheck.error);
    }

    // STEP 8-10: Customer authenticates via PIN
    // Terminal hashes the PIN (SHA-256) and sends the hash to the card.
    // Card compares against the hash stored during personalization.
    // On failure: attempt counter decremented; after 3 failures card blocks itself.
    // If correct, card sets FLAG_PIN_VERIFIED = true internally.
    log("8: Sending PIN hash to card for verification.");
    Result<Void> pinResult = verifyPin(pin, cardNonce);
    if (!pinResult.success) {
      auditLog.record(BackendSystem.EVENT_AUTH_FAIL, cardId, null, null, pinResult.error.getMessage());
      showError("[Auth FAIL] Mutual authentication failed at: " + pinResult.error.getMessage());
      return Result.fail(pinResult.error);
    }
    log("9-10: Card verified PIN hash - customer identity confirmed.");

    // STEP 11-16: Card authenticates itself to the terminal
    // Terminal generates its own fresh nonce and sends it to the card.
    // Card signs it with its private key (sk_c) and sends back:
    // - sigma_2 = Sign_sk_c(nonce)
    // - C_c = card certificate (pk_c signed by master key MPK)
    // Terminal verifies C_c against MPK
    // Terminal extracts pk_c from C_c, then verifies sigma_2 (did this card sign
    // our nonce?)
    // Returns pk_c (card's public key) for use in vehicle assignment later.
    log("11-12: Terminal generated a nonce and sent it to the card.");
    Result<byte[]> cardAuthResult = verifyCardToTerminal();
    if (!cardAuthResult.success) {
      auditLog.record(BackendSystem.EVENT_AUTH_FAIL, cardId, null, null, cardAuthResult.error.getMessage());
      showError("[Auth FAIL] Mutual authentication failed at: " + cardAuthResult.error.getMessage());
      return Result.fail(cardAuthResult.error);
    }
    byte[] cardPkc = cardAuthResult.value;
    log("13-14: Card signed nonce with sk_c and sent sigma_2 + certificate C_c to terminal.");
    log("15-16: Terminal verified C_c against MPK and sigma_2 - smart-card is authentic.");

    // Mutual authentication complete — both sides have proven their identity.
    // cardPkc is returned to the caller for use in vehicle assignment
    // (reqVehicleToken/vehicleToken flow).
    auditLog.record(BackendSystem.EVENT_AUTH_SUCCESS, cardId, null, cardPkc, null);
    showMessage("[Auth OK] Mutual authentication successful. Both terminal and card are verified.");
    return Result.ok(cardPkc);
  }

  /**
   * Execute the vehicle assignment protocol, sending the card request data to the
   * card, obtaining a backend-signed assignment token, and storing it on the card.
   *
   * @param vehicleId vehicle identifier to assign
   * @param customerId customer identifier linked to the card
   * @param cardPkc encoded card public key returned from mutual authentication
   * @param period rental period bytes to store on the card
   * @return success if the assignment completes successfully
   */
  public Result<Void> assignVehicle(byte[] vehicleId, byte[] customerId, byte[] cardPkc,
      byte[] period) {
    byte[] cardId = getCardId();
    byte[] nonce = CryptoUtil.generateNonce(ProtocolConstants.NONCE_LENGTH);
    byte[] reqData = ByteUtil.concat(vehicleId, nonce, period);

    log("Sigma3: sent vehicle request (vehicleId + nonce + period) to card for signing.");
    Result<byte[]> reqVehicleTokenResult = comm.send(ProtocolConstants.INS_SIGN_VEHICLE_REQ, reqData);
    if (!reqVehicleTokenResult.success) {
      auditLog.record(BackendSystem.EVENT_VEHICLE_ASSIGNED, cardId, vehicleId, null,
          "FAILED: " + reqVehicleTokenResult.error.getMessage());
      return Result.fail(reqVehicleTokenResult.error);
    }
    byte[] reqVehicleToken = reqVehicleTokenResult.value;
    log("Sigma3: received card signature (reqVehicleToken) over vehicle request.");

    byte[] vehicleToken;
    try {
      vehicleToken = backend.signAssignmentToken(reqData, reqVehicleToken, cardPkc);
    } catch (GeneralSecurityException e) {
      auditLog.record(BackendSystem.EVENT_VEHICLE_ASSIGNED, cardId, vehicleId, null,
          "FAILED: assignment token signing failed");
      return Result.fail(ReceptionMessages.ERR_ASSIGNMENT_TOKEN_SIGNING, e);
    }
    log("Sigma4: backend signed (reqVehicleToken + pkc) to produce assignment token vehicleToken.");

    log("Sigma4: sending assignment token to card for storage.");
    Result<byte[]> storeResult = comm.send(ProtocolConstants.INS_STORE_ASSIGNMENT, vehicleToken);
    if (!storeResult.success) {
      auditLog.record(BackendSystem.EVENT_VEHICLE_ASSIGNED, cardId, vehicleId, null,
          "FAILED: " + storeResult.error.getMessage());
      return Result.fail(storeResult.error);
    }
    log("Sigma4: assignment token stored on card - vehicle assigned.");

    backend.assignVehicle(vehicleId, customerId);

    auditLog.record(BackendSystem.EVENT_VEHICLE_ASSIGNED, cardId, vehicleId, vehicleToken, null);
    return Result.ok();
  }

  /**
   * Request current mileage from the card, process payment for that mileage,
   * and clear the mileage on the card if payment succeeds.
   *
   * @param customerId customer identifier used for backend payment processing
   * @return mileage value paid for, or failure if the payment process fails
   */
  public Result<Integer> processMileagePayment(byte[] customerId) {
    log("Payment: requesting mileage from card.");
    Result<byte[]> mileageResult = comm.send(ProtocolConstants.INS_GET_MILEAGE);
    if (!mileageResult.success) {
      byte[] cardId = getCardId();
      auditLog.record(BackendSystem.EVENT_PAYMENT, cardId, null, null, "FAILED: " + mileageResult.error.getMessage());
      return Result.fail(mileageResult.error);
    }
    int mileage = ByteUtil.bytesToInt(mileageResult.value, 0);
    log("Payment: received mileage from card: " + mileage + " km.");

    if (mileage > 0) {
      if (SECURE_RANDOM.nextInt(10) + 1 == 1) {
        return Result.fail(ReceptionMessages.ERR_INSUFFICIENT_BALANCE);
      }
      backend.addMileageToCustomer(customerId, mileage);
      backend.processPayment(customerId);
      log("Payment: computed and processed payment for " + mileage + " km.");

      log("Payment: clearing mileage on card.");
      Result<byte[]> clearResult = comm.send(ProtocolConstants.INS_CLEAR_MILEAGE);
      if (!clearResult.success) {
        byte[] cardId = getCardId();
        // Payment charged but card clear failed. Log for manual reconciliation;
        // do NOT return failure to the caller — the backend charge stands and
        // re-running this method would double-charge the customer.
        auditLog.record(BackendSystem.EVENT_PAYMENT, cardId, null, null,
            "RECONCILE_NEEDED: payment charged but card clear failed: "
            + clearResult.error.getMessage());
        return Result.ok(mileage);
      }
      log("Payment: mileage cleared on card.");

      byte[] cardId = getCardId();
      auditLog.record(BackendSystem.EVENT_PAYMENT, cardId, null, null, "mileage=" + mileage);
    }

    return Result.ok(mileage);
  }


  //  Shared workflow template methods 

  /**
   * Orchestrate vehicle selection flow using UI-specific implementations.
   *
   * @param cardPkc card public key (from prior mutualAuth)
   */
  protected void vehicleSelection(byte[] cardPkc) {
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
    Result<Void> assignResult = assignVehicle(selected.getId(), customerId, cardPkc, period);
    if (!assignResult.success) {
      showError("Assignment failed: " + assignResult.error.getMessage());
      return;
    }
    showMessage("Vehicle assigned: " + selected.getPlate());
  }

  /**
   * Orchestrate vehicle return: read mileage, choose payment method, charge
   * backend, then transition card back to ISSUED via INS_RETURN_VEHICLE.
   */
  public void returnVehicleFlow() {
    byte[] cardId = getCardId();
    Customer customer = backend.getCustomerByCardId(cardId);
    if (customer == null) {
      showError("No customer found for this card.");
      return;
    }
    byte[] customerId = customer.getId();

    Result<byte[]> mileageResult = comm.send(ProtocolConstants.INS_GET_MILEAGE);
    if (!mileageResult.success) {
      auditLog.record(BackendSystem.EVENT_PAYMENT_FAIL, cardId, null, null,
          "mileage read failed: " + mileageResult.error.getMessage());
      backend.logEvent(BackendSystem.EVENT_PAYMENT_FAIL, cardId, null, null,
          "customerId=" + ByteUtil.toHex(customerId) + " mileage read failed");
      showError("Failed to read mileage: " + mileageResult.error.getMessage());
      return;
    }
    int mileage = ByteUtil.bytesToShort(mileageResult.value, 0) & 0xFFFF;
    showMessage("Total mileage: " + mileage + " km");

    String method = choosePaymentMethod();
    showMessage("Processing " + method + " payment...");

    if (mileage > 0) {
      backend.addMileageToCustomer(customerId, mileage);
      backend.processPayment(customerId);
    }

    byte[] mileageBytes = new byte[]{(byte)((mileage >> 8) & 0xFF), (byte)(mileage & 0xFF)};
    Result<byte[]> returnResult = comm.send(ProtocolConstants.INS_RETURN_VEHICLE, mileageBytes);
    if (!returnResult.success) {
      auditLog.record(BackendSystem.EVENT_PAYMENT_FAIL, cardId, null, null,
          "card return failed: " + returnResult.error.getMessage());
      backend.logEvent(BackendSystem.EVENT_PAYMENT_FAIL, cardId, null, null,
          "customerId=" + ByteUtil.toHex(customerId) + " method=" + method + " mileage=" + mileage);
      showError("Card return failed: " + returnResult.error.getMessage());
      return;
    }

    Result<byte[]> clearResult = comm.send(ProtocolConstants.INS_CLEAR_MILEAGE);
    if (!clearResult.success) {
      // Card is already ISSUED and payment charged — log for reconciliation, don't fail.
      auditLog.record(BackendSystem.EVENT_PAYMENT, cardId, null, null,
          "RECONCILE_NEEDED: mileage clear failed after payment: " + clearResult.error.getMessage());
    }

    auditLog.record(BackendSystem.EVENT_PAYMENT, cardId, null, null,
        "mileage=" + mileage + " method=" + method);
    backend.logEvent(BackendSystem.EVENT_PAYMENT, cardId, null, null,
        "customerId=" + ByteUtil.toHex(customerId) + " method=" + method + " mileage=" + mileage);
    showMessage("Vehicle returned. Payment processed (" + method + "). Card reset to ISSUED.");
  }

  /**
   * Orchestrate payment flow using UI-specific implementations.
   */
  protected void paymentFlow() {
    byte[] customerId = getCustomerId();
    if (customerId == null) {
      showMessage("Payment cancelled.");
      return;
    }
    Result<Integer> payResult = processMileagePayment(customerId);
    if (!payResult.success) {
      showError("Payment failed: " + payResult.error.getMessage());
      return;
    }
    showMessage("Payment processed. Mileage: " + payResult.value + " km");
  }

  /**
   * Convert a card state byte into a human-readable string.
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
