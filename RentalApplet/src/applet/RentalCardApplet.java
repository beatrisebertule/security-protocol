package applet;

import javacard.framework.*;
import static applet.AppletConstants.*;

public class RentalCardApplet extends Applet implements ISO7816 {

  // Package-private so handler classes in this package can access them directly.
  byte state;
  byte[] cardId;
  byte[] customerId;
  byte[] assignedVehicleId;
  byte[] rentalPeriod;
  byte[] expiryDate;
  int mileage;
  short mileageSeqNum;
  short counter;

  CryptoUtil crypto;
  PinManager pin;

  // Transient session flags: [0]=terminalAuthenticated, [1]=pinVerified
  boolean[] sessionFlags;
  static final byte FLAG_TERMINAL_AUTH = 0;
  static final byte FLAG_PIN_VERIFIED = 1;

  private final PersonalizationHandler personalizationHandler;
  private final VehicleHandler vehicleHandler;
  private final AdminHandler adminHandler;

  private RentalCardApplet() {
    // Card starts with the blank state before becoming personalized.
    state = STATE_BLANK;
    cardId = new byte[CARD_ID_LENGTH];
    customerId = new byte[CUSTOMER_ID_LENGTH];
    assignedVehicleId = new byte[VEHICLE_ID_LENGTH];
    rentalPeriod = new byte[RENTAL_PERIOD_LENGTH];
    expiryDate = new byte[EXPIRY_DATE_LENGTH];
    mileage = 0;
    mileageSeqNum = 0;
    counter = 0;

    crypto = new CryptoUtil();
    pin = new PinManager();

    sessionFlags = JCSystem.makeTransientBooleanArray((short) 2, JCSystem.CLEAR_ON_DESELECT);

    personalizationHandler = new PersonalizationHandler(this);
    vehicleHandler = new VehicleHandler(this);
    adminHandler = new AdminHandler(this);

    register();
  }

  public static void install(byte[] buffer, short offset, byte length) {
    new RentalCardApplet();
  }

  public boolean select() {
    sessionFlags[FLAG_TERMINAL_AUTH] = false;
    sessionFlags[FLAG_PIN_VERIFIED] = false;
    return true;
  }

  public void process(APDU apdu) {
    // The SELECT APDU triggers both select() and process(). selectingApplet() is
    // true only during that SELECT call; we return early since select() already
    // reset session state and there is nothing else to do.
    if (selectingApplet()) {
      return;
    }

    byte[] buf = apdu.getBuffer();
    if (buf[OFFSET_CLA] != CLA_RENTAL) {
      ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }
    byte ins = buf[OFFSET_INS];

    rejectIfTerminated(ins);
    dispatch(ins, apdu);
  }

  private void rejectIfTerminated(byte ins) {
    if (state == STATE_BLOCKED && ins != INS_GET_STATE) {
      ISOException.throwIt(SW_CARD_BLOCKED);
    }
    if (state == STATE_END_OF_LIFE && ins != INS_GET_STATE) {
      ISOException.throwIt(SW_CARD_EXPIRED);
    }
  }

  /**
   * Routes an incoming APDU to the correct handler based on the INS byte.
   *
   * @param ins  instruction byte from the APDU header
   * @param apdu the incoming APDU
   */
  private void dispatch(byte ins, APDU apdu) {
    switch (ins) {

      case INS_PERSONALIZE_KEYS:
      case INS_PERSONALIZE_PIN:
      case INS_PERSONALIZE_FINISH:
      case INS_ISSUE_CARD:
        personalizationHandler.handle(ins, apdu);
        break;

      case INS_GET_NONCE:
      case INS_VERIFY_TERMINAL_SIG:
      case INS_VERIFY_PIN:
      case INS_SIGN_NONCE:
      case INS_GET_CERTIFICATE:
        handleAuthentication(ins, apdu);
        break;

      case INS_SIGN_VEHICLE_REQ:
      case INS_STORE_ASSIGNMENT:
      case INS_GET_ASSIGNMENT_DATA:
      case INS_SIGN_VEHICLE_CHALL:
      case INS_UPDATE_MILEAGE:
      case INS_GET_MILEAGE:
      case INS_RETURN_VEHICLE:
        vehicleHandler.handle(ins, apdu);
        break;

      case INS_GET_STATE:
      case INS_GET_CARD_ID:
      case INS_BLOCK_CARD:
      case INS_CLEAR_MILEAGE:
      case INS_CHECK_EXPIRY:
        adminHandler.handle(ins, apdu);
        break;

      default:
        ISOException.throwIt(SW_INS_NOT_SUPPORTED);
    }
  }

  // Authentication handlers stay here since they directly manage sessionFlags and counter.

  private void handleAuthentication(byte ins, APDU apdu) {
    switch (ins) {
      case INS_GET_NONCE:
        processGetNonce(apdu);
        break;
      case INS_VERIFY_TERMINAL_SIG:
        processVerifyTerminalSig(apdu);
        break;
      case INS_VERIFY_PIN:
        processVerifyPin(apdu);
        break;
      case INS_SIGN_NONCE:
        processSignNonce(apdu);
        break;
      case INS_GET_CERTIFICATE:
        processGetCertificate(apdu);
        break;
    }
  }

  private void processGetNonce(APDU apdu) {
    requireMinState(STATE_ISSUED);
    byte[] buf = apdu.getBuffer();
    short len = crypto.generateNonce(buf, (short) 0);
    JCSystem.beginTransaction();
    counter++;
    JCSystem.commitTransaction();
    apdu.setOutgoingAndSend((short) 0, len);
  }

  private void processVerifyTerminalSig(APDU apdu) {
    requireMinState(STATE_ISSUED);
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    short result = crypto.verifyTerminalSignature(buf, OFFSET_CDATA, bytesRead);
    if (result != (short) 0) {
      ISOException.throwIt(SW_SIGNATURE_INVALID);
    }
    JCSystem.beginTransaction();
    sessionFlags[FLAG_TERMINAL_AUTH] = true;
    JCSystem.commitTransaction();
  }

  private void processVerifyPin(APDU apdu) {
    requireMinState(STATE_ISSUED);
    requireTerminalAuth();
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    // Write the session nonce immediately after the received hash in the APDU
    // buffer (buf[OFFSET_CDATA+bytesRead..]) so PinManager can compute the
    // expected nonce-bound hash without needing a separate allocation.
    short nonceOff = (short) (OFFSET_CDATA + bytesRead);
    crypto.getLastNonce(buf, nonceOff);
    pin.verify(buf, nonceOff, NONCE_LENGTH, buf, OFFSET_CDATA, bytesRead);
    JCSystem.beginTransaction();
    sessionFlags[FLAG_PIN_VERIFIED] = true;
    JCSystem.commitTransaction();
  }

  private void processSignNonce(APDU apdu) {
    requireMinState(STATE_ISSUED);
    requireFullAuth();
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    if (bytesRead != NONCE_LENGTH) {
      ISOException.throwIt(SW_WRONG_LENGTH);
    }
    short respLen = crypto.signNonceWithCert(buf, OFFSET_CDATA, bytesRead, buf, (short) 0);
    apdu.setOutgoingAndSend((short) 0, respLen);
  }

  private void processGetCertificate(APDU apdu) {
    requireMinState(STATE_ISSUED);
    requireTerminalAuth();
    byte[] buf = apdu.getBuffer();
    short len = crypto.getCertificate(buf, (short) 0);
    apdu.setOutgoingAndSend((short) 0, len);
  }

  // Package-private helpers used by all handler classes.

  void requireState(byte required) {
    if (state != required)
      ISOException.throwIt(SW_WRONG_STATE);
  }

  void requireMinState(byte minState) {
    if (state < minState)
      ISOException.throwIt(SW_WRONG_STATE);
  }

  void requireTerminalAuth() {
    if (!sessionFlags[FLAG_TERMINAL_AUTH]) {
      ISOException.throwIt(SW_AUTH_REQUIRED);
    }
  }

  void requireFullAuth() {
    if (!sessionFlags[FLAG_TERMINAL_AUTH] || !sessionFlags[FLAG_PIN_VERIFIED]) {
      ISOException.throwIt(SW_AUTH_REQUIRED);
    }
  }
}
