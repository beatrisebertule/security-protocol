package applet;

import javacard.framework.*;

public class RentalCardApplet extends Applet implements ISO7816, AppletConstants {

  private byte state;
  private byte[] cardId;
  private byte[] customerId;
  private byte[] assignedVehicleId;
  private byte[] rentalPeriod;
  private byte[] expiryDate;
  private short mileage;
  private short mileageSeqNum;
  private short counter;

  private CryptoManager crypto;
  private PinManager pin;

  // Transient session flags: [0]=terminalAuthenticated, [1]=pinVerified
  private boolean[] sessionFlags;
  private static final byte FLAG_TERMINAL_AUTH = 0;
  private static final byte FLAG_PIN_VERIFIED = 1;

  private RentalCardApplet() {
    state = STATE_BLANK;
    cardId = new byte[CARD_ID_LENGTH];
    customerId = new byte[CUSTOMER_ID_LENGTH];
    assignedVehicleId = new byte[VEHICLE_ID_LENGTH];
    rentalPeriod = new byte[RENTAL_PERIOD_LENGTH];
    expiryDate = new byte[EXPIRY_DATE_LENGTH];
    mileage = 0;
    mileageSeqNum = 0;
    counter = 0;

    crypto = new CryptoManager();
    pin = new PinManager();

    sessionFlags = JCSystem.makeTransientBooleanArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
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
    if (selectingApplet())
      return;

    byte[] buf = apdu.getBuffer();
    byte ins = buf[OFFSET_INS];

    if (state == STATE_BLOCKED && ins != INS_GET_STATE) {
      ISOException.throwIt(SW_CARD_BLOCKED);
    }
    if (state == STATE_END_OF_LIFE && ins != INS_GET_STATE) {
      ISOException.throwIt(SW_CARD_EXPIRED);
    }

    switch (ins) {
      case INS_PERSONALIZE_KEYS:
        processPersonalizeKeys(apdu);
        break;
      case INS_PERSONALIZE_PIN:
        processPersonalizePin(apdu);
        break;
      case INS_PERSONALIZE_FINISH:
        processPersonalizeFinish(apdu);
        break;
      case INS_ISSUE_CARD:
        processIssueCard(apdu);
        break;
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
      case INS_SIGN_VEHICLE_REQ:
        processSignVehicleReq(apdu);
        break;
      case INS_STORE_ASSIGNMENT:
        processStoreAssignment(apdu);
        break;
      case INS_GET_ASSIGNMENT_DATA:
        processGetAssignmentData(apdu);
        break;
      case INS_SIGN_VEHICLE_CHALL:
        processSignVehicleChall(apdu);
        break;
      case INS_UPDATE_MILEAGE:
        processUpdateMileage(apdu);
        break;
      case INS_GET_MILEAGE:
        processGetMileage(apdu);
        break;
      case INS_RETURN_VEHICLE:
        processReturnVehicle(apdu);
        break;
      case INS_GET_STATE:
        processGetState(apdu);
        break;
      case INS_GET_CARD_ID:
        processGetCardId(apdu);
        break;
      case INS_BLOCK_CARD:
        processBlockCard(apdu);
        break;
      case INS_CLEAR_MILEAGE:
        processClearMileage(apdu);
        break;
      case INS_CHECK_EXPIRY:
        processCheckExpiry(apdu);
        break;
      default:
        ISOException.throwIt(SW_INS_NOT_SUPPORTED);
    }
  }

  // --- State enforcement helpers ---

  private void requireState(byte required) {
    if (state != required)
      ISOException.throwIt(SW_WRONG_STATE);
  }

  private void requireMinState(byte minState) {
    if (state < minState)
      ISOException.throwIt(SW_WRONG_STATE);
  }

  private void requireFullAuth() {
    if (!sessionFlags[FLAG_TERMINAL_AUTH] || !sessionFlags[FLAG_PIN_VERIFIED]) {
      ISOException.throwIt(SW_AUTH_REQUIRED);
    }
  }

  // --- Personalization ---

  private void processPersonalizeKeys(APDU apdu) {
    requireState(STATE_BLANK);
    byte[] buf = apdu.getBuffer();
    byte p1 = buf[OFFSET_P1];
    short bytesRead = apdu.setIncomingAndReceive();

    if (p1 == (byte) 0x00) {
      // Install MPK and generate key pair, return pkc
      if (bytesRead != EC_PUB_KEY_LENGTH) {
        ISOException.throwIt(SW_WRONG_LENGTH);
      }
      crypto.setMasterPublicKey(buf, OFFSET_CDATA, (short) bytesRead);
      crypto.generateKeyPair();

      short pubLen = crypto.getPublicKey(buf, (short) 0);
      apdu.setOutgoingAndSend((short) 0, pubLen);
    } else if (p1 == (byte) 0x01) {
      // Store certificate
      crypto.setCertificate(buf, OFFSET_CDATA, bytesRead);
    } else {
      ISOException.throwIt(SW_WRONG_P1P2);
    }
  }

  private void processPersonalizePin(APDU apdu) {
    requireState(STATE_BLANK);
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    pin.setPin(buf, OFFSET_CDATA, bytesRead);
  }

  private void processPersonalizeFinish(APDU apdu) {
    requireState(STATE_BLANK);
    if (!crypto.isKeyPairGenerated() || !crypto.hasCertificate() || !pin.isPinSet()) {
      ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
    }
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    if (bytesRead != (short) (CARD_ID_LENGTH + EXPIRY_DATE_LENGTH)) {
      ISOException.throwIt(SW_WRONG_LENGTH);
    }
    Util.arrayCopy(buf, OFFSET_CDATA, cardId, (short) 0, CARD_ID_LENGTH);
    Util.arrayCopy(buf, (short) (OFFSET_CDATA + CARD_ID_LENGTH), expiryDate, (short) 0, EXPIRY_DATE_LENGTH);
    counter = 0;
    state = STATE_PERSONALIZED;
  }

  private void processIssueCard(APDU apdu) {
    requireState(STATE_PERSONALIZED);
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    if (bytesRead != CUSTOMER_ID_LENGTH) {
      ISOException.throwIt(SW_WRONG_LENGTH);
    }
    Util.arrayCopy(buf, OFFSET_CDATA, customerId, (short) 0, CUSTOMER_ID_LENGTH);
    state = STATE_ISSUED;
  }

  // --- Authentication ---

  private void processGetNonce(APDU apdu) {
    requireMinState(STATE_ISSUED);
    byte[] buf = apdu.getBuffer();
    short len = crypto.generateNonce(buf, (short) 0);
    counter++;
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
    sessionFlags[FLAG_TERMINAL_AUTH] = true;
  }

  private void processVerifyPin(APDU apdu) {
    requireMinState(STATE_ISSUED);
    if (!sessionFlags[FLAG_TERMINAL_AUTH]) {
      ISOException.throwIt(SW_AUTH_REQUIRED);
    }
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    pin.verify(buf, OFFSET_CDATA, bytesRead);
    sessionFlags[FLAG_PIN_VERIFIED] = true;
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
    byte[] buf = apdu.getBuffer();
    short len = crypto.getCertificate(buf, (short) 0);
    apdu.setOutgoingAndSend((short) 0, len);
  }

  // --- Vehicle assignment ---

  private void processSignVehicleReq(APDU apdu) {
    requireState(STATE_ISSUED);
    requireFullAuth();
    // Check no unpaid mileage
    if (mileage > 0) {
      ISOException.throwIt(SW_UNPAID_MILEAGE);
    }
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    short expectedLen = (short) (VEHICLE_ID_LENGTH + NONCE_LENGTH + RENTAL_PERIOD_LENGTH);
    if (bytesRead != expectedLen) {
      ISOException.throwIt(SW_WRONG_LENGTH);
    }
    // Store vehicle ID and rental period
    Util.arrayCopy(buf, OFFSET_CDATA, assignedVehicleId, (short) 0, VEHICLE_ID_LENGTH);
    Util.arrayCopy(buf, (short) (OFFSET_CDATA + VEHICLE_ID_LENGTH + NONCE_LENGTH),
        rentalPeriod, (short) 0, RENTAL_PERIOD_LENGTH);
    // Sign the request data (sigma3)
    short sigLen = crypto.sign(buf, OFFSET_CDATA, bytesRead, buf, (short) 0);
    apdu.setOutgoingAndSend((short) 0, sigLen);
  }

  private void processStoreAssignment(APDU apdu) {
    requireState(STATE_ISSUED);
    requireFullAuth();
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    crypto.setAssignment(buf, OFFSET_CDATA, bytesRead);
    mileageSeqNum = 0;
    state = STATE_ASSIGNED;
  }

  // --- Vehicle access ---

  private void processGetAssignmentData(APDU apdu) {
    requireState(STATE_ASSIGNED);
    if (mileage > 0) {
      ISOException.throwIt(SW_UNPAID_MILEAGE);
    }
    byte[] buf = apdu.getBuffer();
    short len = crypto.getAssignment(buf, (short) 0);
    apdu.setOutgoingAndSend((short) 0, len);
  }

  private void processSignVehicleChall(APDU apdu) {
    requireState(STATE_ASSIGNED);
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    if (bytesRead != NONCE_LENGTH) {
      ISOException.throwIt(SW_WRONG_LENGTH);
    }
    short sigLen = crypto.signVehicleChallenge(buf, OFFSET_CDATA, bytesRead, buf, (short) 0);
    apdu.setOutgoingAndSend((short) 0, sigLen);
  }

  // --- Mileage ---

  private void processUpdateMileage(APDU apdu) {
    requireState(STATE_ASSIGNED);
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    if (bytesRead != 4) {
      ISOException.throwIt(SW_WRONG_LENGTH);
    }
    short newMileage = Util.getShort(buf, OFFSET_CDATA);
    short seq = Util.getShort(buf, (short) (OFFSET_CDATA + 2));
    if (seq != mileageSeqNum) {
      ISOException.throwIt(SW_SEQUENCE_ERROR);
    }
    mileage = newMileage;
    mileageSeqNum++;
  }

  private void processGetMileage(APDU apdu) {
    if (state != STATE_ISSUED && state != STATE_ASSIGNED) {
      ISOException.throwIt(SW_WRONG_STATE);
    }
    byte[] buf = apdu.getBuffer();
    Util.setShort(buf, (short) 0, mileage);
    apdu.setOutgoingAndSend((short) 0, (short) 2);
  }

  // --- Vehicle return ---

  private void processReturnVehicle(APDU apdu) {
    requireState(STATE_ASSIGNED);
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    if (bytesRead != 2) {
      ISOException.throwIt(SW_WRONG_LENGTH);
    }
    short finalMileage = Util.getShort(buf, OFFSET_CDATA);
    mileage = finalMileage;

    // Sign final mileage as receipt
    Util.setShort(buf, (short) 0, finalMileage);
    short sigLen = crypto.sign(buf, (short) 0, (short) 2, buf, (short) 2);

    // Clear assignment
    crypto.clearAssignment();
    Util.arrayFillNonAtomic(assignedVehicleId, (short) 0, VEHICLE_ID_LENGTH, (byte) 0);
    Util.arrayFillNonAtomic(rentalPeriod, (short) 0, RENTAL_PERIOD_LENGTH, (byte) 0);
    mileageSeqNum = 0;

    state = STATE_ISSUED;

    // Return [2B mileage][sigBytes]
    apdu.setOutgoingAndSend((short) 0, (short) (2 + sigLen));
  }

  // --- Admin ---

  private void processCheckExpiry(APDU apdu) {
    requireMinState(STATE_ISSUED);
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    if (bytesRead != EXPIRY_DATE_LENGTH) {
      ISOException.throwIt(SW_WRONG_LENGTH);
    }
    if (isExpired(buf, OFFSET_CDATA)) {
      state = STATE_END_OF_LIFE;
      ISOException.throwIt(SW_CARD_EXPIRED);
    }
  }

  private boolean isExpired(byte[] currentTime, short offset) {
    for (short i = 0; i < EXPIRY_DATE_LENGTH; i++) {
      int e = expiryDate[i] & 0xFF;
      int c = currentTime[(short) (offset + i)] & 0xFF;
      if (e < c)
        return true;
      if (e > c)
        return false;
    }
    return false;
  }

  private void processGetState(APDU apdu) {
    byte[] buf = apdu.getBuffer();
    buf[0] = state;
    apdu.setOutgoingAndSend((short) 0, (short) 1);
  }

  private void processGetCardId(APDU apdu) {
    requireMinState(STATE_PERSONALIZED);
    byte[] buf = apdu.getBuffer();
    Util.arrayCopy(cardId, (short) 0, buf, (short) 0, CARD_ID_LENGTH);
    apdu.setOutgoingAndSend((short) 0, CARD_ID_LENGTH);
  }

  private void processBlockCard(APDU apdu) {
    if (state != STATE_ISSUED && state != STATE_ASSIGNED) {
      ISOException.throwIt(SW_WRONG_STATE);
    }
    state = STATE_BLOCKED;
  }

  private void processClearMileage(APDU apdu) {
    requireState(STATE_ISSUED);
    requireFullAuth();
    mileage = 0;
  }
}
