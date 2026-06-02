package applet;

import javacard.framework.*;
import static applet.AppletConstants.*;
import static javacard.framework.ISO7816.*;

/**
 * Handles admin APDUs: state query, card ID read, block, expiry check,
 * and mileage reset (INS 0x70-0x74).
 */
class AdminHandler {

  private final RentalCardApplet applet;

  AdminHandler(RentalCardApplet applet) {
    this.applet = applet;
  }

  void handle(byte ins, APDU apdu) {
    switch (ins) {
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
    }
  }

  private void processGetState(APDU apdu) {
    byte[] buf = apdu.getBuffer();
    buf[0] = applet.state;
    apdu.setOutgoingAndSend((short) 0, (short) 1);
  }

  // Handles INS_GET_CARD_ID: the terminal sends this to read the card's ID so it
  // can look up the corresponding customer record in the backend.
  private void processGetCardId(APDU apdu) {
    applet.requireMinState(STATE_PERSONALIZED);
    byte[] buf = apdu.getBuffer();
    Util.arrayCopy(applet.cardId, (short) 0, buf, (short) 0, CARD_ID_LENGTH);
    apdu.setOutgoingAndSend((short) 0, CARD_ID_LENGTH);
  }

  /**
   * Handles INS_BLOCK_CARD: verifies a backend-signed authorization
   * (Sign_MSK(cardId || INS_BLOCK_CARD)) and transitions the card to BLOCKED.
   * Only accepted when the terminal has already authenticated.
   *
   * @param apdu the incoming APDU; payload is [2B sigLen][sig]
   */
  private void processBlockCard(APDU apdu) {
    if (applet.state != STATE_ISSUED && applet.state != STATE_ASSIGNED) {
      ISOException.throwIt(SW_WRONG_STATE);
    }
    if (!applet.sessionFlags[RentalCardApplet.FLAG_TERMINAL_AUTH]) {
      ISOException.throwIt(SW_AUTH_REQUIRED);
    }
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    if (bytesRead < 2) {
      ISOException.throwIt(SW_WRONG_LENGTH);
    }
    short sigLen = Util.getShort(buf, OFFSET_CDATA);
    short sigOff = (short) (OFFSET_CDATA + 2);
    if (!applet.crypto.verifyBlockAuthorization(applet.cardId, (short) 0, CARD_ID_LENGTH, buf, sigOff, sigLen)) {
      ISOException.throwIt(SW_SIGNATURE_INVALID);
    }
    JCSystem.beginTransaction();
    applet.state = STATE_BLOCKED;
    JCSystem.commitTransaction();
  }

  private void processClearMileage(APDU apdu) {
    applet.requireState(STATE_ISSUED);
    applet.requireFullAuth();
    JCSystem.beginTransaction();
    applet.mileage = 0;
    JCSystem.commitTransaction();
  }

  /**
   * FIXME:  add javadoc
   *
   * @param apdu [TODO:description]
   */
  private void processCheckExpiry(APDU apdu) {
    applet.requireMinState(STATE_ISSUED);
    applet.requireFullAuth();
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    // Payload: [8B timestamp][2B sigLen][sig] — sig is Sign_MSK(timestamp)
    if (bytesRead <= EXPIRY_DATE_LENGTH) {
      ISOException.throwIt(SW_WRONG_LENGTH);
    }
    short tsSigLen = Util.getShort(buf, (short) (OFFSET_CDATA + EXPIRY_DATE_LENGTH));
    short tsSigOff = (short) (OFFSET_CDATA + EXPIRY_DATE_LENGTH + 2);
    if (bytesRead != (short) (EXPIRY_DATE_LENGTH + 2 + tsSigLen)) {
      ISOException.throwIt(SW_WRONG_LENGTH);
    }
    if (!applet.crypto.verifyWithMPK(buf, OFFSET_CDATA, EXPIRY_DATE_LENGTH, buf, tsSigOff, tsSigLen)) {
      ISOException.throwIt(SW_SIGNATURE_INVALID);
    }
    if (isExpired(buf, OFFSET_CDATA)) {
      JCSystem.beginTransaction();
      applet.state = STATE_END_OF_LIFE;
      JCSystem.commitTransaction();
      ISOException.throwIt(SW_CARD_EXPIRED);
    }
  }

  private boolean isExpired(byte[] currentTime, short offset) {
    for (short i = 0; i < EXPIRY_DATE_LENGTH; i++) {
      short e = (short) (applet.expiryDate[i] & 0xFF);
      short c = (short) (currentTime[(short) (offset + i)] & 0xFF);
      if (e != c) {
        return e < c;
      }
    }
    return false;
  }
}
