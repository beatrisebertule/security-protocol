package applet;

import javacard.framework.*;
import static applet.AppletConstants.*;
import static javacard.framework.ISO7816.*;

/**
 * Handles personalization and card issuance APDUs (INS 0x10-0x13).
 * Operates on STATE_BLANK -> STATE_PERSONALIZED -> STATE_ISSUED transitions.
 */
class PersonalizationHandler {

  private final RentalCardApplet applet;

  PersonalizationHandler(RentalCardApplet applet) {
    this.applet = applet;
  }

  void handle(byte ins, APDU apdu) {
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
    }
  }

  private void processPersonalizeKeys(APDU apdu) {
    applet.requireState(STATE_BLANK);
    byte[] buf = apdu.getBuffer();
    byte p1 = buf[OFFSET_P1];
    short bytesRead = apdu.setIncomingAndReceive();

    if (p1 == (byte) 0x00) {
      // P1=0x00: install MPK and generate card key pair; return public key
      if (bytesRead != PUB_KEY_LENGTH) {
        ISOException.throwIt(SW_WRONG_LENGTH);
      }
      JCSystem.beginTransaction();
      applet.crypto.setMasterPublicKey(buf, OFFSET_CDATA, (short) bytesRead);
      applet.crypto.generateKeyPair();
      JCSystem.commitTransaction();

      short pubLen = applet.crypto.getPublicKey(buf, (short) 0);
      apdu.setOutgoingAndSend((short) 0, pubLen);
    } else if (p1 == (byte) 0x01) {
      // P1=0x01: store the backend-signed certificate for the card's public key
      JCSystem.beginTransaction();
      applet.crypto.setCertificate(buf, OFFSET_CDATA, bytesRead);
      JCSystem.commitTransaction();
    } else {
      ISOException.throwIt(SW_WRONG_P1P2);
    }
  }

  private void processPersonalizePin(APDU apdu) {
    applet.requireState(STATE_BLANK);
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    JCSystem.beginTransaction();
    applet.pin.setPin(buf, OFFSET_CDATA, bytesRead);
    JCSystem.commitTransaction();
  }

  private void processPersonalizeFinish(APDU apdu) {
    applet.requireState(STATE_BLANK);
    if (!applet.crypto.isKeyPairGenerated() || !applet.crypto.hasCertificate() || !applet.pin.isPinSet()) {
      ISOException.throwIt(SW_CONDITIONS_NOT_SATISFIED);
    }
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    if (bytesRead != (short) (CARD_ID_LENGTH + EXPIRY_DATE_LENGTH)) {
      ISOException.throwIt(SW_WRONG_LENGTH);
    }
    JCSystem.beginTransaction();
    Util.arrayCopy(buf, OFFSET_CDATA, applet.cardId, (short) 0, CARD_ID_LENGTH);
    Util.arrayCopy(buf, (short) (OFFSET_CDATA + CARD_ID_LENGTH), applet.expiryDate, (short) 0, EXPIRY_DATE_LENGTH);
    applet.counter = 0;
    applet.state = STATE_PERSONALIZED;
    JCSystem.commitTransaction();
  }

  private void processIssueCard(APDU apdu) {
    applet.requireState(STATE_PERSONALIZED);
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    if (bytesRead != CUSTOMER_ID_LENGTH) {
      ISOException.throwIt(SW_WRONG_LENGTH);
    }
    JCSystem.beginTransaction();
    Util.arrayCopy(buf, OFFSET_CDATA, applet.customerId, (short) 0, CUSTOMER_ID_LENGTH);
    applet.state = STATE_ISSUED;
    JCSystem.commitTransaction();
  }
}
