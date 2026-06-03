package applet;

import javacard.framework.*;
import static applet.AppletConstants.*;
import static javacard.framework.ISO7816.*;

/**
 * Handles all vehicle-related APDUs: assignment (INS 0x30-0x31),
 * access (INS 0x40-0x41), mileage (INS 0x50-0x51), and return (INS 0x60).
 */
class VehicleHandler {

  private final RentalCardApplet applet;

  VehicleHandler(RentalCardApplet applet) {
    this.applet = applet;
  }

  void handle(byte ins, APDU apdu) {
    switch (ins) {
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
    }
  }

  private void processSignVehicleReq(APDU apdu) {
    applet.requireState(STATE_ISSUED);
    applet.requireFullAuth();
    if (applet.mileage > 0) {
      ISOException.throwIt(SW_UNPAID_MILEAGE);
    }
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    short expectedLen = (short) (VEHICLE_ID_LENGTH + NONCE_LENGTH + RENTAL_PERIOD_LENGTH);
    if (bytesRead != expectedLen) {
      ISOException.throwIt(SW_WRONG_LENGTH);
    }
    // Store vehicle ID and rental period for later verification
    Util.arrayCopy(buf, OFFSET_CDATA, applet.assignedVehicleId, (short) 0, VEHICLE_ID_LENGTH);
    Util.arrayCopy(buf, (short) (OFFSET_CDATA + VEHICLE_ID_LENGTH + NONCE_LENGTH),
        applet.rentalPeriod, (short) 0, RENTAL_PERIOD_LENGTH);
    short sigLen = applet.crypto.sign(buf, OFFSET_CDATA, bytesRead, buf, (short) 0);
    apdu.setOutgoingAndSend((short) 0, sigLen);
  }

  private void processStoreAssignment(APDU apdu) {
    applet.requireState(STATE_ISSUED);
    applet.requireFullAuth();
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    if (bytesRead > MAX_ASSIGN_LENGTH) {
      ISOException.throwIt(SW_WRONG_LENGTH);
    }
    if (!applet.crypto.verifyAndSetAssignment(buf, OFFSET_CDATA, bytesRead)) {
      ISOException.throwIt(SW_SIGNATURE_INVALID);
    }
    JCSystem.beginTransaction();
    applet.state = STATE_ASSIGNED;
    JCSystem.commitTransaction();
  }

  private void processGetAssignmentData(APDU apdu) {
    applet.requireState(STATE_ASSIGNED);
    if (!applet.sessionFlags[RentalCardApplet.FLAG_TERMINAL_AUTH]) {
      ISOException.throwIt(SW_AUTH_REQUIRED);
    }
    byte[] buf = apdu.getBuffer();
    short len = applet.crypto.getAssignment(buf, (short) 0);
    apdu.setOutgoingAndSend((short) 0, len);
  }

  private void processSignVehicleChall(APDU apdu) {
    applet.requireState(STATE_ASSIGNED);
    applet.requireTerminalAuth();
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    if (bytesRead != NONCE_LENGTH) {
      ISOException.throwIt(SW_WRONG_LENGTH);
    }
    // Seed mileage sequence number from vehicleNonce to bind it to this session,
    // preventing cross-session replay of captured mileage update APDUs.
    JCSystem.beginTransaction();
    applet.mileageSeqNum = Util.getShort(buf, OFFSET_CDATA);
    JCSystem.commitTransaction();
    short sigLen = applet.crypto.signVehicleChallenge(buf, OFFSET_CDATA, bytesRead, buf, (short) 0);
    apdu.setOutgoingAndSend((short) 0, sigLen);
  }

  private void processUpdateMileage(APDU apdu) {
    applet.requireState(STATE_ASSIGNED);
    applet.requireTerminalAuth();
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    if (bytesRead != 6) {
      ISOException.throwIt(SW_WRONG_LENGTH);
    }
    int newMileage = Util.getShort(buf, OFFSET_CDATA) << 16 | 
                     (Util.getShort(buf, (short)(OFFSET_CDATA + 2)) & 0xFFFF);
    short sequenceNumber = Util.getShort(buf, (short) (OFFSET_CDATA + 4));
    if (sequenceNumber != applet.mileageSeqNum) {
      ISOException.throwIt(SW_SEQUENCE_ERROR);
    }
    if (newMileage < applet.mileage) {
      ISOException.throwIt(SW_DATA_INVALID);
    }
    JCSystem.beginTransaction();
    applet.mileage = newMileage;
    applet.mileageSeqNum++;
    JCSystem.commitTransaction();
  }

  private void processGetMileage(APDU apdu) {
    if (applet.state != STATE_ISSUED && applet.state != STATE_ASSIGNED) {
      ISOException.throwIt(SW_WRONG_STATE);
    }
    applet.requireTerminalAuth();
    byte[] buf = apdu.getBuffer();
    Util.setShort(buf, (short) 0, (short) ((applet.mileage >> 16) & 0xFFFF));
    Util.setShort(buf, (short) 2, (short) (applet.mileage & 0xFFFF));
    apdu.setOutgoingAndSend((short) 0, (short) 4);
  }

  /**
   * Handles vehicle return: accepts the final mileage, clears the assignment,
   * transitions the card back to ISSUED, and returns a signed receipt
   * containing the final mileage.
   *
   * @param apdu the incoming APDU; payload is 2 bytes (final mileage, big-endian)
   */
  private void processReturnVehicle(APDU apdu) {
    applet.requireState(STATE_ASSIGNED);
    applet.requireTerminalAuth();
    byte[] buf = apdu.getBuffer();
    short bytesRead = apdu.setIncomingAndReceive();
    if (bytesRead != 4) {
      ISOException.throwIt(SW_WRONG_LENGTH);
    }
    int finalMileage = Util.getShort(buf, OFFSET_CDATA) << 16 |
                       (Util.getShort(buf, (short)(OFFSET_CDATA + 2)) & 0xFFFF);
    if (finalMileage < applet.mileage) {
      ISOException.throwIt(SW_DATA_INVALID);
    }

    JCSystem.beginTransaction();
    applet.mileage = finalMileage;
    applet.mileageSeqNum = 0;
    applet.crypto.clearAssignment();
    Util.arrayFillNonAtomic(applet.assignedVehicleId, (short) 0, VEHICLE_ID_LENGTH, (byte) 0);
    Util.arrayFillNonAtomic(applet.rentalPeriod, (short) 0, RENTAL_PERIOD_LENGTH, (byte) 0);
    applet.state = STATE_ISSUED;
    JCSystem.commitTransaction();

    // Sign after state is durably committed so the receipt reflects committed data
    Util.setShort(buf, (short) 0, (short) ((finalMileage >> 16) & 0xFFFF));
    Util.setShort(buf, (short) 2, (short) (finalMileage & 0xFFFF));
    short signatureLength = applet.crypto.sign(buf, (short) 0, (short) 4, buf, (short) 4);
    apdu.setOutgoingAndSend((short) 0, (short) (4 + signatureLength));
  }
}
