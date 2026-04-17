package applet;

import javacard.framework.*;

public class PinManager {

  private byte[] pinHash;
  private byte triesRemaining;
  private boolean pinSet;

  public PinManager() {
    pinHash = new byte[AppletConstants.PIN_HASH_LENGTH];
    triesRemaining = 0;
    pinSet = false;
  }

  public void setPin(byte[] hash, short off, short len) {
    if (len != AppletConstants.PIN_HASH_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    Util.arrayCopy(hash, off, pinHash, (short) 0, AppletConstants.PIN_HASH_LENGTH);
    triesRemaining = AppletConstants.MAX_PIN_TRIES;
    pinSet = true;
  }

  public boolean isPinSet() {
    return pinSet;
  }

  public boolean isLocked() {
    return triesRemaining <= 0;
  }

  public boolean verify(byte[] hash, short off, short len) {
    if (len != AppletConstants.PIN_HASH_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (isLocked()) {
      ISOException.throwIt(AppletConstants.SW_PIN_LOCKED);
    }
    if (Util.arrayCompare(hash, off, pinHash, (short) 0, AppletConstants.PIN_HASH_LENGTH) == 0) {
      triesRemaining = AppletConstants.MAX_PIN_TRIES;
      return true;
    } else {
      triesRemaining--;
      if (isLocked()) {
        ISOException.throwIt(AppletConstants.SW_PIN_LOCKED);
      }
      ISOException.throwIt(AppletConstants.SW_PIN_INCORRECT);
      return false;
    }
  }

  public byte getTriesRemaining() {
    return triesRemaining;
  }
}
