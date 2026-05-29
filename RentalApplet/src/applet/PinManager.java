package applet;

import javacard.framework.*;
import javacard.framework.OwnerPIN;

/**
 * Manages the PIN for the rental card, including setting, verifying, and tracking remaining attempts.
 * The PIN is stored as a hash, and the class uses OwnerPIN to manage verification and blocking after too many failed attempts.
 */
public class PinManager {

  private OwnerPIN pin;
  private boolean pinSet;

  /**
   * The constructor.
   */
  public PinManager() {
    pin = new OwnerPIN(AppletConstants.MAX_PIN_TRIES, (byte) AppletConstants.PIN_HASH_LENGTH);
    pinSet = false;
  }

  /**
   * Set the PIN hash. This can only be called once; subsequent calls will throw an exception. 
   * The PIN is stored as a hash for security, and the length must match the expected hash length.
   * @param hash The hash of the PIN to set.
   * @param off The offset in the hash array where the hash starts.
   * @param len The length of the hash. Must be equal to AppletConstants.PIN_HASH_LENGTH.
   */
  public void setPin(byte[] hash, short off, short len) {
    if (len != AppletConstants.PIN_HASH_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    pin.update(hash, off, (byte) len);
    pinSet = true;
  }

  /**
   * Check if the PIN has been set.
   *
   * @return true if the PIN is set, false otherwise.
   */
  public boolean isPinSet() {
    return pinSet;
  }

  /**
   * Verify the provided PIN hash.
   *
   * @param hash The PIN hash to verify.
   * @param off  The offset in the hash array.
   * @param len  The length of the hash to verify.
   * @return true if the PIN is correct, false otherwise.
   */
  public boolean verify(byte[] hash, short off, short len) {
    if (len != AppletConstants.PIN_HASH_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    if (isBlocked()) {
      ISOException.throwIt(AppletConstants.SW_PIN_LOCKED);
      return false;
    }
    boolean valid = pin.check(hash, off, (byte) len);
    if (valid) {
      return true;
    }
    if (isBlocked()) {
      ISOException.throwIt(AppletConstants.SW_PIN_LOCKED);
    }
    ISOException.throwIt(AppletConstants.SW_PIN_INCORRECT);
    return false;
  }
  
  private boolean isBlocked() {
    return pin.getTriesRemaining() <= 0;
  }
}
