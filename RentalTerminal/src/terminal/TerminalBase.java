package terminal;

import java.security.GeneralSecurityException;
import java.security.KeyPair;

import terminal.logging.Result;
import terminal.logging.VerboseLogger;
import terminal.util.CardComm;
import terminal.util.CryptoUtil;
import terminal.util.ProtocolConstants;

/**
 * Common base for all terminal types: holds the card communication channel
 * and provides unified output that logs every message to VerboseLogger and
 * writes it to stdout/stderr.
 */
public abstract class TerminalBase {

  protected final CardComm comm;

  protected TerminalBase(CardComm comm) {
    this.comm = comm;
  }

  protected final void log(String message) {
    VerboseLogger.get().step(message);
  }

  protected final void showMessage(String message) {
    VerboseLogger.get().step(message);
    System.out.println(message);
  }

  protected final void showError(String message) {
    VerboseLogger.get().step("ERROR: " + message);
    System.err.println("Error: " + message);
  }

  /**
   * Authenticate this terminal to the card: sign the card-supplied nonce with
   * the terminal private key and send the signature together with the terminal
   * certificate. On success the card sets FLAG_TERMINAL_AUTH.
   */
  protected Result<Void> sendTerminalAuth(byte[] cardNonce, KeyPair kp, byte[] cert) {
    byte[] sig;
    try {
      sig = CryptoUtil.sign(kp.getPrivate(), cardNonce);
    } catch (GeneralSecurityException e) {
      return Result.fail("Terminal authentication signing failure", e);
    }
    byte[] payload = new byte[2 + sig.length + cert.length];
    payload[0] = (byte) ((sig.length >> 8) & 0xFF);
    payload[1] = (byte) (sig.length & 0xFF);
    System.arraycopy(sig, 0, payload, 2, sig.length);
    System.arraycopy(cert, 0, payload, 2 + sig.length, cert.length);
    Result<byte[]> r = comm.send(ProtocolConstants.INS_VERIFY_TERMINAL_SIG, payload);
    if (!r.success) {
      return Result.fail(r.error);
    }
    return Result.ok();
  }

  /**
   * Verify the customer PIN: compute the session-bound hash and send it to the
   * card. On success the card sets FLAG_PIN_VERIFIED.
   */
  protected Result<Void> sendPinVerification(String pin, byte[] cardNonce) {
    byte[] boundHash;
    try {
      boundHash = CryptoUtil.hashPinWithNonce(pin, cardNonce);
    } catch (GeneralSecurityException e) {
      return Result.fail("PIN hashing failure", e);
    }
    Result<byte[]> r = comm.send(ProtocolConstants.INS_VERIFY_PIN, boundHash);
    if (!r.success) {
      return Result.fail(r.error);
    }
    return Result.ok();
  }
}
