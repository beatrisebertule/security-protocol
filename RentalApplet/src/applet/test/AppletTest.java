package applet.test;

import applet.RentalCardApplet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;

/**
 * Standalone applet test using JCardSim's JavaxSmartCardInterface.
 * Tests full lifecycle: blank -> personalized -> issued -> assigned -> mileage
 * -> return -> block.
 * No dependency on terminal code.
 */
public class AppletTest {

  static final byte[] APPLET_AID = {
      (byte) 0x3B, (byte) 0x29, (byte) 0x72, (byte) 0x65,
      (byte) 0x6E, (byte) 0x74, (byte) 0x01
  };

  static JavaxSmartCardInterface sim;
  static KeyPair masterKeyPair;
  static KeyPair terminalKeyPair;
  static byte[] lastSessionNonce; // nonce from most recent INS_GET_NONCE, for session-bound PIN
  static int passed = 0;
  static int failed = 0;

  public static void main(String[] args) throws Exception {
    System.out.println("=== RentalCardApplet Test Suite ===\n");

    // Setup
    masterKeyPair = generateKeyPair();
    terminalKeyPair = generateKeyPair();

    sim = new JavaxSmartCardInterface();
    AID aid = new AID(APPLET_AID, (byte) 0, (byte) APPLET_AID.length);
    sim.installApplet(aid, RentalCardApplet.class);
    sim.selectApplet(aid);

    // Run tests
    testGetStateBlank();
    testPersonalizeKeys();
    testPersonalizePin();
    testPersonalizeFinishIncomplete();
    testPersonalizeFinish();
    testIssueCard();
    testGetNonce();
    testMutualAuth();
    testPinVerification();
    testSignNonce();
    testVehicleAssignment();
    testMileage();
    testReturnVehicle();
    testClearMileage();
    testBlockCard();

    // Summary
    System.out.println("\n=== Results: " + passed + " passed, " + failed + " failed ===");
    if (failed > 0)
      System.exit(1);
  }

  // --- Test methods ---

  static void testGetStateBlank() {
    ResponseAPDU r = send(0x70, 0, 0, null);
    check("GET_STATE blank", r.getSW() == 0x9000 && r.getData()[0] == 0x00);
  }

  static void testPersonalizeKeys() throws Exception {
    // P1=0x00: send MPK, get back pkc
    byte[] mpk = getPublicKeyBytes(masterKeyPair);
    ResponseAPDU r = send(0x10, 0x00, 0, mpk);
    check("PERSONALIZE_KEYS install MPK + gen keypair",
        r.getSW() == 0x9000 && r.getData().length > 0);

    // P1=0x01: store certificate
    byte[] pkc = r.getData();
    byte[] cert = createCertificate(new byte[] { 0x00, 0x01 }, pkc, masterKeyPair.getPrivate());
    r = send(0x10, 0x01, 0, cert);
    check("PERSONALIZE_KEYS store cert", r.getSW() == 0x9000);
  }

  static void testPersonalizePin() throws Exception {
    byte[] pinHash = sha256("1234".getBytes());
    ResponseAPDU r = send(0x11, 0, 0, pinHash);
    check("PERSONALIZE_PIN", r.getSW() == 0x9000);
  }

  static void testPersonalizeFinishIncomplete() {
    // Should fail if we try on a fresh card with no keys (but we already set keys
    // above)
    // Instead, test wrong data length
    ResponseAPDU r = send(0x12, 0, 0, new byte[] { 0x01, 0x02 });
    check("PERSONALIZE_FINISH wrong length rejected", r.getSW() != 0x9000);
  }

  static void testPersonalizeFinish() {
    byte[] cardIdData = { 0x00, 0x00, 0x00, 0x01 };
    // Expiry: year 2100 = 4102444800000 ms since epoch
    long farFuture = 4102444800000L;
    byte[] expiry = new byte[8];
    for (int i = 7; i >= 0; i--) {
      expiry[i] = (byte) (farFuture & 0xFF);
      farFuture >>= 8;
    }
    byte[] payload = new byte[12];
    System.arraycopy(cardIdData, 0, payload, 0, 4);
    System.arraycopy(expiry, 0, payload, 4, 8);
    ResponseAPDU r = send(0x12, 0, 0, payload);
    check("PERSONALIZE_FINISH", r.getSW() == 0x9000);

    r = send(0x70, 0, 0, null);
    check("State is PERSONALIZED", r.getData()[0] == 0x01);

    // Verify card ID
    r = send(0x71, 0, 0, null);
    check("GET_CARD_ID", r.getSW() == 0x9000 && r.getData().length == 4);
  }

  static void testIssueCard() {
    byte[] custId = { 0x00, 0x00, 0x00, 0x42 };
    ResponseAPDU r = send(0x13, 0, 0, custId);
    check("ISSUE_CARD", r.getSW() == 0x9000);

    r = send(0x70, 0, 0, null);
    check("State is ISSUED", r.getData()[0] == 0x02);
  }

  static void testGetNonce() {
    ResponseAPDU r = send(0x20, 0, 0, null);
    check("GET_NONCE", r.getSW() == 0x9000 && r.getData().length == 16);
  }

  static void testMutualAuth() throws Exception {
    ResponseAPDU r = send(0x20, 0, 0, null);
    byte[] cardNonce = r.getData();
    lastSessionNonce = cardNonce;

    byte[] termSig = ecSign(cardNonce, terminalKeyPair.getPrivate());
    byte[] termPubKey = getPublicKeyBytes(terminalKeyPair);
    long notAfter = System.currentTimeMillis() / 1000 + 365L * 24 * 3600;
    byte[] termCert = createTerminalCertificate(
        new byte[] { 0x00, 0x02 }, termPubKey, notAfter, masterKeyPair.getPrivate());

    // Build: [2B sigLen][sig][cert]
    byte[] verifyData = new byte[2 + termSig.length + termCert.length];
    verifyData[0] = (byte) ((termSig.length >> 8) & 0xFF);
    verifyData[1] = (byte) (termSig.length & 0xFF);
    System.arraycopy(termSig, 0, verifyData, 2, termSig.length);
    System.arraycopy(termCert, 0, verifyData, 2 + termSig.length, termCert.length);

    r = send(0x21, 0, 0, verifyData);
    check("VERIFY_TERMINAL_SIG", r.getSW() == 0x9000);
  }

  static void testPinVerification() throws Exception {
    // Bind the PIN hash to the session nonce from testMutualAuth (same session)
    byte[] pinHash = sha256("1234".getBytes());
    byte[] boundHash = sha256(concat(lastSessionNonce, pinHash));
    ResponseAPDU r = send(0x22, 0, 0, boundHash);
    check("VERIFY_PIN correct (SW=" + Integer.toHexString(r.getSW()) + ")", r.getSW() == 0x9000);

    // Re-authenticate terminal for subsequent tests (deselect clears session, but
    // we haven't deselected, so session flags should still be set)
  }

  static void testSignNonce() throws Exception {
    // Terminal sends its nonce, card signs it + returns cert
    byte[] termNonce = new byte[16];
    SecureRandom sr = new SecureRandom();
    sr.nextBytes(termNonce);

    ResponseAPDU r = send(0x23, 0, 0, termNonce);
    check("SIGN_NONCE returns sig+cert", r.getSW() == 0x9000 && r.getData().length > 10);

    // Parse response: [2B sigLen][sig][cert]
    byte[] resp = r.getData();
    int sigLen = ((resp[0] & 0xFF) << 8) | (resp[1] & 0xFF);
    byte[] cardSig = new byte[sigLen];
    System.arraycopy(resp, 2, cardSig, 0, sigLen);
    byte[] cardCert = new byte[resp.length - 2 - sigLen];
    System.arraycopy(resp, 2 + sigLen, cardCert, 0, cardCert.length);

    // Verify card cert with MPK
    byte[] cardPubKey = extractPubKeyFromCert(cardCert);
    check("Card cert verifiable with MPK", verifyCertificate(cardCert, masterKeyPair.getPublic()));

    // Verify card signature of terminal nonce
    check("Card sig verifiable with pkc", ecVerify(termNonce, cardSig, cardPubKey));
  }

  static void testVehicleAssignment() throws Exception {
    // Need fresh auth for assignment
    doFullAuth();

    // Check unpaid mileage block (mileage should be 0 now, so this should work)
    byte[] vehicleId = { 0x00, 0x00, 0x00, 0x05 };
    byte[] nonce = new byte[16];
    new SecureRandom().nextBytes(nonce);
    byte[] period = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02 }; // start=1, end=2

    byte[] reqData = new byte[4 + 16 + 8];
    System.arraycopy(vehicleId, 0, reqData, 0, 4);
    System.arraycopy(nonce, 0, reqData, 4, 16);
    System.arraycopy(period, 0, reqData, 20, 8);

    ResponseAPDU r = send(0x30, 0, 0, reqData);
    check("SIGN_VEHICLE_REQ returns reqVehicleToken", r.getSW() == 0x9000 && r.getData().length > 0);
    byte[] reqVehicleToken = r.getData();

    // Create vehicleToken: [2B rdLen][reqData][2B reqVehicleTokenLen][reqVehicleToken][2B pkcLen][pkc][2B sigLen][sig]
    byte[] pkc = getCardPublicKey();
    byte[] vehicleTokenSignData = new byte[reqVehicleToken.length + pkc.length];
    System.arraycopy(reqVehicleToken, 0, vehicleTokenSignData, 0, reqVehicleToken.length);
    System.arraycopy(pkc, 0, vehicleTokenSignData, reqVehicleToken.length, pkc.length);
    byte[] vehicleTokenSig = ecSign(vehicleTokenSignData, masterKeyPair.getPrivate());

    byte[] vehicleToken = new byte[2 + reqData.length + 2 + reqVehicleToken.length + 2 + pkc.length + 2 + vehicleTokenSig.length];
    int pos = 0;
    vehicleToken[pos++] = (byte) ((reqData.length >> 8) & 0xFF);
    vehicleToken[pos++] = (byte) (reqData.length & 0xFF);
    System.arraycopy(reqData, 0, vehicleToken, pos, reqData.length);
    pos += reqData.length;
    vehicleToken[pos++] = (byte) ((reqVehicleToken.length >> 8) & 0xFF);
    vehicleToken[pos++] = (byte) (reqVehicleToken.length & 0xFF);
    System.arraycopy(reqVehicleToken, 0, vehicleToken, pos, reqVehicleToken.length);
    pos += reqVehicleToken.length;
    vehicleToken[pos++] = (byte) ((pkc.length >> 8) & 0xFF);
    vehicleToken[pos++] = (byte) (pkc.length & 0xFF);
    System.arraycopy(pkc, 0, vehicleToken, pos, pkc.length);
    pos += pkc.length;
    vehicleToken[pos++] = (byte) ((vehicleTokenSig.length >> 8) & 0xFF);
    vehicleToken[pos++] = (byte) (vehicleTokenSig.length & 0xFF);
    System.arraycopy(vehicleTokenSig, 0, vehicleToken, pos, vehicleTokenSig.length);

    r = send(0x31, 0, 0, vehicleToken);
    check("STORE_ASSIGNMENT", r.getSW() == 0x9000);

    r = send(0x70, 0, 0, null);
    check("State is ASSIGNED", r.getData()[0] == 0x03);

    // GET_ASSIGNMENT_DATA
    r = send(0x40, 0, 0, null);
    check("GET_ASSIGNMENT_DATA returns vehicleToken",
        r.getSW() == 0x9000 && r.getData().length == vehicleToken.length);

    // SIGN_VEHICLE_CHALL
    byte[] vehicleNonce = new byte[16];
    new SecureRandom().nextBytes(vehicleNonce);
    r = send(0x41, 0, 0, vehicleNonce);
    check("SIGN_VEHICLE_CHALL returns ephemeralVehicleToken", r.getSW() == 0x9000 && r.getData().length > 0);
  }

  static void testMileage() {
    // UPDATE_MILEAGE seq=0
    byte[] mileageData = new byte[4];
    mileageData[0] = 0x00;
    mileageData[1] = 0x64; // mileage = 100
    mileageData[2] = 0x00;
    mileageData[3] = 0x00; // seq = 0
    ResponseAPDU r = send(0x50, 0, 0, mileageData);
    check("UPDATE_MILEAGE seq=0", r.getSW() == 0x9000);

    // GET_MILEAGE
    r = send(0x51, 0, 0, null);
    check("GET_MILEAGE = 100",
        r.getSW() == 0x9000 && getShort(r.getData(), 0) == 100);

    // UPDATE_MILEAGE seq=0 again -> SEQUENCE_ERROR
    r = send(0x50, 0, 0, mileageData);
    check("UPDATE_MILEAGE replay rejected", r.getSW() == 0x6A85);

    // UPDATE_MILEAGE seq=1 -> OK
    mileageData[0] = 0x00;
    mileageData[1] = (byte) 0xC8; // mileage = 200
    mileageData[2] = 0x00;
    mileageData[3] = 0x01; // seq = 1
    r = send(0x50, 0, 0, mileageData);
    check("UPDATE_MILEAGE seq=1", r.getSW() == 0x9000);

    r = send(0x51, 0, 0, null);
    check("GET_MILEAGE = 200",
        r.getSW() == 0x9000 && getShort(r.getData(), 0) == 200);
  }

  static void testReturnVehicle() {
    // Final mileage = 250
    byte[] finalMileage = { 0x00, (byte) 0xFA };
    ResponseAPDU r = send(0x60, 0, 0, finalMileage);
    check("RETURN_VEHICLE", r.getSW() == 0x9000 && r.getData().length > 2);

    r = send(0x70, 0, 0, null);
    check("State back to ISSUED", r.getData()[0] == 0x02);

    // Mileage should be 250 (final mileage stored)
    r = send(0x51, 0, 0, null);
    check("Mileage = 250 after return", getShort(r.getData(), 0) == 250);

    // Assignment data should be gone
    r = send(0x40, 0, 0, null);
    check("GET_ASSIGNMENT_DATA rejected (ISSUED)", r.getSW() != 0x9000);
  }

  static void testClearMileage() throws Exception {
    // Need auth to clear mileage
    doFullAuth();

    ResponseAPDU r = send(0x73, 0, 0, null);
    check("CLEAR_MILEAGE", r.getSW() == 0x9000);

    r = send(0x51, 0, 0, null);
    check("Mileage = 0 after clear", getShort(r.getData(), 0) == 0);
  }

  /**
   * Test that PERSONALIZE_FINISH fails with SW_CONDITIONS_NOT_SATISFIED when
   * only the keys have been set but the PIN has NOT been set yet.
   * This kills the isPinSet() BooleanTrueReturnValsMutator (line 44) which
   * would make isPinSet() always return true, causing the finish to succeed
   * incorrectly.
   */
  static void testPersonalizeFinishWithoutPin() throws Exception {
    // Use a fresh simulator so state is BLANK and PIN is not set.
    JavaxSmartCardInterface freshSim = new JavaxSmartCardInterface();
    AID freshAid = new AID(APPLET_AID, (byte) 0, (byte) APPLET_AID.length);
    freshSim.installApplet(freshAid, RentalCardApplet.class);
    freshSim.selectApplet(freshAid);

    // Personalize keys only (no PIN step)
    byte[] mpk = getPublicKeyBytes(masterKeyPair);
    ResponseAPDU r = sendOn(freshSim, 0x10, 0x00, 0, mpk);
    byte[] pkc = r.getData();
    byte[] cert = createCertificate(new byte[] { 0x00, 0x01 }, pkc, masterKeyPair.getPrivate());
    sendOn(freshSim, 0x10, 0x01, 0, cert);

    // Attempt PERSONALIZE_FINISH without setting PIN - should fail
    byte[] cardIdData = { 0x00, 0x00, 0x00, 0x02 };
    long farFuture = 4102444800000L;
    byte[] expiry = new byte[8];
    for (int i = 7; i >= 0; i--) {
      expiry[i] = (byte) (farFuture & 0xFF);
      farFuture >>= 8;
    }
    byte[] payload = new byte[12];
    System.arraycopy(cardIdData, 0, payload, 0, 4);
    System.arraycopy(expiry, 0, payload, 4, 8);

    r = sendOn(freshSim, 0x12, 0, 0, payload);
    check("PERSONALIZE_FINISH without PIN rejected (SW_CONDITIONS_NOT_SATISFIED)",
        r.getSW() == 0x6985);
  }

  /**
   * Test that VERIFY_PIN with the correct PIN returns SW 9000.
   * This kills the verify() BooleanFalseReturnValsMutator (line 65).
   */
  static void testCorrectPinVerification() throws Exception {
    // Reuse the existing sim which is in ISSUED state after fullLifecycle tests.
    // Re-authenticate first.
    doFullAuth();
    byte[] pinHash = sha256("1234".getBytes());
    ResponseAPDU r = send(0x22, 0, 0, pinHash);
    check("VERIFY_PIN correct PIN returns 9000", r.getSW() == 0x9000);
  }

  /**
   * Test that VERIFY_PIN with a wrong PIN does not return SW 9000.
   * Complements testCorrectPinVerification to ensure the check is meaningful.
   */
  static void testWrongPinVerification() throws Exception {
    doFullAuth();
    byte[] wrongHash = sha256("9999".getBytes());
    ResponseAPDU r = send(0x22, 0, 0, wrongHash);
    check("VERIFY_PIN wrong PIN does not return 9000", r.getSW() != 0x9000);
  }

  static void testBlockCard() {
    ResponseAPDU r = send(0x72, 0, 0, null);
    check("BLOCK_CARD", r.getSW() == 0x9000);

    r = send(0x70, 0, 0, null);
    check("State is BLOCKED", r.getData()[0] == 0x04);

    // All other ops should fail with SW_CARD_BLOCKED
    r = send(0x20, 0, 0, null);
    check("GET_NONCE rejected on blocked card", r.getSW() == 0x6A86);

    r = send(0x51, 0, 0, null);
    check("GET_MILEAGE rejected on blocked card", r.getSW() == 0x6A86);
  }

  // --- Auth helper ---

  static void doFullAuth() throws Exception {
    ResponseAPDU r = send(0x20, 0, 0, null);
    byte[] cardNonce = r.getData();
    lastSessionNonce = cardNonce;

    byte[] termSig = ecSign(cardNonce, terminalKeyPair.getPrivate());
    byte[] termPubKey = getPublicKeyBytes(terminalKeyPair);
    long notAfter = System.currentTimeMillis() / 1000 + 365L * 24 * 3600;
    byte[] termCert = createTerminalCertificate(
        new byte[] { 0x00, 0x02 }, termPubKey, notAfter, masterKeyPair.getPrivate());

    // format: [2B sigLen][sig][cert]
    byte[] verifyData = new byte[2 + termSig.length + termCert.length];
    verifyData[0] = (byte) ((termSig.length >> 8) & 0xFF);
    verifyData[1] = (byte) (termSig.length & 0xFF);
    System.arraycopy(termSig, 0, verifyData, 2, termSig.length);
    System.arraycopy(termCert, 0, verifyData, 2 + termSig.length, termCert.length);
    send(0x21, 0, 0, verifyData);

    byte[] pinHash = sha256("1234".getBytes());
    byte[] boundHash = sha256(concat(cardNonce, pinHash));
    send(0x22, 0, 0, boundHash);

    byte[] termNonce = new byte[16];
    new SecureRandom().nextBytes(termNonce);
    send(0x23, 0, 0, termNonce);
  }

  static byte[] getCardPublicKey() throws Exception {
    ResponseAPDU r = send(0x24, 0, 0, null);
    byte[] cert = r.getData();
    return extractPubKeyFromCert(cert);
  }

  // --- Crypto helpers (standard Java, EC P-256) ---

  static KeyPair generateKeyPair() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    kpg.initialize(new ECGenParameterSpec("secp256r1"));
    return kpg.generateKeyPair();
  }

  /** Encode EC P-256 public key as 65-byte uncompressed point: 0x04 || x32 || y32 */
  static byte[] getPublicKeyBytes(KeyPair kp) {
    ECPublicKey pub = (ECPublicKey) kp.getPublic();
    ECPoint point = pub.getW();
    byte[] x = toBigIntBytes(point.getAffineX());
    byte[] y = toBigIntBytes(point.getAffineY());
    byte[] encoded = new byte[65];
    encoded[0] = 0x04;
    System.arraycopy(x, 0, encoded, 1, 32);
    System.arraycopy(y, 0, encoded, 33, 32);
    return encoded;
  }

  private static byte[] toBigIntBytes(BigInteger val) {
    byte[] bytes = val.toByteArray();
    if (bytes.length == 32) return bytes;
    byte[] result = new byte[32];
    if (bytes.length > 32) {
      System.arraycopy(bytes, bytes.length - 32, result, 0, 32);
    } else {
      System.arraycopy(bytes, 0, result, 32 - bytes.length, bytes.length);
    }
    return result;
  }

  static byte[] ecSign(byte[] data, PrivateKey privKey) throws Exception {
    Signature sig = Signature.getInstance("SHA256withECDSA");
    sig.initSign(privKey);
    sig.update(data);
    return sig.sign();
  }

  /** Decode 65-byte uncompressed EC point back to PublicKey */
  static PublicKey decodePublicKey(byte[] encoded) throws Exception {
    BigInteger x = new BigInteger(1, Arrays.copyOfRange(encoded, 1, 33));
    BigInteger y = new BigInteger(1, Arrays.copyOfRange(encoded, 33, 65));
    AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
    params.init(new ECGenParameterSpec("secp256r1"));
    ECParameterSpec ecSpec = params.getParameterSpec(ECParameterSpec.class);
    return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), ecSpec));
  }

  static boolean ecVerify(byte[] data, byte[] signature, byte[] pubKeyEncoded) throws Exception {
    PublicKey pub = decodePublicKey(pubKeyEncoded);
    Signature sig = Signature.getInstance("SHA256withECDSA");
    sig.initVerify(pub);
    sig.update(data);
    return sig.verify(signature);
  }

  static byte[] sha256(byte[] data) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    return md.digest(data);
  }

  static byte[] concat(byte[]... arrays) {
    int len = 0;
    for (byte[] a : arrays) len += a.length;
    byte[] out = new byte[len];
    int off = 0;
    for (byte[] a : arrays) { System.arraycopy(a, 0, out, off, a.length); off += a.length; }
    return out;
  }

  /**
   * Create terminal certificate (new format): [2B idLen][id][2B pkLen][pk][8B notAfter][2B sigLen][sig]
   * Signed data = [2B idLen][id][2B pkLen][pk][8B notAfter]
   */
  static byte[] createTerminalCertificate(byte[] subjectId, byte[] pubKey, long notAfterEpochSec,
      PrivateKey signingKey) throws Exception {
    byte[] notAfterBytes = new byte[8];
    long ts = notAfterEpochSec;
    for (int i = 7; i >= 0; i--) {
      notAfterBytes[i] = (byte) (ts & 0xFF);
      ts >>= 8;
    }
    byte[] signedData = new byte[2 + subjectId.length + 2 + pubKey.length + 8];
    signedData[0] = (byte) ((subjectId.length >> 8) & 0xFF);
    signedData[1] = (byte) (subjectId.length & 0xFF);
    System.arraycopy(subjectId, 0, signedData, 2, subjectId.length);
    signedData[2 + subjectId.length] = (byte) ((pubKey.length >> 8) & 0xFF);
    signedData[2 + subjectId.length + 1] = (byte) (pubKey.length & 0xFF);
    System.arraycopy(pubKey, 0, signedData, 2 + subjectId.length + 2, pubKey.length);
    System.arraycopy(notAfterBytes, 0, signedData, 2 + subjectId.length + 2 + pubKey.length, 8);

    byte[] sig = ecSign(signedData, signingKey);

    byte[] cert = new byte[signedData.length + 2 + sig.length];
    System.arraycopy(signedData, 0, cert, 0, signedData.length);
    cert[signedData.length] = (byte) ((sig.length >> 8) & 0xFF);
    cert[signedData.length + 1] = (byte) (sig.length & 0xFF);
    System.arraycopy(sig, 0, cert, signedData.length + 2, sig.length);
    return cert;
  }

  /**
   * Create certificate (card format): [2B idLen][id][2B pkLen][pk][2B sigLen][sig]
   * Signed data = [2B idLen][id][2B pkLen][pk]
   */
  static byte[] createCertificate(byte[] subjectId, byte[] pubKey, PrivateKey signingKey) throws Exception {
    byte[] signedData = new byte[2 + subjectId.length + 2 + pubKey.length];
    signedData[0] = (byte) ((subjectId.length >> 8) & 0xFF);
    signedData[1] = (byte) (subjectId.length & 0xFF);
    System.arraycopy(subjectId, 0, signedData, 2, subjectId.length);
    signedData[2 + subjectId.length] = (byte) ((pubKey.length >> 8) & 0xFF);
    signedData[2 + subjectId.length + 1] = (byte) (pubKey.length & 0xFF);
    System.arraycopy(pubKey, 0, signedData, 2 + subjectId.length + 2, pubKey.length);

    byte[] sig = ecSign(signedData, signingKey);

    byte[] cert = new byte[signedData.length + 2 + sig.length];
    System.arraycopy(signedData, 0, cert, 0, signedData.length);
    cert[signedData.length] = (byte) ((sig.length >> 8) & 0xFF);
    cert[signedData.length + 1] = (byte) (sig.length & 0xFF);
    System.arraycopy(sig, 0, cert, signedData.length + 2, sig.length);
    return cert;
  }

  static boolean verifyCertificate(byte[] cert, PublicKey masterPub) throws Exception {
    int subjectIdLen = ((cert[0] & 0xFF) << 8) | (cert[1] & 0xFF);
    int pubKeyLenOff = 2 + subjectIdLen;
    int pubKeyLen = ((cert[pubKeyLenOff] & 0xFF) << 8) | (cert[pubKeyLenOff + 1] & 0xFF);
    int signedDataLen = 2 + subjectIdLen + 2 + pubKeyLen;
    int sigLen = ((cert[signedDataLen] & 0xFF) << 8) | (cert[signedDataLen + 1] & 0xFF);

    byte[] signedData = new byte[signedDataLen];
    System.arraycopy(cert, 0, signedData, 0, signedDataLen);
    byte[] sig = new byte[sigLen];
    System.arraycopy(cert, signedDataLen + 2, sig, 0, sigLen);

    Signature verifier = Signature.getInstance("SHA1withRSA");
    verifier.initVerify(masterPub);
    verifier.update(signedData);
    return verifier.verify(sig);
  }

  static byte[] extractPubKeyFromCert(byte[] cert) {
    int subjectIdLen = ((cert[0] & 0xFF) << 8) | (cert[1] & 0xFF);
    int pubKeyLenOff = 2 + subjectIdLen;
    int pubKeyLen = ((cert[pubKeyLenOff] & 0xFF) << 8) | (cert[pubKeyLenOff + 1] & 0xFF);
    byte[] pubKey = new byte[pubKeyLen];
    System.arraycopy(cert, pubKeyLenOff + 2, pubKey, 0, pubKeyLen);
    return pubKey;
  }

  // --- APDU helpers ---

  static ResponseAPDU sendOn(JavaxSmartCardInterface s, int ins, int p1, int p2, byte[] data) {
    CommandAPDU cmd;
    if (data != null) {
      cmd = new CommandAPDU(0x00, ins, p1, p2, data, 256);
    } else {
      cmd = new CommandAPDU(0x00, ins, p1, p2, 256);
    }
    return s.transmitCommand(cmd);
  }

  static ResponseAPDU send(int ins, int p1, int p2, byte[] data) {
    CommandAPDU cmd;
    if (data != null) {
      cmd = new CommandAPDU(0x00, ins, p1, p2, data, 256);
    } else {
      cmd = new CommandAPDU(0x00, ins, p1, p2, 256);
    }
    return sim.transmitCommand(cmd);
  }

  static short getShort(byte[] buf, int off) {
    return (short) (((buf[off] & 0xFF) << 8) | (buf[off + 1] & 0xFF));
  }

  static void check(String name, boolean condition) {
    if (condition) {
      System.out.println("  PASS: " + name);
      passed++;
    } else {
      System.out.println("  FAIL: " + name);
      failed++;
    }
  }

  static String toHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes)
      sb.append(String.format("%02X", b));
    return sb.toString();
  }
}
