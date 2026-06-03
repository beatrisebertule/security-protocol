package terminal.test;

import javacard.framework.AID;
import javax.smartcardio.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;

import applet.RentalCardApplet;
import terminal.backend.BackendSystem;
import terminal.util.CardComm;
import terminal.util.ProtocolConstants;
import terminal.logging.Result;
import terminal.personalization.PersonalizationTerminal;
import terminal.util.ByteUtil;
import terminal.util.CryptoUtil;

/**
 * Adversarial integration tests: malicious terminal and malicious card.
 *
 * Part 1 - Malicious terminal: replayed nonces, auth step skipping,
 * forged vehicleTokens, mileage rollback.
 *
 * Part 2 - Malicious card: TamperingCardChannel intercepts and corrupts
 * responses; verifies that the terminal side detects each tamper.
 */
public class AdversarialTest {

  static final byte[] APPLET_AID = {
      (byte) 0x3B, (byte) 0x29, (byte) 0x72, (byte) 0x65,
      (byte) 0x6E, (byte) 0x74, (byte) 0x01
  };
  static final byte[] CARD_ID     = { 0x00, 0x00, 0x00, 0x01 };
  static final byte[] CUSTOMER_ID = { 0x00, 0x00, 0x00, 0x42 };
  static final byte[] VEHICLE_ID  = { 0x00, 0x00, 0x00, 0x05 };
  static final String PIN = "1234";

  static final int SW_OK                = 0x9000;
  static final int SW_AUTH_REQUIRED     = 0x6A83;
  static final int SW_SIGNATURE_INVALID = 0x6A84;

  static int passed = 0;
  static int failed = 0;
  static int testNum = 0;
  static BackendSystem backend;

  public static void main(String[] args) throws Exception {
    System.out.println("=== AdversarialTest: Malicious Terminal / Malicious Card ===\n");

    // Part 1: malicious terminal
    testNonceReplay_SignatureInvalid();
    testSkipTerminalAuth_PinRejected();
    testSkipPin_SignNonceRejected();
    testSkipPin_SignVehicleReqRejected();
    testForgedVehicleToken_CardRejects();
    testMileageRollback_TerminalRejects();

    // Part 2: malicious card
    testMaliciousCard_FakeCardCert_TerminalRejects();
    testMaliciousCard_CorruptedCardSig_TerminalRejects();
    testMaliciousCard_FakeEphemeralToken_VehicleTerminalRejects();
    testMaliciousCard_FakeReturnReceipt_VehicleTerminalRejects();

    System.out.println("\n=== Results: " + passed + " passed, " + failed + " failed ===");
    if (failed > 0) System.exit(1);
  }

  // ---------------------------------------------------------------------------
  // Part 1: Malicious terminal
  // ---------------------------------------------------------------------------

  static void testNonceReplay_SignatureInvalid() throws Exception {
    System.out.println("\n-- Nonce replay --");
    setup();
    CardComm comm = freshIssuedCard();

    // Capture nonce1, then force a new nonce2 into the card's crypto state
    byte[] nonce1 = unwrap(comm.send(ProtocolConstants.INS_GET_NONCE));
    unwrap(comm.send(ProtocolConstants.INS_GET_NONCE)); // nonce2 now active; nonce1 stale

    // Build valid terminal sig over stale nonce1
    byte[] termSig  = CryptoUtil.sign(backend.getTerminalKeyPair().getPrivate(), nonce1);
    byte[] termCert = backend.getTerminalCertificate();
    byte[] payload  = ByteUtil.concat(
        ByteUtil.shortToBytes((short) termSig.length), termSig, termCert);

    ResponseAPDU r = comm.sendRaw(ProtocolConstants.INS_VERIFY_TERMINAL_SIG, payload).value;
    check("stale nonce sig rejected", r.getSW() == SW_SIGNATURE_INVALID);
  }

  static void testSkipTerminalAuth_PinRejected() throws Exception {
    System.out.println("\n-- Skip terminal auth: PIN rejected --");
    setup();
    CardComm comm = freshIssuedCard();

    byte[] pinHash = CryptoUtil.hashPin(PIN);
    ResponseAPDU r = comm.sendRaw(ProtocolConstants.INS_VERIFY_PIN, pinHash).value;
    check("PIN without terminal auth rejected", r.getSW() == SW_AUTH_REQUIRED);
  }

  static void testSkipPin_SignNonceRejected() throws Exception {
    System.out.println("\n-- Skip PIN: SIGN_NONCE rejected --");
    setup();
    CardComm comm = freshIssuedCard();

    doTerminalAuth(comm);

    byte[] fakeTermNonce = CryptoUtil.generateNonce(ProtocolConstants.NONCE_LENGTH);
    ResponseAPDU r = comm.sendRaw(ProtocolConstants.INS_SIGN_NONCE, fakeTermNonce).value;
    check("SIGN_NONCE without PIN rejected", r.getSW() == SW_AUTH_REQUIRED);
  }

  static void testSkipPin_SignVehicleReqRejected() throws Exception {
    System.out.println("\n-- Skip PIN: SIGN_VEHICLE_REQ rejected --");
    setup();
    CardComm comm = freshIssuedCard();

    doTerminalAuth(comm);

    byte[] reqData = new byte[
        ProtocolConstants.VEHICLE_ID_LENGTH
        + ProtocolConstants.NONCE_LENGTH
        + ProtocolConstants.RENTAL_PERIOD_LENGTH];
    ResponseAPDU r = comm.sendRaw(ProtocolConstants.INS_SIGN_VEHICLE_REQ, reqData).value;
    check("SIGN_VEHICLE_REQ without PIN rejected", r.getSW() == SW_AUTH_REQUIRED);
  }

  static void testForgedVehicleToken_CardRejects() throws Exception {
    System.out.println("\n-- Forged vehicleToken: card rejects (MSK check on card) --");
    setup();
    CardComm comm = freshIssuedCard();

    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);
    byte[] pkc = unwrap(rt.mutualAuth(PIN));

    // Get reqVehicleToken from card (card signs reqData with its private key)
    byte[] nonce   = CryptoUtil.generateNonce(ProtocolConstants.NONCE_LENGTH);
    long now       = System.currentTimeMillis() / 1000;
    byte[] period  = periodBytes(now, now + 86400);
    byte[] reqData = ByteUtil.concat(VEHICLE_ID, nonce, period);
    byte[] reqVehicleToken = unwrap(comm.send(ProtocolConstants.INS_SIGN_VEHICLE_REQ, reqData));

    // Forge vehicleToken: rogue key signs (reqVehicleToken || pkc) instead of MSK
    KeyPair rogueKP   = CryptoUtil.generateKeyPair();
    byte[] dataToSign = ByteUtil.concat(reqVehicleToken, pkc);
    byte[] rogueSig   = CryptoUtil.sign(rogueKP.getPrivate(), dataToSign);
    byte[] forgedToken = ByteUtil.concat(
        ByteUtil.shortToBytes((short) reqData.length),         reqData,
        ByteUtil.shortToBytes((short) reqVehicleToken.length), reqVehicleToken,
        ByteUtil.shortToBytes((short) pkc.length),             pkc,
        ByteUtil.shortToBytes((short) rogueSig.length),        rogueSig);

    // Card verifies MSK signature and rejects the forged token
    ResponseAPDU storeResp = comm.sendRaw(ProtocolConstants.INS_STORE_ASSIGNMENT, forgedToken).value;
    check("card rejects forged vehicleToken (MSK check on card)", storeResp.getSW() != SW_OK);
  }

  static void testMileageRollback_TerminalRejects() throws Exception {
    System.out.println("\n-- Mileage rollback: terminal rejects --");
    setup();
    CardComm comm = freshIssuedCard();

    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);
    byte[] pkc = unwrap(rt.mutualAuth(PIN));
    doAssign(comm, pkc);

    TestVehicleTerminal vt = new TestVehicleTerminal(comm, backend.getMasterPublicKey(),
        backend.getTerminalKeyPair(), backend.getTerminalCertificate(), VEHICLE_ID);
    unwrap(vt.open());
    unwrap(vt.updateMileage((short) 100));

    Result<Void> rollback = vt.updateMileage((short) 50);
    check("mileage rollback rejected by terminal", !rollback.success);
  }

  // ---------------------------------------------------------------------------
  // Part 2: Malicious card (TamperingCardChannel)
  // ---------------------------------------------------------------------------

  static void testMaliciousCard_FakeCardCert_TerminalRejects() throws Exception {
    System.out.println("\n-- Malicious card: fake cert rejected by terminal --");
    setup();

    // Build a self-signed (rogue) cert - not signed by real MPK
    KeyPair rogueKP = CryptoUtil.generateKeyPair();
    byte[] fakeCert = CryptoUtil.createCertificate(
        CARD_ID, CryptoUtil.encodePublicKey(rogueKP.getPublic()), rogueKP.getPrivate());

    CardChannel raw = freshRawChannel();
    // Intercept INS_SIGN_NONCE: keep real sig bytes, replace cert with rogue cert
    TamperingCardChannel tampered = new TamperingCardChannel(
        raw, ProtocolConstants.INS_SIGN_NONCE & 0xFF) {
      @Override ResponseAPDU tamper(ResponseAPDU real) {
        byte[] data = real.getData();
        if (data == null || data.length < 2) return real;
        int sigLen = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);
        byte[] out = new byte[2 + sigLen + fakeCert.length + 2];
        System.arraycopy(data, 0, out, 0, 2 + sigLen);
        System.arraycopy(fakeCert, 0, out, 2 + sigLen, fakeCert.length);
        out[out.length - 2] = (byte) 0x90;
        out[out.length - 1] = (byte) 0x00;
        return new ResponseAPDU(out);
      }
    };

    CardComm comm = issueOnChannel(tampered);
    Result<byte[]> result = new TestReceptionTerminal(comm, backend).mutualAuth(PIN);
    check("fake card cert rejected by terminal", !result.success);
  }

  static void testMaliciousCard_CorruptedCardSig_TerminalRejects() throws Exception {
    System.out.println("\n-- Malicious card: corrupted sig rejected by terminal --");
    setup();

    CardChannel raw = freshRawChannel();
    // Intercept INS_SIGN_NONCE: flip one bit in the signature body
    TamperingCardChannel tampered = new TamperingCardChannel(
        raw, ProtocolConstants.INS_SIGN_NONCE & 0xFF) {
      @Override ResponseAPDU tamper(ResponseAPDU real) {
        byte[] data = real.getData();
        if (data == null || data.length < 4) return real;
        byte[] out = Arrays.copyOf(data, data.length);
        out[3] ^= 0x01;
        byte[] resp = new byte[out.length + 2];
        System.arraycopy(out, 0, resp, 0, out.length);
        resp[out.length]     = (byte) 0x90;
        resp[out.length + 1] = (byte) 0x00;
        return new ResponseAPDU(resp);
      }
    };

    CardComm comm = issueOnChannel(tampered);
    Result<byte[]> result = new TestReceptionTerminal(comm, backend).mutualAuth(PIN);
    check("corrupted card sig rejected by terminal", !result.success);
  }

  static void testMaliciousCard_FakeEphemeralToken_VehicleTerminalRejects() throws Exception {
    System.out.println("\n-- Malicious card: fake ephemeral token rejected by vehicle terminal --");
    setup();

    CardChannel raw = freshRawChannel();
    // Intercept INS_SIGN_VEHICLE_CHALL: flip first byte of the ephemeral sig
    TamperingCardChannel tampered = new TamperingCardChannel(
        raw, ProtocolConstants.INS_SIGN_VEHICLE_CHALL & 0xFF) {
      @Override ResponseAPDU tamper(ResponseAPDU real) {
        byte[] data = real.getData();
        if (data == null || data.length == 0) return real;
        byte[] out = Arrays.copyOf(data, data.length);
        out[0] ^= 0x01;
        byte[] resp = new byte[out.length + 2];
        System.arraycopy(out, 0, resp, 0, out.length);
        resp[out.length]     = (byte) 0x90;
        resp[out.length + 1] = (byte) 0x00;
        return new ResponseAPDU(resp);
      }
    };

    CardComm comm = issueOnChannel(tampered);
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);
    byte[] pkc = unwrap(rt.mutualAuth(PIN));
    doAssign(comm, pkc);

    TestVehicleTerminal vt = new TestVehicleTerminal(comm, backend.getMasterPublicKey(),
        backend.getTerminalKeyPair(), backend.getTerminalCertificate(), VEHICLE_ID);
    Result<byte[]> result = vt.open();
    check("fake ephemeral token rejected by vehicle terminal", !result.success);
  }

  static void testMaliciousCard_FakeReturnReceipt_VehicleTerminalRejects() throws Exception {
    System.out.println("\n-- Malicious card: fake return receipt rejected by vehicle terminal --");
    setup();

    CardChannel raw = freshRawChannel();
    // Intercept INS_RETURN_VEHICLE: flip first byte of sig (after 2B mileage)
    TamperingCardChannel tampered = new TamperingCardChannel(
        raw, ProtocolConstants.INS_RETURN_VEHICLE & 0xFF) {
      @Override ResponseAPDU tamper(ResponseAPDU real) {
        byte[] data = real.getData();
        if (data == null || data.length < 3) return real;
        byte[] out = Arrays.copyOf(data, data.length);
        out[2] ^= 0x01;
        byte[] resp = new byte[out.length + 2];
        System.arraycopy(out, 0, resp, 0, out.length);
        resp[out.length]     = (byte) 0x90;
        resp[out.length + 1] = (byte) 0x00;
        return new ResponseAPDU(resp);
      }
    };

    CardComm comm = issueOnChannel(tampered);
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);
    byte[] pkc = unwrap(rt.mutualAuth(PIN));
    doAssign(comm, pkc);

    TestVehicleTerminal vt = new TestVehicleTerminal(comm, backend.getMasterPublicKey(),
        backend.getTerminalKeyPair(), backend.getTerminalCertificate(), VEHICLE_ID);
    byte[] cardPkc = unwrap(vt.open());

    Result<byte[]> result = vt.returnVehicle((short) 0, cardPkc);
    check("fake return receipt rejected by vehicle terminal", !result.success);
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  static void setup() throws Exception {
    BackendSystem.reset();
    backend = BackendSystem.getInstance();
    backend.init();
    backend.registerVehicle(VEHICLE_ID, "ADV-VEH");
    backend.registerCustomer(CUSTOMER_ID, "Adversary");
  }

  // Raw channel: simulator installed, applet selected, card NOT yet personalized.
  static CardChannel freshRawChannel() throws Exception {
    String termName = "ADV-" + (++testNum);
    CardTerminals terminals = CardTerminalSimulator.terminals(termName);
    CardTerminal terminal = terminals.getTerminal(termName);
    CardSimulator simulator = new CardSimulator();
    AID aid = new AID(APPLET_AID, (byte) 0, (byte) APPLET_AID.length);
    simulator.installApplet(aid, RentalCardApplet.class);
    simulator.assignToTerminal(terminal);
    Card card = terminal.connect("*");
    CardChannel channel = card.getBasicChannel();
    channel.transmit(new CommandAPDU(
        (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, APPLET_AID));
    return channel;
  }

  // Personalize + issue a card reachable via the given channel.
  static CardComm issueOnChannel(CardChannel channel) throws Exception {
    CardComm comm = new CardComm(channel);
    PersonalizationTerminal pt = new PersonalizationTerminal(comm, backend);
    pt.personalizeCard(CARD_ID, PIN);
    pt.issueCard(CUSTOMER_ID);
    return comm;
  }

  // Fresh issued card on a plain (non-tampering) channel.
  static CardComm freshIssuedCard() throws Exception {
    return issueOnChannel(freshRawChannel());
  }

  // Terminal auth step only (no PIN, no card auth).
  static void doTerminalAuth(CardComm comm) throws Exception {
    byte[] nonce    = unwrap(comm.send(ProtocolConstants.INS_GET_NONCE));
    byte[] termSig  = CryptoUtil.sign(backend.getTerminalKeyPair().getPrivate(), nonce);
    byte[] termCert = backend.getTerminalCertificate();
    byte[] payload  = ByteUtil.concat(
        ByteUtil.shortToBytes((short) termSig.length), termSig, termCert);
    unwrap(comm.send(ProtocolConstants.INS_VERIFY_TERMINAL_SIG, payload));
  }

  // Full vehicle assignment (mutual auth must already be done, pkc provided).
  static void doAssign(CardComm comm, byte[] pkc) throws Exception {
    TestReceptionTerminal rt = new TestReceptionTerminal(comm, backend);
    long now      = System.currentTimeMillis() / 1000;
    byte[] period = periodBytes(now, now + 86400);
    unwrap(rt.assignVehicle(VEHICLE_ID, CUSTOMER_ID, pkc, period));
    rt.auditLog.flushToBackend(backend);
  }

  // Encode rental period as 4B start + 4B end (matching card's RENTAL_PERIOD_LENGTH=8).
  static byte[] periodBytes(long start, long end) {
    byte[] buf = new byte[8];
    buf[0] = (byte) ((start >> 24) & 0xFF);
    buf[1] = (byte) ((start >> 16) & 0xFF);
    buf[2] = (byte) ((start >>  8) & 0xFF);
    buf[3] = (byte) (start & 0xFF);
    buf[4] = (byte) ((end >> 24) & 0xFF);
    buf[5] = (byte) ((end >> 16) & 0xFF);
    buf[6] = (byte) ((end >>  8) & 0xFF);
    buf[7] = (byte) (end & 0xFF);
    return buf;
  }

  static <T> T unwrap(Result<T> r) {
    if (!r.success) throw new RuntimeException("Result.fail: " + r.error.getMessage(), r.error);
    return r.value;
  }

  static void check(String desc, boolean condition) {
    if (condition) {
      System.out.println("  PASS: " + desc);
      passed++;
    } else {
      System.out.println("  FAIL: " + desc);
      failed++;
    }
  }

  // ---------------------------------------------------------------------------
  // TamperingCardChannel
  // ---------------------------------------------------------------------------

  /**
   * Wraps a real CardChannel and intercepts responses for one specific INS byte.
   * Subclasses override tamper() to corrupt the real response as desired.
   */
  abstract static class TamperingCardChannel extends CardChannel {
    protected final CardChannel delegate;
    private final int interceptIns;

    TamperingCardChannel(CardChannel delegate, int interceptIns) {
      this.delegate = delegate;
      this.interceptIns = interceptIns;
    }

    abstract ResponseAPDU tamper(ResponseAPDU real);

    @Override
    public ResponseAPDU transmit(CommandAPDU cmd) throws CardException {
      ResponseAPDU real = delegate.transmit(cmd);
      if ((cmd.getINS() & 0xFF) == interceptIns) {
        return tamper(real);
      }
      return real;
    }

    @Override
    public int transmit(ByteBuffer command, ByteBuffer response) throws CardException {
      return delegate.transmit(command, response);
    }

    @Override public Card getCard()          { return delegate.getCard(); }
    @Override public int  getChannelNumber() { return delegate.getChannelNumber(); }
    @Override public void close() throws CardException { delegate.close(); }
  }
}
