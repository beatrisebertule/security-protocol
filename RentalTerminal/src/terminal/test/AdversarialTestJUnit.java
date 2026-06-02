package terminal.test;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
public class AdversarialTestJUnit {
  @Before public void reset() { AdversarialTest.passed=0; AdversarialTest.failed=0; }
  @Test public void nonceReplay() throws Exception { AdversarialTest.testNonceReplay_SignatureInvalid(); assertEquals(0,AdversarialTest.failed); }
  @Test public void skipTerminalAuth() throws Exception { AdversarialTest.testSkipTerminalAuth_PinRejected(); assertEquals(0,AdversarialTest.failed); }
  @Test public void skipPinSignNonce() throws Exception { AdversarialTest.testSkipPin_SignNonceRejected(); assertEquals(0,AdversarialTest.failed); }
  @Test public void skipPinSignVehicleReq() throws Exception { AdversarialTest.testSkipPin_SignVehicleReqRejected(); assertEquals(0,AdversarialTest.failed); }
  @Test public void forgedVehicleToken() throws Exception { AdversarialTest.testForgedVehicleToken_CardRejects(); assertEquals(0,AdversarialTest.failed); }
  @Test public void mileageRollback() throws Exception { AdversarialTest.testMileageRollback_TerminalRejects(); assertEquals(0,AdversarialTest.failed); }
  @Test public void fakeCardCert() throws Exception { AdversarialTest.testMaliciousCard_FakeCardCert_TerminalRejects(); assertEquals(0,AdversarialTest.failed); }
  @Test public void corruptedCardSig() throws Exception { AdversarialTest.testMaliciousCard_CorruptedCardSig_TerminalRejects(); assertEquals(0,AdversarialTest.failed); }
  @Test public void fakeEphemeralToken() throws Exception { AdversarialTest.testMaliciousCard_FakeEphemeralToken_VehicleTerminalRejects(); assertEquals(0,AdversarialTest.failed); }
  @Test public void fakeReturnReceipt() throws Exception { AdversarialTest.testMaliciousCard_FakeReturnReceipt_VehicleTerminalRejects(); assertEquals(0,AdversarialTest.failed); }
}
