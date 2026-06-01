package terminal.test;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

/** JUnit4 wrappers around ProtocolTest for PIT mutation testing. */
public class ProtocolTestJUnit {

  @Before
  public void reset() {
    ProtocolTest.passed = 0;
    ProtocolTest.failed = 0;
  }

  @Test public void wrongStateTransitions() throws Exception {
    ProtocolTest.testWrongStateTransitions(); assertEquals(0, ProtocolTest.failed);
  }
  @Test public void pinLockout() throws Exception {
    ProtocolTest.testPinLockout(); assertEquals(0, ProtocolTest.failed);
  }
  @Test public void tamperedSignature() throws Exception {
    ProtocolTest.testTamperedSignature(); assertEquals(0, ProtocolTest.failed);
  }
  @Test public void blockedCard() throws Exception {
    ProtocolTest.testBlockedCard(); assertEquals(0, ProtocolTest.failed);
  }
  @Test public void backendBlocklistEnforced() throws Exception {
    ProtocolTest.testBackendBlocklistEnforced(); assertEquals(0, ProtocolTest.failed);
  }
  @Test public void mileageReplay() throws Exception {
    ProtocolTest.testMileageReplay(); assertEquals(0, ProtocolTest.failed);
  }
  @Test public void unpaidMileageBlocksAssignment() throws Exception {
    ProtocolTest.testUnpaidMileageBlocksAssignment(); assertEquals(0, ProtocolTest.failed);
  }
  @Test public void loggingAuth() throws Exception {
    ProtocolTest.testLoggingAuth(); assertEquals(0, ProtocolTest.failed);
  }
  @Test public void loggingAssignmentAndVehicle() throws Exception {
    ProtocolTest.testLoggingAssignmentAndVehicle(); assertEquals(0, ProtocolTest.failed);
  }
  @Test public void loggingPaymentAndBlock() throws Exception {
    ProtocolTest.testLoggingPaymentAndBlock(); assertEquals(0, ProtocolTest.failed);
  }
  @Test public void endOfLife() throws Exception {
    ProtocolTest.testEndOfLife(); assertEquals(0, ProtocolTest.failed);
  }
  @Test public void vehicleReopenMidRental() throws Exception {
    ProtocolTest.testVehicleReopenMidRental(); assertEquals(0, ProtocolTest.failed);
  }
  @Test public void wrongVehicleRejected() throws Exception {
    ProtocolTest.testWrongVehicleRejected(); assertEquals(0, ProtocolTest.failed);
  }
  @Test public void flushLogsToBackend() throws Exception {
    ProtocolTest.testFlushLogsToBackend(); assertEquals(0, ProtocolTest.failed);
  }
  @Test public void noFlushMidRental() throws Exception {
    ProtocolTest.testNoFlushMidRental(); assertEquals(0, ProtocolTest.failed);
  }
  @Test public void flushAfterReturnIsNoop() throws Exception {
    ProtocolTest.testFlushAfterReturnIsNoop(); assertEquals(0, ProtocolTest.failed);
  }
}
