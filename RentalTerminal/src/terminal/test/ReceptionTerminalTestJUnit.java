package terminal.test;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
public class ReceptionTerminalTestJUnit {
  @Before public void reset() { ReceptionTerminalTest.passed=0; ReceptionTerminalTest.failed=0; }
  @Test public void authSuccessBufferedLocally() throws Exception { ReceptionTerminalTest.testAuthSuccessBufferedLocally(); assertEquals(0,ReceptionTerminalTest.failed); }
  @Test public void authFailBufferedLocally() throws Exception { ReceptionTerminalTest.testAuthFailBufferedLocally(); assertEquals(0,ReceptionTerminalTest.failed); }
  @Test public void assignVehicleBufferedLocally() throws Exception { ReceptionTerminalTest.testAssignVehicleBufferedLocally(); assertEquals(0,ReceptionTerminalTest.failed); }
  @Test public void flushSendsToBackend() throws Exception { ReceptionTerminalTest.testFlushSendsToBackend(); assertEquals(0,ReceptionTerminalTest.failed); }
  @Test public void shutdownFlushesRemaining() throws Exception { ReceptionTerminalTest.testShutdownFlushesRemaining(); assertEquals(0,ReceptionTerminalTest.failed); }
  @Test public void blockedCardRejectedInMutualAuth() throws Exception { ReceptionTerminalTest.testBlockedCardRejectedInMutualAuth(); assertEquals(0,ReceptionTerminalTest.failed); }
  @Test public void wrongPinLogsAuthFailWithDetail() throws Exception { ReceptionTerminalTest.testWrongPinLogsAuthFailWithDetail(); assertEquals(0,ReceptionTerminalTest.failed); }
  @Test public void mutualAuthSuccessLogsWithEvidence() throws Exception { ReceptionTerminalTest.testMutualAuthSuccessLogsWithEvidence(); assertEquals(0,ReceptionTerminalTest.failed); }
  @Test public void mileagePaymentZeroMileage() throws Exception { ReceptionTerminalTest.testMileagePaymentZeroMileage(); assertEquals(0,ReceptionTerminalTest.failed); }
  @Test public void mileagePaymentNonZeroMileage() throws Exception { ReceptionTerminalTest.testMileagePaymentNonZeroMileage(); assertEquals(0,ReceptionTerminalTest.failed); }
  @Test public void assignVehicleAlreadyAssignedLogsFailure() throws Exception { ReceptionTerminalTest.testAssignVehicleAlreadyAssignedLogsFailure(); assertEquals(0,ReceptionTerminalTest.failed); }
}
