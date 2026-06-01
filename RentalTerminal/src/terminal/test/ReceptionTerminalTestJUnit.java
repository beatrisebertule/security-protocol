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
}
