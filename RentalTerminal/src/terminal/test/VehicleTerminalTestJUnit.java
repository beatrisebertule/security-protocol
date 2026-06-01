package terminal.test;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
public class VehicleTerminalTestJUnit {
  @Before public void reset() { VehicleTerminalTest.passed=0; VehicleTerminalTest.failed=0; }
  @Test public void openAndUpdate() throws Exception { VehicleTerminalTest.testOpenAndUpdate(); assertEquals(0,VehicleTerminalTest.failed); }
  @Test public void returnAndFlush() throws Exception { VehicleTerminalTest.testReturnAndFlush(); assertEquals(0,VehicleTerminalTest.failed); }
  @Test public void wrongVehicleRejected() throws Exception { VehicleTerminalTest.testWrongVehicleRejected(); assertEquals(0,VehicleTerminalTest.failed); }
}
