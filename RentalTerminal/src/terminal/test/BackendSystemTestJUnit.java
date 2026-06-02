package terminal.test;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

/** JUnit4 wrapper around BackendSystemTest for PIT mutation testing. */
public class BackendSystemTestJUnit {

  @Test
  public void testGetVehicleKnownAndUnknown() throws Exception {
    BackendSystemTest.passed = 0;
    BackendSystemTest.failed = 0;
    BackendSystemTest.testGetVehicleKnownAndUnknown();
    assertEquals(0, BackendSystemTest.failed);
  }

  @Test
  public void testGetCustomerKnownAndUnknown() throws Exception {
    BackendSystemTest.passed = 0;
    BackendSystemTest.failed = 0;
    BackendSystemTest.testGetCustomerKnownAndUnknown();
    assertEquals(0, BackendSystemTest.failed);
  }

  @Test
  public void testAssignVehicleReturnsTrue() throws Exception {
    BackendSystemTest.passed = 0;
    BackendSystemTest.failed = 0;
    BackendSystemTest.testAssignVehicleReturnsTrue();
    assertEquals(0, BackendSystemTest.failed);
  }

  @Test
  public void testAssignVehicleReturnsFalseWhenUnavailable() throws Exception {
    BackendSystemTest.passed = 0;
    BackendSystemTest.failed = 0;
    BackendSystemTest.testAssignVehicleReturnsFalseWhenUnavailable();
    assertEquals(0, BackendSystemTest.failed);
  }

  @Test
  public void testCompleteAssignmentUnknownVehicle() throws Exception {
    BackendSystemTest.passed = 0;
    BackendSystemTest.failed = 0;
    BackendSystemTest.testCompleteAssignmentUnknownVehicle();
    assertEquals(0, BackendSystemTest.failed);
  }

  @Test
  public void testLinkCardToCustomerUnknownCustomer() throws Exception {
    BackendSystemTest.passed = 0;
    BackendSystemTest.failed = 0;
    BackendSystemTest.testLinkCardToCustomerUnknownCustomer();
    assertEquals(0, BackendSystemTest.failed);
  }

  @Test
  public void testAddMileageToCustomerKnown() throws Exception {
    BackendSystemTest.passed = 0;
    BackendSystemTest.failed = 0;
    BackendSystemTest.testAddMileageToCustomerKnown();
    assertEquals(0, BackendSystemTest.failed);
  }

  @Test
  public void testAddMileageToCustomerUnknown() throws Exception {
    BackendSystemTest.passed = 0;
    BackendSystemTest.failed = 0;
    BackendSystemTest.testAddMileageToCustomerUnknown();
    assertEquals(0, BackendSystemTest.failed);
  }

  @Test
  public void testProcessPaymentKnown() throws Exception {
    BackendSystemTest.passed = 0;
    BackendSystemTest.failed = 0;
    BackendSystemTest.testProcessPaymentKnown();
    assertEquals(0, BackendSystemTest.failed);
  }

  @Test
  public void testProcessPaymentUnknown() throws Exception {
    BackendSystemTest.passed = 0;
    BackendSystemTest.failed = 0;
    BackendSystemTest.testProcessPaymentUnknown();
    assertEquals(0, BackendSystemTest.failed);
  }

  @Test
  public void testBlockCustomerKnown() throws Exception {
    BackendSystemTest.passed = 0;
    BackendSystemTest.failed = 0;
    BackendSystemTest.testBlockCustomerKnown();
    assertEquals(0, BackendSystemTest.failed);
  }

  @Test
  public void testBlockCustomerUnknown() throws Exception {
    BackendSystemTest.passed = 0;
    BackendSystemTest.failed = 0;
    BackendSystemTest.testBlockCustomerUnknown();
    assertEquals(0, BackendSystemTest.failed);
  }

  @Test
  public void testLogEventAppearsInAuditLog() throws Exception {
    BackendSystemTest.passed = 0;
    BackendSystemTest.failed = 0;
    BackendSystemTest.testLogEventAppearsInAuditLog();
    assertEquals(0, BackendSystemTest.failed);
  }

  @Test
  public void testLogEventNullCardId() throws Exception {
    BackendSystemTest.passed = 0;
    BackendSystemTest.failed = 0;
    BackendSystemTest.testLogEventNullCardId();
    assertEquals(0, BackendSystemTest.failed);
  }

  @Test
  public void testLogEventNullVehicleId() throws Exception {
    BackendSystemTest.passed = 0;
    BackendSystemTest.failed = 0;
    BackendSystemTest.testLogEventNullVehicleId();
    assertEquals(0, BackendSystemTest.failed);
  }

  @Test
  public void testLogEventTwiceNoThrow() throws Exception {
    BackendSystemTest.passed = 0;
    BackendSystemTest.failed = 0;
    BackendSystemTest.testLogEventTwiceNoThrow();
    assertEquals(0, BackendSystemTest.failed);
  }

  @Test
  public void testGetAuditLogByCardIdFiltersCorrectly() throws Exception {
    BackendSystemTest.passed = 0;
    BackendSystemTest.failed = 0;
    BackendSystemTest.testGetAuditLogByCardIdFiltersCorrectly();
    assertEquals(0, BackendSystemTest.failed);
  }

  @Test
  public void testVerifyAssignmentToken() throws Exception {
    BackendSystemTest.passed = 0;
    BackendSystemTest.failed = 0;
    BackendSystemTest.testVerifyAssignmentToken();
    assertEquals(0, BackendSystemTest.failed);
  }
}
