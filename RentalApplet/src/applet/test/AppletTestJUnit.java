package applet.test;

import applet.RentalCardApplet;

import com.licel.jcardsim.io.JavaxSmartCardInterface;
import javacard.framework.AID;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertEquals;

/** JUnit4 wrapper around AppletTest for PIT mutation testing. */
public class AppletTestJUnit {

  @Before
  public void setup() throws Exception {
    AppletTest.passed = 0;
    AppletTest.failed = 0;
    AppletTest.masterKeyPair  = AppletTest.generateKeyPair();
    AppletTest.terminalKeyPair = AppletTest.generateKeyPair();
    AppletTest.sim = new JavaxSmartCardInterface();
    AID aid = new AID(AppletTest.APPLET_AID, (byte) 0, (byte) AppletTest.APPLET_AID.length);
    AppletTest.sim.installApplet(aid, RentalCardApplet.class);
    AppletTest.sim.selectApplet(aid);
  }

  /**
   * Test PERSONALIZE_FINISH without PIN set - kills isPinSet BooleanTrueReturnValsMutator.
   * Uses a fresh simulator; does not depend on fullLifecycle state.
   */
  @Test
  public void testPersonalizeFinishWithoutPin() throws Exception {
    AppletTest.passed = 0;
    AppletTest.failed = 0;
    AppletTest.testPersonalizeFinishWithoutPin();
    assertEquals(0, AppletTest.failed);
  }

  /**
   * Test correct PIN verify returns 9000 - kills verify BooleanFalseReturnValsMutator.
   * Runs full lifecycle up to and including authentication, then verifies correct PIN SW.
   */
  @Test
  public void testCorrectAndWrongPinVerification() throws Exception {
    AppletTest.passed = 0;
    AppletTest.failed = 0;
    // Build up state to ISSUED so PIN verification is possible
    AppletTest.testGetStateBlank();
    AppletTest.testPersonalizeKeys();
    AppletTest.testPersonalizePin();
    AppletTest.testPersonalizeFinishIncomplete();
    AppletTest.testPersonalizeFinish();
    AppletTest.testIssueCard();
    AppletTest.testGetNonce();
    AppletTest.testMutualAuth();
    AppletTest.testCorrectPinVerification();
    AppletTest.testWrongPinVerification();
    assertEquals(0, AppletTest.failed);
  }

  /** Sequential lifecycle test - methods share simulator state, must run in order. */
  @Test
  public void fullLifecycle() throws Exception {
    AppletTest.testGetStateBlank();
    AppletTest.testPersonalizeKeys();
    AppletTest.testPersonalizePin();
    AppletTest.testPersonalizeFinishIncomplete();
    AppletTest.testPersonalizeFinish();
    AppletTest.testIssueCard();
    AppletTest.testGetNonce();
    AppletTest.testMutualAuth();
    AppletTest.testPinVerification();
    AppletTest.testSignNonce();
    AppletTest.testVehicleAssignment();
    AppletTest.testMileage();
    AppletTest.testReturnVehicle();
    AppletTest.testClearMileage();
    AppletTest.testBlockCard();
    assertEquals(0, AppletTest.failed);
  }
}
