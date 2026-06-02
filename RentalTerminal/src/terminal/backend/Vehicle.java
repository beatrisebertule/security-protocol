package terminal.backend;

import terminal.util.ByteUtil;
import java.util.Arrays;

public class Vehicle {
  private final byte[] id;
  private String plate;
  private boolean available;
  private byte[] assignedCustomerId;
  private long assignmentTime;

  public Vehicle(byte[] id, String plate) {
    this.id = id;
    this.plate = plate; // NOTE plate and id are both unique but a plate can change while the id cannot
    this.available = true;
    this.assignedCustomerId = null;
    this.assignmentTime = 0;
  }

  public byte[] getId() {
    return id;
  }

  public String getPlate() {
    return plate;
  }

  public boolean isAvailable() {
    return available && assignedCustomerId == null;
  }

  /**
   * When a vehicle is assigned to a customer, the assignment is initially
   * temporary: the card must complete the full assignment protocol (signing the
   * vehicle request and storing the token) within 30 minutes. If that does not
   * happen - for example because the card failed mid-protocol or the customer
   * walked away - the vehicle would be stuck as "pending" forever. Calling this
   * method releases the vehicle back to available in that case, so it can be
   * assigned to another customer. The method is a no-op if no such timeout has
   * occurred.
   */
  public void checkAndReleaseTimeout() {
    if (assignedCustomerId != null && (System.currentTimeMillis() - assignmentTime) > 30 * 60 * 1000) {
      release();
    }
  }

  public byte[] getAssignedCustomerId() {
    return assignedCustomerId;
  }

  public void assign(byte[] customerId) {
    this.assignedCustomerId = customerId;
    this.assignmentTime = System.currentTimeMillis();
  }

  public void completeAssignment(byte[] customerId) {
    if (assignedCustomerId != null && Arrays.equals(assignedCustomerId, customerId)) {
      this.available = false; // The vehicle is now officially assigned to the customer, it will only be
                              // released when the customer returns the vehicle.
    }
  }

  public void release() {
    this.available = true;
    this.assignedCustomerId = null;
  }

  public void changePlate(String newPlate) {
    // NOTE this method is meant for changing the plate when the vehicle goes to for
    // example another country or gets its plate,
    // when it is a new vehicle. In our implementation we do not use this method,
    // but this is meant for further extension..
    this.plate = newPlate;
  }
}
