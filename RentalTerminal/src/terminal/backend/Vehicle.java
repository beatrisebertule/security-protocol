package terminal.backend;

public class Vehicle {
  private final byte[] id;
  private final String plate;
  private boolean available;
  private byte[] assignedCustomerId;

  public Vehicle(byte[] id, String plate) {
    this.id = id;
    this.plate = plate; // NOTE plate and id are both unique but a plate can change while the id cannot
    this.available = true;
    this.assignedCustomerId = null;
  }

  public byte[] getId() {
    return id;
  }

  public String getPlate() {
    return plate;
  }

  public boolean isAvailable() {
    return available;
  }

  public byte[] getAssignedCustomerId() {
    return assignedCustomerId;
  }

  public void assign(byte[] customerId) {
    this.available = false;
    this.assignedCustomerId = customerId;
  }

  public void release() {
    this.available = true;
    this.assignedCustomerId = null;
  }

  public void changePlate(String newPlate) {
    // NOTE  this method is meant for changing the plate when the vehicle goes to for example another country or gets its plate,
    // when it is a new vehicle. In our implementation we do not use this method, but this is meant for further extension.
    this.plate = newPlate;
  }
}
