package terminal.backend;

public class Vehicle {
    private final byte[] id;
    private final String plate;
    private boolean available;
    private byte[] assignedCustomerId;

    public Vehicle(byte[] id, String plate) {
        this.id = id;
        this.plate = plate;
        this.available = true;
        this.assignedCustomerId = null;
    }

    public byte[] getId() { return id; }
    public String getPlate() { return plate; }
    public boolean isAvailable() { return available; }
    public byte[] getAssignedCustomerId() { return assignedCustomerId; }

    public void assign(byte[] customerId) {
        this.available = false;
        this.assignedCustomerId = customerId;
    }

    public void release() {
        this.available = true;
        this.assignedCustomerId = null;
    }
}
