package terminal.backend;

public class Customer {
  private final byte[] id;
  private final String name;
  private byte[] cardId;
  private int outstandingMileage;
  private boolean blocked;

  public Customer(byte[] id, String name) {
    this.id = id;
    this.name = name;
    this.cardId = null;
    this.outstandingMileage = 0;
    this.blocked = false;
    // We might want to add more information about the customer for the information at the backend system/ on the terminal.
    // Things like banking information and contact information, but for our implementation we do not need this information.
  }

  public byte[] getId() {
    return id;
  }

  public String getName() {
    return name;
  }

  public byte[] getCardId() {
    return cardId;
  }

  public int getOutstandingMileage() {
    return outstandingMileage;
  }

  public boolean isBlocked() {
    return blocked;
  }

  public void setCardId(byte[] cardId) {
    this.cardId = cardId;
  }

  public void addMileage(int mileage) {
    this.outstandingMileage += mileage;
  }

  public void clearMileage() {
    this.outstandingMileage = 0;
  }

  public void block() {
    this.blocked = true;
  }
}
