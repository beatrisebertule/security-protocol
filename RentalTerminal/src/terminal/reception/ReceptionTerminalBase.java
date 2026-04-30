public class ReceptionTerminalBase {
  protected final CardComm comm;
  protected final BackendSystem backend;

  public ReceptionTerminalBase(CardComm comm, BackendSystem backend) {
    this.comm = comm;
    this.backend = backend;
  }

  // --- Vehicle management ---

  public List<Vehicle> getAvailableVehicles() {
    List<Vehicle> available = new ArrayList<>();
    for (Vehicle v : backend.getAllVehicles()) {
      if (v.isAvailable()) {
        available.add(v);
      }
    }
  }

  public abstract void chooseVehicle(); // TODO

  public abstract void showAvailableVehicles(); //TODO: This is meant to be implemented by the CLI reception terminal, but not by the UI reception terminal, this way we can separate the logic of the reception terminal from the interface of the reception terminal, which is a good design principle.

  //TODO: place some functions from the reception terminal here and make some abstract methods that the reception terminal has to implement, this way we can extend the reception terminal with different interfaces and not have to change the logic of the reception terminal itself. This is also a way to separate the logic of the reception terminal from the interface of the reception terminal, which is a good design principle.

}