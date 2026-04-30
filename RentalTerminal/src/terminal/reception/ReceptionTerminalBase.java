public class ReceptionTerminalBase { //TODO: fix the TODO's and merge with Reception Terminal.
  protected final CardComm comm;
  protected final BackendSystem backend;

  public ReceptionTerminalBase(CardComm comm, BackendSystem backend) {
    this.comm = comm;
    this.backend = backend;
  }

  // --- Vehicle management ---

  private List<Vehicle> getAvailableVehicles() { //TODO: Should we return the vhicles or should we just let the backend handle this??
    List<Vehicle> available = new ArrayList<>();
    for (Vehicle v : backend.getAllVehicles()) {
      if (v.isAvailable()) {
        available.add(v);
      }
    }
    return available;
  }
  protected abstract byte[] getCardPkc(); //TODO: This is meant to be implemented by the CLI reception terminal, but not by the UI reception terminal, this way we can separate the logic of the reception terminal from the interface of the reception terminal, which is a good design principle.

  protected abstract Vehicle chooseVehicle(List<Vehicle> vehicles); // TODO

  protected abstract void showAvailableVehicles(List<Vehicle> vehicles); //TODO: This is meant to be implemented by the CLI reception terminal, but not by the UI reception terminal, this way we can separate the logic of the reception terminal from the interface of the reception terminal, which is a good design principle.

  //TODO: place some functions from the reception terminal here and make some abstract methods that the reception terminal has to implement, this way we can extend the reception terminal with different interfaces and not have to change the logic of the reception terminal itself. This is also a way to separate the logic of the reception terminal from the interface of the reception terminal, which is a good design principle.
    public void VehicleSelection(){       
        List<Vehicle> available = getAvailableVehicles();
        showAvailableVehicles(available);
        Vehicle selected = chooseVehicle(available);
        if (selected != null) {
            //No vehicle selected, return to main menu
            return;
        }
        // Vehicle selected, verify the card.
        byte[] cardPkc = getCardPkc();
        if (!verifyCard(cardPkc)) {
            // Card verification failed, return to main menu
            return;
        }
        byte[] customer = backend.getCustomerByCardPkc(cardPkc);
        // The card is now verified, we can assign the vehicle. We need an transaction for this part.
        JCSystem.beginTransaction();
        // TODO: Get sigma_3 from the card and verify it, if it is not correct, we should not assign the vehicle and return to the main menu.
        byte[] sigma3 = 0 //TODO: get sigma_3 from the card
         if (!verifySigma3(sigma3)) {
            // Sigma_3 verification failed, return to main menu
            JCSystem.abortTransaction();
            return;
        }

        backend.assignVehicle(selected.getId(), customer);
        // TODO: get sigma_4
        var sigma4 = backend.signAssignmentToken(sigma3, TODO); // TODO: get the correct key material

        //Store the sigma4 on the card, if this fails, we should abort the transaction and return to the main menu, as the assignment is not complete without storing sigma_4 on the card.
        if (!storeSigma4OnCard(sigma4)) {
            // Storing sigma_4 on the card failed, return to main menu
            JCSystem.abortTransaction();
            return;
        }

        // If everything is successfull, we can complete the assignement at the backend.
        backend.completeAssignment(selected.getId(), customer);
        JCSystem.commitTransaction();
    }
    private boolean storeSigma4OnCard(byte[] sigma4) {
      comm.
    }

    private boolean verifySigma3(byte[] sigma3) {
      //TODO: Implement this
    }

    private boolean verifyCard(byte[] cardPkc) {
        // TODO: Implement the verifying of the card...

        //
    }
}