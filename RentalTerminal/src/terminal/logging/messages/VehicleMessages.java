package terminal.logging.messages;

/** Result message strings for VehicleTerminal operations. */
public final class VehicleMessages {

  private VehicleMessages() {}

  public static final String ERR_VEHICLE_TOKEN_INVALID =
      "Assignment token (vehicleToken) invalid";
  public static final String ERR_VEHICLE_TOKEN_CRYPTO =
      "vehicleToken verification crypto failure";
  public static final String ERR_WRONG_VEHICLE =
      "Card not assigned to this vehicle";
  public static final String ERR_REQ_VEHICLE_TOKEN_INVALID =
      "Assignment request signature (reqVehicleToken) invalid";
  public static final String ERR_REQ_VEHICLE_TOKEN_CRYPTO =
      "reqVehicleToken verification crypto failure";
  public static final String ERR_EPHEMERAL_TOKEN_INVALID =
      "Vehicle challenge signature (ephemeralVehicleToken) invalid";
  public static final String ERR_EPHEMERAL_TOKEN_CRYPTO =
      "ephemeralVehicleToken verification crypto failure";
  public static final String ERR_MILEAGE_ROLLBACK =
      "Mileage rollback detected";
  public static final String ERR_RECEIPT_MISSING_SIG =
      "Return receipt missing signature";
  public static final String ERR_RECEIPT_SIG_INVALID =
      "Return receipt signature invalid";
  public static final String ERR_RECEIPT_CRYPTO =
      "Return receipt verification crypto failure";

  public static final String ERR_TERMINAL_NONCE_REQUEST =
      "Failed to get nonce from card for terminal authentication";
  public static final String ERR_TERMINAL_AUTH_SIGNING =
      "Terminal authentication signing failure";
  public static final String ERR_TERMINAL_AUTH_FAILED =
      "Terminal authentication rejected by card";
  public static final String ERR_PIN_HASHING =
      "PIN hashing failure";
  public static final String ERR_PIN_REJECTED =
      "PIN rejected by card";

  public static String errCardNotAssigned(byte state) {
    String stateStr = getStateDescription(state);
    return "Card not in ASSIGNED state (state=0x" + String.format("%02X", state) + 
           (stateStr != null ? " - " + stateStr : "") + ")";
  }

  private static String getStateDescription(byte state) {
    switch (state) {
      case 0x00: return "BLANK - card not initialized";
      case 0x01: return "PERSONALIZED - card is personalized but not yet issued";
      case 0x02: return "ISSUED - card is issued but not assigned to any vehicle";
      case 0x03: return "ASSIGNED - card is assigned to a vehicle (expected state)";
      case 0x04: return "BLOCKED - card has been blocked";
      case 0x05: return "END_OF_LIFE - card is decommissioned";
      default: return null;
    }
  }
}
