package terminal.simulator;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import javacard.framework.AID;
import javax.smartcardio.*;
import applet.RentalCardApplet;

import terminal.backend.BackendSystem;
import terminal.backend.Vehicle;
import terminal.common.ByteUtil;
import terminal.common.CardComm;
import terminal.common.ProtocolConstants;
import terminal.common.Result;
import terminal.personalization.PersonalizationTerminal;
import terminal.reception.ReceptionTerminal;
import terminal.vehicle.VehicleTerminal;

import java.util.*;

import org.jline.reader.*;
import org.jline.reader.impl.completer.*;
import org.jline.terminal.*;

public class SystemSimulator {

  static final byte[] APPLET_AID = {
      (byte) 0x3B, (byte) 0x29, (byte) 0x72, (byte) 0x65, (byte) 0x6E, (byte) 0x74, (byte) 0x01
  };

  static class CardSession {
    String cardIdHex;
    byte[] cardIdBytes;
    String pin;
    String customerName;
    byte[] customerId;
    CardComm comm;
    CardChannel channel;
    byte[] lastPkc;
  }

  static final byte[][] VEHICLE_IDS = {
      { 0x00, 0x00, 0x00, 0x01 }, { 0x00, 0x00, 0x00, 0x02 }, { 0x00, 0x00, 0x00, 0x03 }
  };
  static final String[] VEHICLE_PLATES = { "AB-001-CD", "EF-002-GH", "IJ-003-KL" };

  static final byte[][] CUSTOMER_IDS = {
      { 0x00, 0x00, 0x00, 0x01 }, { 0x00, 0x00, 0x00, 0x02 }, { 0x00, 0x00, 0x00, 0x03 }
  };
  static final String[] CUSTOMER_NAMES = { "Alice", "Bob", "Charlie" };

  static BackendSystem backend;
  static Map<String, CardSession> cards = new LinkedHashMap<>();
  static String activeCardId = null;
  static int cardCounter = 0;
  static LineReader reader;

  static final List<String> TOP_COMMANDS = Arrays.asList(
      "help", "status", "new", "use", "cards", "reception", "vehicle", "log", "exit");

  static Completer buildCompleter() {
    return (reader, line, candidates) -> {
      String word = line.word();
      int wordIndex = line.wordIndex();
      List<String> words = line.words();

      if (wordIndex == 0) {
        for (String cmd : TOP_COMMANDS) {
          if (cmd.startsWith(word)) candidates.add(new Candidate(cmd));
        }
      } else if (wordIndex == 1 && !words.isEmpty() && "use".equals(words.get(0))) {
        for (String id : cards.keySet()) {
          if (id.startsWith(word)) candidates.add(new Candidate(id));
        }
      }
    };
  }

  public static void main(String[] args) throws Exception {
    BackendSystem.reset();
    backend = BackendSystem.getInstance();
    backend.init();

    for (int i = 0; i < VEHICLE_IDS.length; i++) {
      backend.registerVehicle(VEHICLE_IDS[i], VEHICLE_PLATES[i]);
    }
    for (int i = 0; i < CUSTOMER_IDS.length; i++) {
      backend.registerCustomer(CUSTOMER_IDS[i], CUSTOMER_NAMES[i]);
    }

    Terminal terminal = TerminalBuilder.builder().system(true).build();
    reader = LineReaderBuilder.builder()
        .terminal(terminal)
        .completer(buildCompleter())
        .option(LineReader.Option.CASE_INSENSITIVE, true)
        .build();

    System.out.println("=== Vehicle Rental Smartcard System Simulator ===");
    System.out.println("Type 'help' for commands. Tab completes commands and card IDs.");

    boolean running = true;
    while (running) {
      String line;
      try {
        line = reader.readLine(prompt());
      } catch (UserInterruptException | EndOfFileException e) {
        break;
      }
      line = line.trim();
      if (line.isEmpty())
        continue;
      String[] parts = line.split("\\s+", 2);
      String cmd = parts[0].toLowerCase();

      switch (cmd) {
        case "help":
          printHelp();
          break;
        case "status":
          printStatus();
          break;
        case "new":
          cmdNew();
          break;
        case "use":
          cmdUse(parts.length > 1 ? parts[1] : "");
          break;
        case "cards":
          printCards();
          break;
        case "reception":
          cmdReception();
          break;
        case "vehicle":
          cmdVehicle();
          break;
        case "log":
          printLog();
          break;
        case "exit":
          running = false;
          break;
        default:
          System.out.println("Unknown command. Type 'help'.");
      }
    }
    System.out.println("Bye.");
  }

  static String prompt() {
    if (activeCardId == null)
      return "[no card] > ";
    CardSession cs = cards.get(activeCardId);
    String state = "?";
    try {
      selectApplet(cs.channel);
      byte[] data = cs.comm.sendCommandChecked(ProtocolConstants.INS_GET_STATE);
      state = stateString(data[0]);
    } catch (Exception e) {
      /* ignore */ }
    return "[card:" + activeCardId + " " + state + "] > ";
  }

  static void selectApplet(CardChannel channel) throws Exception {
    channel.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, APPLET_AID));
  }

  static String stateString(byte s) {
    switch (s) {
      case ProtocolConstants.STATE_BLANK:
        return "BLANK";
      case ProtocolConstants.STATE_PERSONALIZED:
        return "PERSONALIZED";
      case ProtocolConstants.STATE_ISSUED:
        return "ISSUED";
      case ProtocolConstants.STATE_ASSIGNED:
        return "ASSIGNED";
      case ProtocolConstants.STATE_BLOCKED:
        return "BLOCKED";
      case ProtocolConstants.STATE_END_OF_LIFE:
        return "END_OF_LIFE";
      default:
        return "UNKNOWN";
    }
  }

  static void printHelp() {
    System.out.println("Commands:");
    System.out.println("  help            - list commands");
    System.out.println("  status          - show system status");
    System.out.println("  new             - create and issue a new card");
    System.out.println("  use <cardId>    - switch active card");
    System.out.println("  cards           - list all cards");
    System.out.println("  reception       - reception terminal sub-session");
    System.out.println("  vehicle         - vehicle terminal sub-session");
    System.out.println("  log             - print audit log");
    System.out.println("  exit            - quit");
  }

  static void printStatus() {
    System.out.println("--- Vehicles ---");
    for (int i = 0; i < VEHICLE_IDS.length; i++) {
      Vehicle v = backend.getVehicle(VEHICLE_IDS[i]);
      if (v == null)
        continue;
      String avail = v.isAvailable() ? "AVAILABLE" : "IN USE";
      System.out.println("  " + v.getPlate() + " [" + ByteUtil.toHex(v.getId()) + "] " + avail);
    }
    System.out.println("--- Cards ---");
    if (cards.isEmpty()) {
      System.out.println("  (none)");
    } else {
      for (CardSession cs : cards.values()) {
        String state = "?";
        try {
          selectApplet(cs.channel);
          byte[] data = cs.comm.sendCommandChecked(ProtocolConstants.INS_GET_STATE);
          state = stateString(data[0]);
        } catch (Exception e) {
          /* ignore */ }
        String mark = cs.cardIdHex.equals(activeCardId) ? " *" : "";
        System.out.println("  " + cs.cardIdHex + " customer=" + cs.customerName
            + " pin=" + cs.pin + " state=" + state + mark);
      }
    }
    System.out.println("--- Audit log: " + backend.getAuditLog().size() + " entries ---");
  }

  static void printCards() {
    if (cards.isEmpty()) {
      System.out.println("No cards.");
      return;
    }
    for (CardSession cs : cards.values()) {
      String state = "?";
      try {
        selectApplet(cs.channel);
        byte[] data = cs.comm.sendCommandChecked(ProtocolConstants.INS_GET_STATE);
        state = stateString(data[0]);
      } catch (Exception e) {
        /* ignore */ }
      String mark = cs.cardIdHex.equals(activeCardId) ? " [active]" : "";
      System.out.println("  " + cs.cardIdHex + " customer=" + cs.customerName + " state=" + state + mark);
    }
  }

  static void cmdNew() throws Exception {
    System.out.println("Customers:");
    for (int i = 0; i < CUSTOMER_NAMES.length; i++) {
      System.out.println("  " + i + ") " + CUSTOMER_NAMES[i]);
    }
    System.out.print("Select customer (0-2): ");
    int idx;
    try {
      idx = Integer.parseInt(reader.readLine("").trim());
    } catch (NumberFormatException e) {
      System.out.println("Invalid selection.");
      return;
    }
    if (idx < 0 || idx >= CUSTOMER_NAMES.length) {
      System.out.println("Invalid selection.");
      return;
    }
    System.out.print("PIN: ");
    String pin = reader.readLine("").trim();

    cardCounter++;
    byte[] cardId = { 0x00, 0x00, (byte) (cardCounter >> 8), (byte) (cardCounter & 0xFF) };
    String cardIdHex = ByteUtil.toHex(cardId);
    byte[] customerId = CUSTOMER_IDS[idx];

    String termName = "SIM-" + cardIdHex;
    CardTerminals terminals = CardTerminalSimulator.terminals(termName);
    CardTerminal terminal = terminals.getTerminal(termName);

    CardSimulator simulator = new CardSimulator();
    AID aid = new AID(APPLET_AID, (byte) 0, (byte) APPLET_AID.length);
    simulator.installApplet(aid, RentalCardApplet.class);
    simulator.assignToTerminal(terminal);

    Card card = terminal.connect("*");
    CardChannel channel = card.getBasicChannel();
    selectApplet(channel);

    CardComm comm = new CardComm(channel);

    PersonalizationTerminal pt = new PersonalizationTerminal(comm, backend);
    pt.personalizeCard(cardId, pin);
    pt.issueCard(customerId);
    backend.linkCardToCustomer(customerId, cardId);

    CardSession cs = new CardSession();
    cs.cardIdHex = cardIdHex;
    cs.cardIdBytes = cardId;
    cs.pin = pin;
    cs.customerName = CUSTOMER_NAMES[idx];
    cs.customerId = customerId;
    cs.comm = comm;
    cs.channel = channel;
    cs.lastPkc = null;

    cards.put(cardIdHex, cs);
    activeCardId = cardIdHex;
    System.out.println("Card " + cardIdHex + " created for " + CUSTOMER_NAMES[idx] + ". Now active.");
  }

  static void cmdUse(String cardId) {
    if (cardId.isEmpty()) {
      System.out.println("Usage: use <cardId>");
      return;
    }
    if (!cards.containsKey(cardId)) {
      System.out.println("Card not found: " + cardId);
      return;
    }
    activeCardId = cardId;
    System.out.println("Active card: " + cardId);
  }

  static void cmdReception() {
    if (activeCardId == null) {
      System.out.println("No active card. Use 'new' or 'use <cardId>'.");
      return;
    }
    CardSession cs = cards.get(activeCardId);
    try {
      selectApplet(cs.channel);
    } catch (Exception e) {
      System.out.println("Failed to select applet: " + e.getMessage());
      return;
    }

    ReceptionTerminal rt = new ReceptionTerminal(cs.comm, backend);

    Result<Byte> stateResult = rt.getCardState();
    if (stateResult.success) {
      System.out.println("Card state: " + stateString(stateResult.value));
    } else {
      System.out.println("Cannot read state: " + stateResult.error.getMessage());
    }

    System.out.print("PIN: ");
    String pin = reader.readLine("").trim();

    Result<byte[]> authResult = rt.mutualAuth(pin);
    if (!authResult.success) {
      System.out.println("Auth failed: " + authResult.error.getMessage());
      return;
    }
    byte[] pkc = authResult.value;
    cs.lastPkc = pkc;
    System.out.println("Authentication successful.");

    boolean sub = true;
    while (sub) {
      System.out.println("1) Assign vehicle  2) Process payment  3) Card state  0) Back");
      System.out.print("Choice: ");
      String choice = reader.readLine("").trim();
      switch (choice) {
        case "1":
          receptionAssignVehicle(rt, cs, pkc);
          break;
        case "2":
          Result<Integer> payResult = rt.processMileagePayment(cs.customerId);
          if (payResult.success) {
            System.out.println("Payment processed. Mileage paid: " + payResult.value + " km");
          } else {
            System.out.println("Payment failed: " + payResult.error.getMessage());
          }
          break;
        case "3":
          Result<Byte> stR = rt.getCardState();
          if (stR.success) {
            System.out.println("State: " + stateString(stR.value));
          } else {
            System.out.println("Error: " + stR.error.getMessage());
          }
          break;
        case "0":
          sub = false;
          break;
        default:
          System.out.println("Unknown option.");
      }
    }
  }

  static void receptionAssignVehicle(ReceptionTerminal rt, CardSession cs, byte[] pkc) {
    List<Vehicle> available = backend.getAvailableVehicles();
    if (available.isEmpty()) {
      System.out.println("No vehicles available.");
      return;
    }
    System.out.println("Available vehicles:");
    for (int i = 0; i < available.size(); i++) {
      Vehicle v = available.get(i);
      System.out.println("  " + i + ") " + v.getPlate() + " [" + ByteUtil.toHex(v.getId()) + "]");
    }
    System.out.print("Select vehicle (index): ");
    int idx;
    try {
      idx = Integer.parseInt(reader.readLine("").trim());
    } catch (NumberFormatException e) {
      System.out.println("Invalid selection.");
      return;
    }
    if (idx < 0 || idx >= available.size()) {
      System.out.println("Invalid selection.");
      return;
    }
    Vehicle vehicle = available.get(idx);
    long now = System.currentTimeMillis() / 1000;
    long end = now + 7 * 24 * 3600;
    byte[] period = periodBytes(now, end);
    Result<Void> assignResult = rt.assignVehicle(vehicle.getId(), cs.customerId, pkc, period);
    if (assignResult.success) {
      System.out.println("Vehicle assigned: " + vehicle.getPlate());
    } else {
      System.out.println("Assignment failed: " + assignResult.error.getMessage());
    }
  }

  static void cmdVehicle() {
    if (activeCardId == null) {
      System.out.println("No active card. Use 'new' or 'use <cardId>'.");
      return;
    }
    CardSession cs = cards.get(activeCardId);
    try {
      selectApplet(cs.channel);
    } catch (Exception e) {
      System.out.println("Failed to select applet: " + e.getMessage());
      return;
    }

    // Show all vehicles with availability
    System.out.println("Vehicles:");
    for (int i = 0; i < VEHICLE_IDS.length; i++) {
      Vehicle v = backend.getVehicle(VEHICLE_IDS[i]);
      if (v == null)
        continue;
      String avail = v.isAvailable() ? "AVAILABLE" : "IN USE";
      System.out.println("  " + i + ") " + v.getPlate() + " [" + ByteUtil.toHex(v.getId()) + "] " + avail);
    }
    System.out.print("Select vehicle (index): ");
    int idx;
    try {
      idx = Integer.parseInt(reader.readLine("").trim());
    } catch (NumberFormatException e) {
      System.out.println("Invalid selection.");
      return;
    }
    if (idx < 0 || idx >= VEHICLE_IDS.length) {
      System.out.println("Invalid selection.");
      return;
    }
    byte[] vehicleId = VEHICLE_IDS[idx];

    VehicleTerminal vt = new VehicleTerminal(cs.comm, backend.getMasterPublicKey(), vehicleId);

    Result<Byte> vtStateResult = vt.getCardState();
    if (vtStateResult.success) {
      System.out.println("Card state: " + stateString(vtStateResult.value));
    } else {
      System.out.println("Cannot read state: " + vtStateResult.error.getMessage());
    }

    byte[] sessionPkc = null;

    boolean sub = true;
    while (sub) {
      System.out
          .println("1) Open vehicle  2) Update mileage  3) Return vehicle  4) Get mileage  5) Card state  0) Back");
      System.out.print("Choice: ");
      String choice = reader.readLine("").trim();
      switch (choice) {
        case "1":
          Result<byte[]> openResult = vt.openVehicle();
          if (openResult.success) {
            sessionPkc = openResult.value;
            System.out.println("Vehicle opened. Card pkc: " + sessionPkc.length + "B");
          } else {
            System.out.println("Open failed: " + openResult.error.getMessage());
          }
          break;
        case "2":
          if (sessionPkc == null) {
            System.out.println("Must open vehicle first.");
            break;
          }
          System.out.print("Mileage to add (km): ");
          try {
            short km = Short.parseShort(reader.readLine("").trim());
            Result<Void> updResult = vt.updateMileage(km);
            if (updResult.success) {
              System.out.println("Mileage updated.");
            } else {
              System.out.println("Update failed: " + updResult.error.getMessage());
            }
          } catch (NumberFormatException e) {
            System.out.println("Invalid number.");
          }
          break;
        case "3":
          if (sessionPkc == null) {
            System.out.println("Must open vehicle first.");
            break;
          }
          System.out.print("Final mileage (km): ");
          try {
            short fm = Short.parseShort(reader.readLine("").trim());
            Result<byte[]> retResult = vt.returnVehicle(fm, sessionPkc);
            if (retResult.success) {
              vt.flushLogsToBackend(backend);
              backend.releaseVehicle(vehicleId);
              sessionPkc = null;
              System.out.println("Vehicle returned. Receipt: " + retResult.value.length + "B");
            } else {
              System.out.println("Return failed: " + retResult.error.getMessage());
            }
          } catch (NumberFormatException e) {
            System.out.println("Invalid number.");
          }
          break;
        case "4":
          Result<Short> milResult = vt.getMileage();
          if (milResult.success) {
            System.out.println("Current mileage: " + milResult.value + " km");
          } else {
            System.out.println("Error: " + milResult.error.getMessage());
          }
          break;
        case "5":
          Result<Byte> vtSt = vt.getCardState();
          if (vtSt.success) {
            System.out.println("State: " + stateString(vtSt.value));
          } else {
            System.out.println("Error: " + vtSt.error.getMessage());
          }
          break;
        case "0":
          sub = false;
          break;
        default:
          System.out.println("Unknown option.");
      }
    }
    if (sessionPkc == null) {
      vt.flushLogsToBackend(backend);
    }
  }

  static void printLog() {
    List<BackendSystem.AuditEntry> log = backend.getAuditLog();
    if (log.isEmpty()) {
      System.out.println("Audit log empty.");
      return;
    }
    for (BackendSystem.AuditEntry e : log) {
      String cardHex = e.cardId != null ? ByteUtil.toHex(e.cardId) : "-";
      String vehicleHex = e.vehicleId != null ? ByteUtil.toHex(e.vehicleId) : "-";
      String evidence = e.cryptoEvidence != null ? "[" + e.cryptoEvidence.length + "B]" : "-";
      System.out.printf("  %-20s card=%-10s vehicle=%-10s evidence=%-10s%n",
          e.eventType, cardHex, vehicleHex, evidence);
    }
  }

  static byte[] periodBytes(long startSecs, long endSecs) {
    byte[] b = new byte[8];
    b[0] = (byte) ((startSecs >> 24) & 0xFF);
    b[1] = (byte) ((startSecs >> 16) & 0xFF);
    b[2] = (byte) ((startSecs >> 8) & 0xFF);
    b[3] = (byte) (startSecs & 0xFF);
    b[4] = (byte) ((endSecs >> 24) & 0xFF);
    b[5] = (byte) ((endSecs >> 16) & 0xFF);
    b[6] = (byte) ((endSecs >> 8) & 0xFF);
    b[7] = (byte) (endSecs & 0xFF);
    return b;
  }
}
