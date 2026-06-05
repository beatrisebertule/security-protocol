package terminal.simulation;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import javacard.framework.AID;
import javax.smartcardio.*;
import applet.RentalCardApplet;

import terminal.backend.BackendSystem;
import terminal.backend.Vehicle;
import terminal.util.ByteUtil;
import terminal.util.CardComm;
import terminal.util.CardUtil;
import terminal.util.ProtocolConstants;
import terminal.logging.Result;
import terminal.logging.TerminalOutput;
import terminal.personalization.PersonalizationTerminal;
import terminal.reception.ReceptionTerminal;
import terminal.vehicle.VehicleTerminal;

import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
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

  static final long DEFAULT_RENTAL_PERIOD_SECONDS = 7L * 24 * 3600;

  static BackendSystem backend;
  static Map<String, CardSession> cards = new LinkedHashMap<>();

  static byte[] unwrapData(Result<byte[]> r) {
    if (!r.success) throw new RuntimeException(r.error.getMessage(), r.error);
    return r.value;
  }

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
    reader = LineReaderBuilder
        .builder()
        .terminal(terminal)
        .completer(buildCompleter())
        .option(LineReader.Option.CASE_INSENSITIVE, true)
        .build();

    TerminalOutput.showMessage("=== Vehicle Rental Smartcard System Simulator ===");
    TerminalOutput.showMessage("Type 'help' for commands. Tab completes commands and card IDs.");

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
        case "help":   printHelp();  break;
        case "status": printStatus(); break;
        case "new":    cmdNew();     break;
        case "use":    cmdUse(parts.length > 1 ? parts[1] : ""); break;
        case "cards":  printCards(); break;
        case "reception": cmdReception(); break;
        case "vehicle":   cmdVehicle();   break;
        case "log":    printLog();   break;
        case "exit":   running = false; break;
        default: TerminalOutput.showMessage("Unknown command. Type 'help'.");
      }
    }
    TerminalOutput.showMessage("Bye.");
  }

  static String prompt() {
    if (activeCardId == null) return "[no card] > ";
    CardSession cs = cards.get(activeCardId);
    String state = "?";
    try {
      selectApplet(cs.channel);
      byte[] data = unwrapData(cs.comm.send(ProtocolConstants.INS_GET_STATE));
      state = stateString(data[0]);
    } catch (Exception e) { /* ignore */ }
    return "[card:" + activeCardId + " " + state + "] > ";
  }

  static void selectApplet(CardChannel channel) throws Exception {
    channel.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, APPLET_AID));
  }

  static String stateString(byte s) {
    switch (s) {
      case ProtocolConstants.STATE_BLANK:         return "BLANK";
      case ProtocolConstants.STATE_PERSONALIZED:  return "PERSONALIZED";
      case ProtocolConstants.STATE_ISSUED:        return "ISSUED";
      case ProtocolConstants.STATE_ASSIGNED:      return "ASSIGNED";
      case ProtocolConstants.STATE_BLOCKED:       return "BLOCKED";
      case ProtocolConstants.STATE_END_OF_LIFE:   return "END_OF_LIFE";
      default:                                    return "UNKNOWN";
    }
  }

  static void printHelp() {
    TerminalOutput.showMessage("Commands:\n"
        + "  help            - list commands\n"
        + "  status          - show system status\n"
        + "  new             - create and issue a new card\n"
        + "  use <cardId>    - switch active card\n"
        + "  cards           - list all cards\n"
        + "  reception       - reception terminal sub-session\n"
        + "  vehicle         - vehicle terminal sub-session\n"
        + "  log             - print audit log\n"
        + "  exit            - quit");
  }

  static void printStatus() {
    StringBuilder sb = new StringBuilder("--- Vehicles ---\n");
    for (int i = 0; i < VEHICLE_IDS.length; i++) {
      Vehicle v = backend.getVehicle(VEHICLE_IDS[i]);
      if (v == null) continue;
      sb.append("  ").append(v.getPlate()).append(" [").append(ByteUtil.toHex(v.getId())).append("] ")
          .append(v.isAvailable() ? "AVAILABLE" : "IN USE").append("\n");
    }
    sb.append("--- Cards ---\n");
    if (cards.isEmpty()) {
      sb.append("  (none)\n");
    } else {
      for (CardSession cs : cards.values()) {
        String state = "?";
        try {
          selectApplet(cs.channel);
          byte[] data = unwrapData(cs.comm.send(ProtocolConstants.INS_GET_STATE));
          state = stateString(data[0]);
        } catch (Exception e) {
          TerminalOutput.showError("Error reading card state for " + cs.cardIdHex + ": " + e.getMessage());
        }
        String mark = cs.cardIdHex.equals(activeCardId) ? " *" : "";
        sb.append("  ").append(cs.cardIdHex).append(" customer=").append(cs.customerName)
            .append(" pin=").append(cs.pin).append(" state=").append(state).append(mark).append("\n");
      }
    }
    sb.append("--- Audit log: ").append(backend.getAuditLog().size()).append(" entries ---");
    TerminalOutput.showMessage(sb.toString());
  }

  static void printCards() {
    if (cards.isEmpty()) { TerminalOutput.showMessage("No cards."); return; }
    StringBuilder sb = new StringBuilder();
    for (CardSession cs : cards.values()) {
      String state = "?";
      try {
        selectApplet(cs.channel);
        byte[] data = unwrapData(cs.comm.send(ProtocolConstants.INS_GET_STATE));
        state = stateString(data[0]);
      } catch (Exception e) {
        TerminalOutput.showError("Error reading card state for " + cs.cardIdHex + ": " + e.getMessage());
      }
      String mark = cs.cardIdHex.equals(activeCardId) ? " [active]" : "";
      sb.append("  ").append(cs.cardIdHex).append(" customer=").append(cs.customerName)
          .append(" state=").append(state).append(mark).append("\n");
    }
    TerminalOutput.showMessage(sb.toString().stripTrailing());
  }

  static void cmdNew() throws Exception {
    StringBuilder customerList = new StringBuilder("Customers:\n");
    for (int i = 0; i < CUSTOMER_NAMES.length; i++) {
      customerList.append("  ").append(i).append(") ").append(CUSTOMER_NAMES[i]).append("\n");
    }
    TerminalOutput.showMessage(customerList.toString().stripTrailing());
    int idx;
    try {
      String idxLine = reader.readLine("Select customer (0-2): ");
      if (idxLine == null) { TerminalOutput.showMessage("Input ended unexpectedly."); return; }
      idx = Integer.parseInt(idxLine.trim());
    } catch (NumberFormatException e) { TerminalOutput.showMessage("Invalid selection."); return; }
    if (idx < 0 || idx >= CUSTOMER_NAMES.length) { TerminalOutput.showMessage("Invalid selection."); return; }
    String pinLine = reader.readLine("PIN: ");
    if (pinLine == null) { TerminalOutput.showMessage("Input ended unexpectedly."); return; }
    String pin = pinLine.trim();

    byte[] cardId = { 0x00, 0x00, (byte) (cardCounter >> 8), (byte) (cardCounter & 0xFF) };
    String cardIdHex = ByteUtil.toHex(cardId);
    byte[] customerId = CUSTOMER_IDS[idx];

    String termName = "SIM-" + cardIdHex;
    CardTerminals terminals = CardTerminalSimulator.terminals(termName);
    CardTerminal terminal = terminals.getTerminal(termName);

    // Suppress jcardsim's own diagnostic output during card init - it writes directly to
    // System.out/err and there is no library-level way to silence it.
    PrintStream savedOut = System.out;
    PrintStream savedErr = System.err;
    PrintStream devNull = new PrintStream(OutputStream.nullOutputStream());
    System.setOut(devNull);
    System.setErr(devNull);
    CardSimulator simulator;
    Card card;
    try {
      simulator = new CardSimulator();
      AID aid = new AID(APPLET_AID, (byte) 0, (byte) APPLET_AID.length);
      simulator.installApplet(aid, RentalCardApplet.class);
      simulator.assignToTerminal(terminal);
      card = terminal.connect("*");
    } finally {
      System.setOut(savedOut);
      System.setErr(savedErr);
    }
    CardChannel channel = card.getBasicChannel();
    selectApplet(channel);

    CardComm comm = new CardComm(channel);
    PersonalizationTerminal pt = new PersonalizationTerminal(comm, backend);
    Result<Void> personalizeResult = pt.personalizeCard(cardId, pin);
    if (!personalizeResult.success) {
      TerminalOutput.showError("Failed to personalize card: " + personalizeResult.error.getMessage());
      return;
    }
    cardCounter++;
    Result<Void> issueResult = pt.issueCard(customerId);
    if (!issueResult.success) {
      TerminalOutput.showError("Failed to issue card: " + issueResult.error.getMessage());
      return;
    }
    backend.linkCardToCustomer(customerId, cardId);

    CardSession cs = new CardSession();
    cs.cardIdHex = cardIdHex;
    cs.cardIdBytes = cardId;
    cs.pin = pin;
    cs.customerName = CUSTOMER_NAMES[idx];
    cs.customerId = customerId;
    cs.comm = comm;
    cs.channel = channel;

    cards.put(cardIdHex, cs);
    activeCardId = cardIdHex;
    TerminalOutput.showMessage("Card " + cardIdHex + " created for " + CUSTOMER_NAMES[idx] + ". Now active.");
  }

  static void cmdUse(String cardId) {
    if (cardId.isEmpty()) { TerminalOutput.showMessage("Usage: use <cardId>"); return; }
    if (!cards.containsKey(cardId)) { TerminalOutput.showMessage("Card not found: " + cardId); return; }
    activeCardId = cardId;
    TerminalOutput.showMessage("Active card: " + cardId);
  }

  static void cmdReception() {
    if (activeCardId == null) { TerminalOutput.showMessage("No active card. Use 'new' or 'use <cardId>'."); return; }
    CardSession cs = cards.get(activeCardId);
    if (cs == null) { TerminalOutput.showError("Active card not found in session map."); return; }
    try { selectApplet(cs.channel); } catch (Exception e) {
      TerminalOutput.showError("Failed to select applet: " + e.getMessage()); return;
    }

    ReceptionTerminal rt = new ReceptionTerminal(cs.comm, backend);
    Result<Byte> stateResult = CardUtil.getCardState(cs.comm);
    if (stateResult.success) TerminalOutput.showMessage("Card state: " + stateString(stateResult.value));

    String pinLine = reader.readLine("PIN: ");
    if (pinLine == null) { TerminalOutput.showMessage("Input ended unexpectedly."); return; }
    String pin = pinLine.trim();
    Result<byte[]> authResult = rt.mutualAuth(pin);
    if (!authResult.success) { TerminalOutput.showError("Auth failed: " + authResult.error.getMessage()); return; }
    byte[] pkc = authResult.value;
    cs.lastPkc = pkc;
    TerminalOutput.showMessage("Authentication successful.");

    boolean sub = true;
    while (sub) {
      String choiceLine = reader.readLine("1) Assign vehicle  2) Return vehicle  3) Card state  0) Back\nChoice: ");
      if (choiceLine == null) break;
      String choice = choiceLine.trim();
      switch (choice) {
        case "1": receptionAssignVehicle(rt, cs, pkc); break;
        case "2":
          rt.returnVehicleFlow();
          break;
        case "3":
          Result<Byte> stR = CardUtil.getCardState(cs.comm);
          if (stR.success) TerminalOutput.showMessage("State: " + stateString(stR.value));
          else TerminalOutput.showError("Error: " + stR.error.getMessage());
          break;
        case "0": sub = false; break;
        default: TerminalOutput.showMessage("Unknown option.");
      }
    }
  }

  static void receptionAssignVehicle(ReceptionTerminal rt, CardSession cs, byte[] pkc) {
    List<Vehicle> available = backend.getAvailableVehicles();
    if (available.isEmpty()) { TerminalOutput.showMessage("No vehicles available."); return; }
    StringBuilder sb = new StringBuilder("Available vehicles:\n");
    for (int i = 0; i < available.size(); i++) {
      Vehicle v = available.get(i);
      sb.append("  ").append(i).append(") ").append(v.getPlate())
          .append(" [").append(ByteUtil.toHex(v.getId())).append("]\n");
    }
    TerminalOutput.showMessage(sb.toString());
    int idx;
    try {
      String idxLine = reader.readLine("Select vehicle (index): ");
      if (idxLine == null) { TerminalOutput.showMessage("Input ended unexpectedly."); return; }
      idx = Integer.parseInt(idxLine.trim());
    } catch (NumberFormatException e) { TerminalOutput.showError("Invalid selection."); return; }
    if (idx < 0 || idx >= available.size()) { TerminalOutput.showError("Invalid selection."); return; }
    Vehicle vehicle = available.get(idx);
    long now = System.currentTimeMillis() / 1000;
    byte[] period = periodBytes(now, now + DEFAULT_RENTAL_PERIOD_SECONDS);
    Result<Void> assignResult = rt.assignVehicle(vehicle.getId(), cs.customerId, pkc, period);
    if (assignResult.success) TerminalOutput.showMessage("Vehicle assigned: " + vehicle.getPlate());
    else TerminalOutput.showError("Assignment failed: " + assignResult.error.getMessage());
  }

  static void cmdVehicle() {
    if (activeCardId == null) { TerminalOutput.showMessage("No active card. Use 'new' or 'use <cardId>'."); return; }
    CardSession cs = cards.get(activeCardId);
    if (cs == null) { TerminalOutput.showError("Active card not found in session map."); return; }
    try { selectApplet(cs.channel); } catch (Exception e) {
      TerminalOutput.showError("Failed to select applet: " + e.getMessage()); return;
    }

    StringBuilder vlist = new StringBuilder("Vehicles:\n");
    for (int i = 0; i < VEHICLE_IDS.length; i++) {
      Vehicle v = backend.getVehicle(VEHICLE_IDS[i]);
      if (v == null) continue;
      vlist.append("  ").append(i).append(") ").append(v.getPlate())
          .append(" [").append(ByteUtil.toHex(v.getId())).append("] ")
          .append(v.isAvailable() ? "AVAILABLE" : "IN USE").append("\n");
    }
    TerminalOutput.showMessage(vlist.toString());
    int idx;
    try {
      String idxLine = reader.readLine("Select vehicle (index): ");
      if (idxLine == null) { TerminalOutput.showMessage("Input ended unexpectedly."); return; }
      idx = Integer.parseInt(idxLine.trim());
    } catch (NumberFormatException e) { TerminalOutput.showError("Invalid selection."); return; }
    if (idx < 0 || idx >= VEHICLE_IDS.length) { TerminalOutput.showError("Invalid selection."); return; }
    byte[] vehicleId = VEHICLE_IDS[idx];

    VehicleTerminal vt = new VehicleTerminal(cs.comm, backend.getMasterPublicKey(),
        backend.getTerminalKeyPair(), backend.getTerminalCertificate(), vehicleId);
    Result<Byte> vtStateResult = CardUtil.getCardState(cs.comm);
    if (vtStateResult.success) TerminalOutput.showMessage("Card state: " + stateString(vtStateResult.value));

    byte[] sessionPkc = null;
    boolean sub = true;
    while (sub) {
      String choiceLine = reader.readLine("1) Open  2) Update mileage  3) Return  4) Get mileage  5) State  0) Back\nChoice: ");
      if (choiceLine == null) break;
      String choice = choiceLine.trim();
      switch (choice) {
        case "1":
          Result<byte[]> openResult = vt.open();
          if (openResult.success) { sessionPkc = openResult.value; TerminalOutput.showMessage("Vehicle opened."); }
          else TerminalOutput.showError("Open failed: " + openResult.error.getMessage());
          break;
        case "2":
          if (sessionPkc == null) { TerminalOutput.showMessage("Must open vehicle first."); break; }
          try {
            String kmLine = reader.readLine("Mileage (km): ");
            if (kmLine == null) { TerminalOutput.showMessage("Input ended unexpectedly."); break; }
            Integer km = Integer.parseInt(kmLine.trim());
            Result<Void> updResult = vt.updateMileage(km);
            if (updResult.success) TerminalOutput.showMessage("Mileage updated.");
            else TerminalOutput.showError("Update failed: " + updResult.error.getMessage());
          } catch (NumberFormatException e) { TerminalOutput.showError("Invalid number."); }
          break;
        case "3":
          if (sessionPkc == null) { TerminalOutput.showMessage("Must open vehicle first."); break; }
          try {
            String fmLine = reader.readLine("Final mileage (km): ");
            if (fmLine == null) { TerminalOutput.showMessage("Input ended unexpectedly."); break; }
            Integer fm = Integer.parseInt(fmLine.trim());
            Result<byte[]> retResult = vt.returnVehicle(fm, sessionPkc);
            if (retResult.success) {
              vt.auditLog.flushToBackend(backend);
              backend.releaseVehicle(vehicleId);
              sessionPkc = null;
              TerminalOutput.showMessage("Vehicle returned.");
            } else TerminalOutput.showError("Return failed: " + retResult.error.getMessage());
          } catch (NumberFormatException e) { TerminalOutput.showError("Invalid number."); }
          break;
        case "4":
          Result<Integer> milResult = vt.getMileage();
          if (milResult.success) TerminalOutput.showMessage("Mileage: " + milResult.value + " km");
          else TerminalOutput.showError("Error: " + milResult.error.getMessage());
          break;
        case "5":
          Result<Byte> vtSt = CardUtil.getCardState(cs.comm);
          if (vtSt.success) TerminalOutput.showMessage("State: " + stateString(vtSt.value));
          else TerminalOutput.showError("Error: " + vtSt.error.getMessage());
          break;
        case "0": sub = false; break;
        default: TerminalOutput.showMessage("Unknown option.");
      }
    }
    if (sessionPkc != null) {
      TerminalOutput.showMessage("Warning: vehicle session still open - audit log not flushed.");
    } else {
      vt.auditLog.flushToBackend(backend);
    }
  }

  static final DateTimeFormatter LOG_TIME_FORMAT =
      DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

  static void printLog() {
    List<BackendSystem.AuditEntry> log = backend.getAuditLog();
    if (log.isEmpty()) { TerminalOutput.showMessage("Audit log empty."); return; }
    StringBuilder sb = new StringBuilder();
    for (BackendSystem.AuditEntry e : log) {
      String time = LOG_TIME_FORMAT.format(Instant.ofEpochMilli(e.timestamp));
      String cardHex = e.cardId != null ? ByteUtil.toHex(e.cardId) : "-";
      String vehicleHex = e.vehicleId != null ? ByteUtil.toHex(e.vehicleId) : "-";
      String evidence = e.cryptoEvidence != null ? "[" + e.cryptoEvidence.length + "B]" : "-";
      sb.append(String.format("%s  %-20s card=%-10s vehicle=%-10s evidence=%-10s%n",
          time, e.eventType, cardHex, vehicleHex, evidence));
    }
    TerminalOutput.showMessage(sb.toString().stripTrailing());
  }

  static byte[] periodBytes(long startSecs, long endSecs) {
    return ByteBuffer.allocate(8).putInt((int) startSecs).putInt((int) endSecs).array();
  }
}
