package terminal.logging;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import terminal.util.ByteUtil;

/**
 * File-backed verbose logger for protocol steps and APDU traffic. 
 *
 * Path from system property {@code rentalsim.verbose.log}, default
 * {@code /tmp/rentalsim-verbose.log}.
 */
public final class VerboseLogger {
  private static final String PROP = "rentalsim.verbose.log";
  private static final String DEFAULT_PATH = "/tmp/rentalsim-verbose.log";
  private static final String AUDIT_PROP = "rentalsim.audit.log";
  private static final String AUDIT_DEFAULT = "/tmp/rentalsim-audit.log";

  private static VerboseLogger instance;

  private PrintWriter out;
  private PrintWriter auditOut;
  private static final DateTimeFormatter TS = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
  private static final DateTimeFormatter AUDIT_TS = DateTimeFormatter.ofPattern("HH:mm:ss");
  private final List<String> captured = new ArrayList<>();

  private VerboseLogger() {
    out = openAppend(System.getProperty(PROP, DEFAULT_PATH));
    auditOut = openAppend(System.getProperty(AUDIT_PROP, AUDIT_DEFAULT));
  }

  private static PrintWriter openAppend(String path) {
    try {
      return new PrintWriter(new FileWriter(path, true), true);
    } catch (IOException e) {
      System.err.println("[VerboseLogger] Failed to open log file '" + path + "': " + e.getMessage());
      return null;
    }
  }

  public static VerboseLogger get() {
    if (instance == null) {
      synchronized (VerboseLogger.class) {
        if (instance == null) instance = new VerboseLogger();
      }
    }
    return instance;
  }

  public void step(String msg) {
    write("[Step] " + msg);
  }

  public void term(String msg) {
    write("[Term] " + msg);
  }

  public void apdu(String dir, byte[] data, int sw) {
    String hex = data == null ? "" : ByteUtil.toHex(data);
    String swStr = sw < 0 ? "" : String.format(" SW=%04X", sw);
    write("[APDU " + dir + "] " + hex + swStr);
  }

  public void event(String msg) {
    write("[Event] " + msg);
  }

  public synchronized void audit(String eventType, byte[] cardId, byte[] vehicleId,
      String details) {
    if (auditOut == null) return;
    try {
      String card = cardId == null ? "-" : ByteUtil.toHex(cardId);
      String veh = vehicleId == null ? "-" : ByteUtil.toHex(vehicleId);
      auditOut.println(String.format("%s %s card=%s vehicle=%s%s",
          AUDIT_TS.format(LocalTime.now()), eventType, card, veh,
          details == null ? "" : " " + details));
    } catch (Exception e) {
      System.err.println("[VerboseLogger] Failed to write audit log: " + e.getMessage());
    }
  }

  /** Returns and clears all messages written since the last call. For tests only. */
  public synchronized List<String> getAndClearCapture() {
    List<String> copy = new ArrayList<>(captured);
    captured.clear();
    return copy;
  }

  private synchronized void write(String line) {
    captured.add(line);
    if (out == null) return;
    try {
      out.println(TS.format(LocalTime.now()) + " " + line);
    } catch (Exception e) {
      System.err.println("[VerboseLogger] Failed to write log: " + e.getMessage());
    }
  }
}
