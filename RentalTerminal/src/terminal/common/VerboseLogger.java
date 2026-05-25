package terminal.common;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * File-backed verbose logger for protocol steps and APDU traffic. Singleton,
 * append mode, autoflush. Best-effort: any IO failure silently disables further
 * writes so log IO never blocks or crashes protocol code.
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
  private final SimpleDateFormat ts = new SimpleDateFormat("HH:mm:ss.SSS");
  private final SimpleDateFormat auditTs = new SimpleDateFormat("HH:mm:ss");

  private VerboseLogger() {
    out = openAppend(System.getProperty(PROP, DEFAULT_PATH));
    auditOut = openAppend(System.getProperty(AUDIT_PROP, AUDIT_DEFAULT));
  }

  private static PrintWriter openAppend(String path) {
    try {
      return new PrintWriter(new FileWriter(path, true), true);
    } catch (IOException e) {
      return null;
    }
  }

  public static synchronized VerboseLogger get() {
    if (instance == null) instance = new VerboseLogger();
    return instance;
  }

  public void step(String msg) {
    write("[Step] " + msg);
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
      auditOut.println(auditTs.format(new Date())
          + " " + eventType + " card=" + card + " vehicle=" + veh
          + (details == null ? "" : " " + details));
    } catch (Exception ignored) {
    }
  }

  private synchronized void write(String line) {
    if (out == null) return;
    try {
      out.println(ts.format(new Date()) + " " + line);
    } catch (Exception ignored) {
    }
  }
}
