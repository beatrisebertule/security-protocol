package terminal.logging;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import terminal.backend.BackendSystem;

/**
 * Thread-safe local audit log buffer. Records audit events offline and flushes
 * them to the backend on demand or via a scheduled caller.
 *
 * Used by offline terminals (e.g. vehicle terminal) that accumulate events
 * locally and push them to the backend in batches, rather than on every event.
 */
public class LocalAuditLog {
  private final List<BackendSystem.AuditEntry> log = new ArrayList<>();

  /**
   * Records an audit event to the local buffer and writes it to the verbose
   * audit log file.
   *
   * NOTE: synchronized is needed to avoid multiple threads writing
   * to the logs at the same time (race condition)
   *
   * @param eventType one of the {@code EVENT_*} constants in
   *                  {@link terminal.backend.BackendSystem}
   * @param cardId    card identifier, or {@code null} if unknown
   * @param vehicleId vehicle identifier, or {@code null} if not applicable
   * @param evidence  raw crypto evidence (e.g. signed token), or {@code null}
   * @param details   human-readable detail string, or {@code null}
   */
  public synchronized void record(String eventType, byte[] cardId, byte[] vehicleId,
      byte[] evidence, String details) {
    log.add(new BackendSystem.AuditEntry(eventType, cardId, vehicleId, evidence, details));
    VerboseLogger.get().audit(eventType, cardId, vehicleId, details);
  }

  /**
   * Returns an unmodifiable view of the buffered entries.
   *
   * @return immutable list of pending audit entries
   */
  public List<BackendSystem.AuditEntry> getLog() {
    return Collections.unmodifiableList(log);
  }

  /**
   * Sends all buffered entries to the backend and clears the local buffer.
   *
   * NOTE: synchronized is needed to avoid multiple threads writing
   * to the logs at the same time (race condition)
   *
   * @param backend backend instance to receive the entries
   */
  public synchronized void flushToBackend(BackendSystem backend) {
    for (BackendSystem.AuditEntry e : log) {
      backend.appendToAuditLogOnly(e);
    }
    log.clear();
  }
}
