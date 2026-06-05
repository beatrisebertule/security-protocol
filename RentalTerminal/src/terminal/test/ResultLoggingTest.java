package terminal.test;

import terminal.logging.Result;
import terminal.logging.VerboseLogger;

import java.util.List;

/**
 * Confirms that Result.fail() with a new error message logs to VerboseLogger,
 * and that propagation (fail(SecurityException)) stays silent.
 *
 * Tests for fail(String) and fail(String, Throwable) fail BEFORE the fix in
 * Result.java and pass AFTER.
 */
public class ResultLoggingTest {

  static int passed = 0;
  static int failed = 0;

  public static void main(String[] args) {
    System.out.println("=== ResultLoggingTest ===");

    testFailStringLogsError();
    testFailStringWithCauseLogsError();
    testFailSecurityExceptionDoesNotLog();
    testOkDoesNotLog();

    System.out.println("\n=== Results: " + passed + " passed, " + failed + " failed ===");
    if (failed > 0) System.exit(1);
  }

  static void testFailStringLogsError() {
    System.out.println("\n-- Result.fail(String) logs error --");
    VerboseLogger.get().getAndClearCapture();

    Result.fail("card not responding");

    List<String> logs = VerboseLogger.get().getAndClearCapture();
    check("fail(String) produces a log entry", !logs.isEmpty());
    check("fail(String) entry contains ERROR prefix",
        logs.stream().anyMatch(l -> l.contains("ERROR")));
    check("fail(String) entry contains the message",
        logs.stream().anyMatch(l -> l.contains("card not responding")));
  }

  static void testFailStringWithCauseLogsError() {
    System.out.println("\n-- Result.fail(String, Throwable) logs error --");
    VerboseLogger.get().getAndClearCapture();

    Result.fail("cert signing failed", new Exception("underlying cause"));

    List<String> logs = VerboseLogger.get().getAndClearCapture();
    check("fail(String, Throwable) produces a log entry", !logs.isEmpty());
    check("fail(String, Throwable) entry contains ERROR prefix",
        logs.stream().anyMatch(l -> l.contains("ERROR")));
    check("fail(String, Throwable) entry contains the message",
        logs.stream().anyMatch(l -> l.contains("cert signing failed")));
  }

  static void testFailSecurityExceptionDoesNotLog() {
    System.out.println("\n-- Result.fail(SecurityException) does NOT log (propagation) --");
    VerboseLogger.get().getAndClearCapture();

    SecurityException existing = new SecurityException("already logged upstream");
    Result.fail(existing);

    List<String> logs = VerboseLogger.get().getAndClearCapture();
    check("fail(SecurityException) produces no log entry (propagation is silent)", logs.isEmpty());
  }

  static void testOkDoesNotLog() {
    System.out.println("\n-- Result.ok() does NOT log --");
    VerboseLogger.get().getAndClearCapture();

    Result.ok("value");
    Result.ok();

    List<String> logs = VerboseLogger.get().getAndClearCapture();
    check("Result.ok does not produce any log entry", logs.isEmpty());
  }

  static void check(String name, boolean ok) {
    if (ok) {
      System.out.println("  PASS: " + name);
      passed++;
    } else {
      System.out.println("  FAIL: " + name);
      failed++;
    }
  }
}
