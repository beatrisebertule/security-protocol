package terminal.logging;

/**
 * Error-handling type. All terminal methods MUST return Result<T> to signal
 * failure.
 * DO NOT throw exceptions. DO NOT catch exceptions and rethrow. Use
 * Result.fail().
 *
 * fail(String) and fail(String, Throwable) log automatically via
 * TerminalOutput.showError -
 * they originate a new error. fail(SecurityException) is silent - it propagates
 * an existing
 * error that was already logged at origin.
 */
public final class Result<T> {
  public final boolean success;
  public final T value;
  public final SecurityException error;

  private Result(boolean success, T value, SecurityException error) {
    this.success = success;
    this.value = value;
    this.error = error;
  }

  public static <T> Result<T> ok(T value) {
    return new Result<T>(true, value, null);
  }

  public static <T> Result<T> ok() {
    return new Result<T>(true, null, null);
  }

  /**
   * Propagates an existing error. Silent, the error was already logged at origin.
   */
  public static <T> Result<T> fail(SecurityException error) {
    return new Result<T>(false, null, error);
  }

  /** Originates a new error. Logs and prints to stderr automatically. */
  public static <T> Result<T> fail(String message) {
    TerminalOutput.showError(message);
    return new Result<T>(false, null, new SecurityException(message));
  }

  /**
   * Originates a new error with a cause. Logs and prints to stderr automatically.
   */
  public static <T> Result<T> fail(String message, Throwable cause) {
    TerminalOutput.showError(message);
    return new Result<T>(false, null, new SecurityException(message, cause));
  }
}
