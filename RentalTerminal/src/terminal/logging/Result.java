package terminal.logging;

/**
 * Error-handling type. All terminal methods MUST return Result<T> to signal failure.
 * DO NOT throw exceptions. DO NOT catch exceptions and rethrow. Use Result.fail().
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

  public static <T> Result<T> fail(SecurityException error) {
    return new Result<T>(false, null, error);
  }

  public static <T> Result<T> fail(String message) {
    return new Result<T>(false, null, new SecurityException(message));
  }

  public static <T> Result<T> fail(String message, Throwable cause) {
    return new Result<T>(false, null, new SecurityException(message, cause));
  }
}
