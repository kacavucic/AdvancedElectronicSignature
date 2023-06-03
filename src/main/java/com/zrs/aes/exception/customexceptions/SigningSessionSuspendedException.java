package com.zrs.aes.exception.customexceptions;

public class SigningSessionSuspendedException extends RuntimeException {

  public SigningSessionSuspendedException(String message) {
    super(message);
  }

  public SigningSessionSuspendedException(String message, Throwable cause) {
    super(message, cause);
  }
}
