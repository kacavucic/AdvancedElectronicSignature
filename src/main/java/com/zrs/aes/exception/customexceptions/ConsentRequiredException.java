package com.zrs.aes.exception.customexceptions;

public class ConsentRequiredException extends RuntimeException {

  public ConsentRequiredException(String message) {
    super(message);
  }

  public ConsentRequiredException(String message, Throwable cause) {
    super(message, cause);
  }
}
