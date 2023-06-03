package com.zrs.aes.exception.customexceptions;

public class InvalidStatusException extends RuntimeException {

  public InvalidStatusException(String message) {
    super(message);
  }

  public InvalidStatusException(String message, Throwable cause) {
    super(message, cause);
  }
}

