package com.zrs.aes.exception.customexceptions;

public class InvalidUserException extends RuntimeException {

  public InvalidUserException(String message) {
    super(message);
  }

  public InvalidUserException(String message, Throwable cause) {
    super(message, cause);
  }
}
