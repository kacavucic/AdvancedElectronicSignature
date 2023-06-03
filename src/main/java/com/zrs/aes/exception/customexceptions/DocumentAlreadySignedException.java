package com.zrs.aes.exception.customexceptions;


public class DocumentAlreadySignedException extends RuntimeException {

  public DocumentAlreadySignedException(String message) {
    super(message);
  }

  public DocumentAlreadySignedException(String message, Throwable cause) {
    super(message, cause);
  }
}