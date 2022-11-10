package com.zrs.aes.web.exception;

public class ConsentRequiredException extends RuntimeException {
    public ConsentRequiredException(String message) {
        super(message);
    }

    public ConsentRequiredException(String message, Throwable cause) {
        super(message, cause);
    }
}
