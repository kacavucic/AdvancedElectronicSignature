package com.zrs.aes.web.exception;

public class SigningSessionNotFoundException extends RuntimeException {
    public SigningSessionNotFoundException(String message) {
        super(message);
    }

    public SigningSessionNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
