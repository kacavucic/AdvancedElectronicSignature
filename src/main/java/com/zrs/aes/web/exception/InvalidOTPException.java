package com.zrs.aes.web.exception;

public class InvalidOTPException extends RuntimeException {
    public InvalidOTPException(String message) {
        super(message);
    }

    public InvalidOTPException(String message, Throwable cause) {
        super(message, cause);
    }
}
