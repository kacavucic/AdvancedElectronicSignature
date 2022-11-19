package com.zrs.aes.web.customexceptions;

public class CustomFileNotFoundException extends RuntimeException {

    public CustomFileNotFoundException(String message) {
        super(message);
    }

    public CustomFileNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}