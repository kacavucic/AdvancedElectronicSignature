package com.zrs.aes.web.customexceptions;

public class InvalidKeystorePassException extends RuntimeException {

    public InvalidKeystorePassException(String message) {
        super(message);
    }

    public InvalidKeystorePassException(String message, Throwable cause) {
        super(message, cause);
    }
}