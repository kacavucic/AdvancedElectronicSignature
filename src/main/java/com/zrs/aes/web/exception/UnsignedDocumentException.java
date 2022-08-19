package com.zrs.aes.web.exception;

public class UnsignedDocumentException extends RuntimeException {
    public UnsignedDocumentException(String message) {
        super(message);
    }

    public UnsignedDocumentException(String message, Throwable cause) {
        super(message, cause);
    }
}
