package com.antivirus.auth;

public class UnauthorizedAuthException extends RuntimeException {
    public UnauthorizedAuthException(String message) {
        super(message);
    }
}
