package com.orange.exception;

/**
 * Created by fqsq3375 on 19/01/2017.
 */
public class EncryptException extends Exception{

    public EncryptException() {
        super();
    }

    public EncryptException(String message) {
        super(message);
    }

    public EncryptException(String message, Exception cause) {
        super(message, cause);
    }
}
