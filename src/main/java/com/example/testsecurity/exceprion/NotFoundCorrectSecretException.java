package com.example.testsecurity.exceprion;

public class NotFoundCorrectSecretException extends RuntimeException {

    public NotFoundCorrectSecretException() {
        this("Not found correct secret");
    }

    public NotFoundCorrectSecretException(String message) {
        super(message);
    }

}
