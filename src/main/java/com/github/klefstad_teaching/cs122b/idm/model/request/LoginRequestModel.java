package com.github.klefstad_teaching.cs122b.idm.model.request;

public class LoginRequestModel {
    private String email;
    private char[] password;

    public String getEmail() {
        return email;
    }

    public LoginRequestModel setEmail(String email) {
        this.email = email;
        return this;
    }

    public char[] getPassword() {
        return password;
    }

    public LoginRequestModel setPassword(char[] password) {
        this.password = password;
        // NOT PUT ERROR THROW HERE
        return this;
    }
}
