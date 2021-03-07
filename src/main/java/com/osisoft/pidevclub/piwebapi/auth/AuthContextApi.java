package com.osisoft.pidevclub.piwebapi.auth;

import static java.util.Objects.requireNonNull;

public class AuthContextApi {
    String authMethod;
    Authentication authentication;

    public AuthContextApi(String authMethod, Authentication authentication) {
        requireNonNull(authMethod);
        requireNonNull(authentication);

        this.authMethod = authMethod;
        this.authentication = authentication;
    }

    public String getAuthMethod() {
        return authMethod;
    }
    public Authentication getAuthentication() {
        return authentication;
    }
}
