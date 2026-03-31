package com.hassan.auth.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class GoogleAuthRequest {

    /**
     * The ID token credential returned by Google Identity Services JS SDK
     * after the user completes the Google sign-in flow in the browser.
     */
    @NotBlank(message = "Google ID token is required")
    private String idToken;
}
