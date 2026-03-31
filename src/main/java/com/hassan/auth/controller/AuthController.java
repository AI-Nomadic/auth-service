package com.hassan.auth.controller;

import com.hassan.auth.dto.AuthResponse;
import com.hassan.auth.dto.GoogleAuthRequest;
import com.hassan.auth.dto.LoginRequest;
import com.hassan.auth.dto.RegisterRequest;
import com.hassan.auth.model.User;
import com.hassan.auth.repository.UserRepository;
import com.hassan.auth.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;

    /**
     * POST /auth/register
     * Create a new user account with email and password.
     */
    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        AuthResponse response = authService.register(request);
        return ResponseEntity.ok(response);
    }

    /**
     * POST /auth/login
     * Login with email and password. Returns a JWT.
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    /**
     * POST /auth/google
     * Exchange a Google ID token (from the browser) for our JWT.
     */
    @PostMapping("/google")
    public ResponseEntity<AuthResponse> googleLogin(@Valid @RequestBody GoogleAuthRequest request) {
        AuthResponse response = authService.googleLogin(request);
        return ResponseEntity.ok(response);
    }

    /**
     * GET /auth/me
     * Returns the current user info. The gateway adds X-User-Id header.
     * This is a protected route — gateway validates JWT before forwarding.
     */
    @GetMapping("/me")
    public ResponseEntity<User> getCurrentUser(@RequestHeader("X-User-Id") String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));
        user.setPasswordHash(null); // Never expose password hash
        return ResponseEntity.ok(user);
    }
}
