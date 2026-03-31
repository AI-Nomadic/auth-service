package com.hassan.auth.service;

import com.hassan.auth.dto.AuthResponse;
import com.hassan.auth.dto.GoogleAuthRequest;
import com.hassan.auth.dto.LoginRequest;
import com.hassan.auth.dto.RegisterRequest;
import com.hassan.auth.model.User;
import com.hassan.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RestTemplate restTemplate;

    @Value("${app.google.client-id}")
    private String googleClientId;

    // ─────────────────────────────────────────────────────────
    // REGISTER
    // ─────────────────────────────────────────────────────────

    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already registered");
        }

        User user = User.builder()
                .email(request.getEmail())
                .name(request.getName())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .build();

        User saved = userRepository.save(user);
        String token = jwtService.generateToken(saved.getId(), saved.getEmail(), saved.getName());

        return AuthResponse.builder()
                .token(token)
                .id(saved.getId())
                .email(saved.getEmail())
                .name(saved.getName())
                .build();
    }

    // ─────────────────────────────────────────────────────────
    // LOGIN
    // ─────────────────────────────────────────────────────────

    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Invalid email or password"));

        if (user.getPasswordHash() == null) {
            throw new RuntimeException("This account uses Google login. Please sign in with Google.");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new RuntimeException("Invalid email or password");
        }

        String token = jwtService.generateToken(user.getId(), user.getEmail(), user.getName());

        return AuthResponse.builder()
                .token(token)
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .build();
    }

    // ─────────────────────────────────────────────────────────
    // GOOGLE LOGIN
    // ─────────────────────────────────────────────────────────

    /**
     * Verify Google ID token by calling Google's tokeninfo endpoint.
     * Extract user info and create/find user in our DB.
     * Return our own JWT.
     */
    public AuthResponse googleLogin(GoogleAuthRequest request) {
        // 1. Call Google tokeninfo to verify the ID token
        String tokenInfoUrl = "https://oauth2.googleapis.com/tokeninfo?id_token=" + request.getIdToken();

        @SuppressWarnings("unchecked")
        Map<String, String> googleData = restTemplate.getForObject(tokenInfoUrl, Map.class);

        if (googleData == null) {
            throw new RuntimeException("Failed to verify Google token");
        }

        // 2. Validate that this token was issued for our app
        String aud = googleData.get("aud");
        if (!googleClientId.equals(aud)) {
            throw new RuntimeException("Google token was not issued for this application");
        }

        // 3. Extract user info from Google's response
        String googleSub = googleData.get("sub");
        String email = googleData.get("email");
        String name = googleData.getOrDefault("name", email);

        // 4. Find existing user by Google sub, or by email, or create new
        User user = userRepository.findByGoogleSub(googleSub)
                .orElseGet(() -> userRepository.findByEmail(email)
                        .map(existingUser -> {
                            // Link Google to existing email/password account
                            existingUser.setGoogleSub(googleSub);
                            if (existingUser.getName() == null) {
                                existingUser.setName(name);
                            }
                            return userRepository.save(existingUser);
                        })
                        .orElseGet(() -> {
                            // Brand new user via Google
                            User newUser = User.builder()
                                    .email(email)
                                    .name(name)
                                    .googleSub(googleSub)
                                    .build();
                            return userRepository.save(newUser);
                        }));

        String token = jwtService.generateToken(user.getId(), user.getEmail(), user.getName());

        return AuthResponse.builder()
                .token(token)
                .id(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .build();
    }
}
