package com.example.security.controller;

import com.example.security.service.CustomUserDetailsService;
import com.example.security.util.JwtUtil;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * ── Auth Controller ───────────────────────────────────────────────────────────
 *
 * POST /api/auth/login  → authenticate with username/password → returns JWT
 * POST /api/auth/refresh → exchange refresh token → new access token
 *
 * This handles LOCAL authentication (not OIDC).
 * OIDC login is handled by Spring Security at /oauth2/authorization/{provider}
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService userDetailsService;
    private final JwtUtil jwtUtil;

    /**
     * Login endpoint.
     *
     * Flow:
     *   POST /api/auth/login { username, password }
     *   → Spring authenticates against DB (BCrypt)
     *   → Issues JWT with roles + permissions embedded
     *   → Client stores JWT and sends as: Authorization: Bearer <token>
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        // Authenticate — throws if credentials invalid
        Authentication auth = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        UserDetails userDetails = (UserDetails) auth.getPrincipal();

        String accessToken  = jwtUtil.generateAccessToken(userDetails);
        String refreshToken = jwtUtil.generateRefreshToken(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .toList();

        log.info("User '{}' logged in with roles: {}", userDetails.getUsername(), roles);

        return ResponseEntity.ok(Map.of(
            "accessToken",  accessToken,
            "refreshToken", refreshToken,
            "tokenType",    "Bearer",
            "expiresIn",    3600,
            "roles",        roles
        ));
    }

    /**
     * Refresh token endpoint.
     * Client sends the refresh token to get a new access token.
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@Valid @RequestBody RefreshRequest request) {
        String username = jwtUtil.extractUsername(request.getRefreshToken());
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        if (jwtUtil.isTokenValid(request.getRefreshToken(), userDetails)) {
            String newAccessToken = jwtUtil.generateAccessToken(userDetails);
            return ResponseEntity.ok(Map.of(
                "accessToken", newAccessToken,
                "tokenType",   "Bearer",
                "expiresIn",   3600
            ));
        }

        return ResponseEntity.status(401).body(Map.of("error", "Invalid refresh token"));
    }

    // ── Request DTOs ──────────────────────────────────────────────────────────

    @Data
    public static class LoginRequest {
        @NotBlank private String username;
        @NotBlank private String password;
    }

    @Data
    public static class RefreshRequest {
        @NotBlank private String refreshToken;
    }
}
