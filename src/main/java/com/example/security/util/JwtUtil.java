package com.example.security.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * ═══════════════════════════════════════════════════════════════════
 *  JWT UTILITY
 *
 *  Handles creation and validation of locally-issued JWTs.
 *  Used for the /api/auth/login endpoint (not IdP-issued tokens).
 *
 *  JWT Structure (decoded):
 *  ┌─────────────────────────────────────────────────────────────┐
 *  │ HEADER  { "alg": "HS256", "typ": "JWT" }                   │
 *  ├─────────────────────────────────────────────────────────────┤
 *  │ PAYLOAD {                                                   │
 *  │   "sub":   "alice",           ← subject (username)         │
 *  │   "iat":   1710000000,        ← issued at                  │
 *  │   "exp":   1710003600,        ← expiry (1hr)               │
 *  │   "roles": ["ROLE_ADMIN"],    ← RBAC roles                 │
 *  │   "perms": ["USER_READ"],     ← fine-grained permissions   │
 *  │   "dept":  "engineering",     ← ABAC attribute             │
 *  │   "jti":   "uuid-here"        ← unique token ID            │
 *  │ }                                                           │
 *  ├─────────────────────────────────────────────────────────────┤
 *  │ SIGNATURE  HMACSHA256(base64(header)+"."+base64(payload))  │
 *  └─────────────────────────────────────────────────────────────┘
 * ═══════════════════════════════════════════════════════════════════
 */
@Component
@Slf4j
public class JwtUtil {

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.expiration-ms}")
    private long expirationMs;

    @Value("${app.jwt.refresh-expiration-ms}")
    private long refreshExpirationMs;

    // ── Token Generation ──────────────────────────────────────────────────────

    public String generateAccessToken(UserDetails userDetails) {
        Map<String, Object> extraClaims = new HashMap<>();

        // Embed roles in token (RBAC)
        List<String> roles = userDetails.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .filter(a -> a.startsWith("ROLE_"))
            .collect(Collectors.toList());

        // Embed fine-grained permissions (RBAC — permission level)
        List<String> permissions = userDetails.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .filter(a -> !a.startsWith("ROLE_"))
            .collect(Collectors.toList());

        extraClaims.put("roles", roles);
        extraClaims.put("perms", permissions);
        extraClaims.put("jti", UUID.randomUUID().toString()); // unique token ID

        return buildToken(extraClaims, userDetails.getUsername(), expirationMs);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        // Refresh tokens are minimal — no roles/claims, just subject + expiry
        return buildToken(Map.of("type", "refresh"), userDetails.getUsername(), refreshExpirationMs);
    }

    private String buildToken(Map<String, Object> claims, String subject, long expiration) {
        return Jwts.builder()
            .claims(claims)
            .subject(subject)
            .issuedAt(new Date())
            .expiration(new Date(System.currentTimeMillis() + expiration))
            .signWith(getSigningKey(), Jwts.SIG.HS256)
            .compact();
    }

    // ── Token Validation ──────────────────────────────────────────────────────

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            final String username = extractUsername(token);
            return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
        } catch (JwtException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            return false;
        }
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // ── Claim Extraction ──────────────────────────────────────────────────────

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        return extractClaim(token, claims -> claims.get("roles", List.class));
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
            .verifyWith(getSigningKey())
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(Base64.getEncoder().encodeToString(secret.getBytes()));
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
