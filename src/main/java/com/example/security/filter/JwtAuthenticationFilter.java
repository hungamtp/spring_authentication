package com.example.security.filter;

import com.example.security.service.CustomUserDetailsService;
import com.example.security.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * ── JWT Authentication Filter ────────────────────────────────────────────────
 *
 * Intercepts every request and:
 *   1. Extracts the Bearer token from the Authorization header
 *   2. Validates the JWT signature and expiry
 *   3. Loads the user from the database
 *   4. Injects the Authentication into the SecurityContext
 *
 * This handles locally-issued JWTs (from /api/auth/login).
 * IdP-issued JWTs are handled by Spring's OAuth2ResourceServer automatically.
 *
 * Flow:
 *   Request → [JwtAuthFilter] → validate token → set SecurityContext → Controller
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
        @NonNull HttpServletRequest request,
        @NonNull HttpServletResponse response,
        @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");

        // Skip if no Bearer token present
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7);

        try {
            final String username = jwtUtil.extractUsername(jwt);

            // Only authenticate if not already authenticated
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                if (jwtUtil.isTokenValid(jwt, userDetails)) {
                    // Build authentication token with user's authorities (roles + permissions)
                    UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,                          // credentials cleared after auth
                            userDetails.getAuthorities()   // roles + permissions → RBAC
                        );

                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // Set in SecurityContext — all @PreAuthorize checks will use this
                    SecurityContextHolder.getContext().setAuthentication(authToken);

                    log.debug("Authenticated user '{}' via local JWT", username);
                }
            }
        } catch (Exception e) {
            log.warn("Could not authenticate via JWT: {}", e.getMessage());
            // Don't throw — let the request continue unauthenticated
            // Spring Security will reject it at the authorization layer
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Skip JWT filter for public auth endpoints
        String path = request.getServletPath();
        return path.startsWith("/api/auth/") || path.startsWith("/api/public/");
    }
}
