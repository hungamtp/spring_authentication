package com.example.security.config;

import com.example.security.filter.JwtAuthenticationFilter;
import com.example.security.service.CustomOidcUserService;
import com.example.security.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * ═══════════════════════════════════════════════════════════════════
 *  SECURITY CONFIGURATION
 *
 *  Two SecurityFilterChains:
 *
 *  [1] API chain  — stateless, JWT Bearer tokens, RBAC via @PreAuthorize
 *  [2] Web chain  — OIDC login with Auth0/Okta/Keycloak/Google (CIAM/IdP)
 *
 *  mTLS is enforced at the TLS layer (server.ssl.client-auth=need in yml).
 *  The X.509 client certificate is extracted here for additional ABAC checks.
 * ═══════════════════════════════════════════════════════════════════
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity   // enables @PreAuthorize, @PostAuthorize, @Secured
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;
    private final CustomUserDetailsService userDetailsService;
    private final CustomOidcUserService oidcUserService;

    // ─────────────────────────────────────────────────────────────────────────
    // Chain 1: REST API — JWT Bearer (OAuth2 Resource Server)
    //          Applies to /api/**
    //          Stateless, no session. JWT validated against IdP's JWKS.
    // ─────────────────────────────────────────────────────────────────────────
    @Bean
    @Order(1)
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/api/**")
            .csrf(csrf -> csrf.disable())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            .authorizeHttpRequests(auth -> auth
                // Public endpoints
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/public/**").permitAll()

                // RBAC: role-based access
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/manager/**").hasAnyRole("ADMIN", "MANAGER")
                .requestMatchers("/api/reports/**").hasAuthority("REPORT_READ")

                // Everything else needs authentication (ABAC checked at method level)
                .anyRequest().authenticated()
            )

            // ── OAuth2 Resource Server: validate incoming JWT Bearer tokens ──
            // Spring auto-fetches JWKS from your IdP and verifies signatures
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
            )

            // ── X.509 / mTLS: extract client cert as additional identity ─────
            // Works in tandem with server.ssl.client-auth=need in application.yml
            .x509(x509 -> x509
                .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
                .userDetailsService(userDetailsService)
            )

            // Local JWT filter (for self-issued tokens, e.g. after /api/auth/login)
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Chain 2: Web (Browser) — OIDC Login via external IdP / CIAM
    //          Applies to everything else (/, /login, /dashboard, etc.)
    //          Uses Authorization Code flow with PKCE (handled by Spring)
    // ─────────────────────────────────────────────────────────────────────────
    @Bean
    @Order(2)
    public SecurityFilterChain webSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login", "/error", "/h2-console/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )

            // ── OIDC Login: delegates to your IdP (Auth0 / Okta / Keycloak) ─
            // On login, Spring fetches the ID Token, validates it, and builds
            // an OidcUser with claims (sub, email, roles, etc.)
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/login")
                .userInfoEndpoint(ui -> ui.oidcUserService(oidcUserService))
                .defaultSuccessUrl("/dashboard", true)
            )

            // ── OAuth2 Client: used for downstream API calls with access token ─
            .oauth2Client(oauth2 -> {})

            .logout(logout -> logout
                .logoutSuccessUrl("/")
                .invalidateHttpSession(true)
                .clearAuthentication(true)
            )

            .csrf(csrf -> csrf
                .ignoringRequestMatchers("/h2-console/**")
            )

            .headers(headers -> headers
                .frameOptions(fo -> fo.sameOrigin()) // for H2 console
            );

        return http.build();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // JWT Converter: extract roles from JWT claims → Spring GrantedAuthorities
    //
    // Different IdPs put roles in different claim names:
    //   Auth0:    "https://myapp.com/roles" (custom namespace)
    //   Okta:     "groups"
    //   Keycloak: "realm_access.roles"
    //
    // Adjust the authoritiesClaimName to match your IdP's JWT structure.
    // ─────────────────────────────────────────────────────────────────────────
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

        // The claim in the JWT that holds roles/scopes
        grantedAuthoritiesConverter.setAuthoritiesClaimName("roles");

        // Prefix added to each authority: "ROLE_" → works with hasRole("ADMIN")
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return converter;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Standard beans
    // ─────────────────────────────────────────────────────────────────────────
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
