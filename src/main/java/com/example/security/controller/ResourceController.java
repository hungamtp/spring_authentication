package com.example.security.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * ═══════════════════════════════════════════════════════════════════
 *  RESOURCE CONTROLLER
 *
 *  Demonstrates RBAC and ABAC access control patterns side by side.
 *
 *  RBAC via @PreAuthorize:
 *    hasRole()        → checks ROLE_X in authorities
 *    hasAuthority()   → checks exact authority string (for permissions)
 *    hasAnyRole()     → OR condition across roles
 *
 *  ABAC via @PreAuthorize with Spring EL calling our AbacPolicyService:
 *    @abacService.canAccess(authentication, #id, 'REPORT')
 *    → evaluates user attributes + resource attributes + environment
 * ═══════════════════════════════════════════════════════════════════
 */
@RestController
@RequiredArgsConstructor
public class ResourceController {

    // ─────────────────────────────────────────────────────────────────────────
    // RBAC Examples
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Only ADMIN role can access.
     * RBAC: coarse-grained — if you have the role, you're in.
     */
    @GetMapping("/api/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> adminDashboard() {
        return ResponseEntity.ok(Map.of(
            "message", "Admin dashboard",
            "access",  "RBAC: ROLE_ADMIN required"
        ));
    }

    /**
     * ADMIN or MANAGER can access.
     */
    @GetMapping("/api/manager/team")
    @PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')")
    public ResponseEntity<?> teamView() {
        return ResponseEntity.ok(Map.of(
            "message", "Team view",
            "access",  "RBAC: ROLE_ADMIN or ROLE_MANAGER required"
        ));
    }

    /**
     * Fine-grained RBAC: checks a specific Permission, not just a Role.
     * User must have the REPORT_WRITE permission (which their Role grants).
     */
    @PostMapping("/api/reports")
    @PreAuthorize("hasAuthority('REPORT_WRITE')")
    public ResponseEntity<?> createReport(@RequestBody Map<String, Object> body) {
        return ResponseEntity.ok(Map.of(
            "message", "Report created",
            "access",  "RBAC: REPORT_WRITE permission required"
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ABAC Examples
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * ABAC: access depends on the specific report, the user's department,
     * clearance level, and time of day — not just their role.
     *
     * @PreAuthorize calls our AbacPolicyService (registered as 'abacService' bean)
     * #reportId is the method parameter — Spring EL extracts it automatically
     */
    @GetMapping("/api/reports/{reportId}")
    @PreAuthorize("@abacService.canAccess(authentication, #reportId, 'REPORT')")
    public ResponseEntity<?> getReport(@PathVariable Long reportId, Authentication auth) {
        return ResponseEntity.ok(Map.of(
            "reportId", reportId,
            "message",  "Report data",
            "access",   "ABAC: evaluated department, clearance, and office hours",
            "user",     auth.getName()
        ));
    }

    /**
     * ABAC: only finance dept during office hours.
     */
    @GetMapping("/api/invoices/{invoiceId}")
    @PreAuthorize("@abacService.canAccess(authentication, #invoiceId, 'INVOICE')")
    public ResponseEntity<?> getInvoice(@PathVariable Long invoiceId) {
        return ResponseEntity.ok(Map.of(
            "invoiceId", invoiceId,
            "access",    "ABAC: finance department only"
        ));
    }

    /**
     * Combined RBAC + ABAC: must have USER role AND pass ABAC policy.
     */
    @GetMapping("/api/hr/{employeeId}")
    @PreAuthorize("hasRole('USER') and @abacService.canAccess(authentication, #employeeId, 'HR_DATA')")
    public ResponseEntity<?> getHrData(@PathVariable Long employeeId) {
        return ResponseEntity.ok(Map.of(
            "employeeId", employeeId,
            "access",     "Combined RBAC (USER role) + ABAC (HR dept, office hours)"
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // OIDC / JWT claim inspection
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Shows claims from the IdP-issued JWT.
     * @AuthenticationPrincipal Jwt is populated when using OAuth2 Resource Server.
     */
    @GetMapping("/api/me")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> me(@AuthenticationPrincipal Jwt jwt, Authentication auth) {
        if (jwt != null) {
            // OIDC/IdP path: JWT from external IdP
            return ResponseEntity.ok(Map.of(
                "source",      "IdP JWT",
                "subject",     jwt.getSubject(),
                "issuer",      jwt.getIssuer(),
                "claims",      jwt.getClaims(),
                "authorities", auth.getAuthorities()
            ));
        }
        // Local JWT or session path
        return ResponseEntity.ok(Map.of(
            "source",      "local",
            "username",    auth.getName(),
            "authorities", auth.getAuthorities()
        ));
    }

    // Public
    @GetMapping("/api/public/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok(Map.of("status", "UP", "secured", true));
    }
}
