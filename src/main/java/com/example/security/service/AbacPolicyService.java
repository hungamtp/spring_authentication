package com.example.security.service;

import com.example.security.config.AbacProperties;
import com.example.security.model.User;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalTime;
import java.util.List;
import java.util.Map;

/**
 * ═══════════════════════════════════════════════════════════════════
 *  ABAC — ATTRIBUTE-BASED ACCESS CONTROL
 *
 *  ABAC evaluates access decisions based on attributes of:
 *    - Subject  (the user:  department, clearance, active status)
 *    - Resource (the data:  sensitivity, owner, department)
 *    - Environment (time of day, IP address, geo-location)
 *
 *  Used via Spring EL in @PreAuthorize:
 *    @PreAuthorize("@abacService.canAccess(authentication, #resourceId, 'REPORT')")
 *
 *  This is the key difference from RBAC:
 *    RBAC → "Can ADMIN role do this?" (coarse)
 *    ABAC → "Can THIS user access THIS resource given THESE conditions?" (fine)
 * ═══════════════════════════════════════════════════════════════════
 */
@Service("abacService")
@Slf4j
public class AbacPolicyService {

    private final AbacProperties abacProperties;
    private final UserService userService;

    public AbacPolicyService(AbacProperties abacProperties, UserService userService) {
        this.abacProperties = abacProperties;
        this.userService = userService;
    }

    /**
     * Main ABAC policy entry point.
     *
     * Policy example:
     *   ALLOW if:
     *     - user is active AND
     *     - user's department matches resource's department OR user is ADMIN AND
     *     - user's clearance level is sufficient AND
     *     - request is within office hours (for sensitive resources)
     */
    public boolean canAccess(Authentication auth, Long resourceId, String resourceType) {
        User user = userService.findByUsername(auth.getName()).orElse(null);
        if (user == null || !user.isActive()) {
            log.warn("ABAC DENY: user '{}' not found or inactive", auth.getName());
            return false;
        }

        return switch (resourceType) {
            case "REPORT"   -> canAccessReport(user, resourceId);
            case "INVOICE"  -> canAccessInvoice(user, resourceId);
            case "HR_DATA"  -> canAccessHrData(user, resourceId);
            default         -> false;
        };
    }

    /**
     * Report access policy:
     *   - ADMIN can access all reports
     *   - MANAGER can access reports from their own department
     *   - Users can only access public reports
     *   - Sensitive reports: only during office hours
     */
    private boolean canAccessReport(User user, Long reportId) {
        // Simulate fetching resource attributes (in real app: from DB)
        Map<String, String> reportAttrs = getReportAttributes(reportId);
        String reportDept = reportAttrs.getOrDefault("department", "public");
        String sensitivity = reportAttrs.getOrDefault("sensitivity", "public");

        // Environment check: sensitive reports only during office hours
        if ("confidential".equals(sensitivity) && !isWithinOfficeHours()) {
            log.warn("ABAC DENY: confidential report {} accessed outside office hours", reportId);
            return false;
        }

        // Subject-resource match: department attribute comparison
        boolean isAdmin = user.getRoles().stream()
            .anyMatch(r -> r.getName().equals("ROLE_ADMIN"));

        if (isAdmin) return true;

        boolean deptMatch = user.getDepartment() != null &&
            user.getDepartment().equalsIgnoreCase(reportDept);

        boolean clearanceSufficient = isClearanceSufficient(user.getClearanceLevel(), sensitivity);

        boolean result = deptMatch && clearanceSufficient;
        log.info("ABAC {}: user={}, dept={}/{}, clearance={}/{}, officeHours={}",
            result ? "ALLOW" : "DENY",
            user.getUsername(), user.getDepartment(), reportDept,
            user.getClearanceLevel(), sensitivity, isWithinOfficeHours());

        return result;
    }

    private boolean canAccessInvoice(User user, Long invoiceId) {
        // Finance dept or admin only
        return "finance".equalsIgnoreCase(user.getDepartment()) ||
            user.getRoles().stream().anyMatch(r -> r.getName().equals("ROLE_ADMIN"));
    }

    private boolean canAccessHrData(User user, Long targetId) {
        // HR dept or admin only, and only during office hours
        boolean isHr = "hr".equalsIgnoreCase(user.getDepartment());
        boolean isAdmin = user.getRoles().stream().anyMatch(r -> r.getName().equals("ROLE_ADMIN"));
        return (isHr || isAdmin) && isWithinOfficeHours();
    }

    // ── Environment Attributes ────────────────────────────────────────────────

    private boolean isWithinOfficeHours() {
        int hour = LocalTime.now().getHour();
        return hour >= abacProperties.getOfficeHoursStart() && hour < abacProperties.getOfficeHoursEnd();
    }

    private boolean isIpAllowed(String clientIp) {
        // If no allowed IP ranges configured, allow all
        if (abacProperties.getAllowedIpRanges().isEmpty()) {
            return true;
        }
        // In a real app, validate CIDR ranges or IP addresses
        // For now, simple string matching
        return abacProperties.getAllowedIpRanges().stream()
            .anyMatch(clientIp::contains);
    }

    private String getCurrentClientIp() {
        try {
            HttpServletRequest request =
                ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
            String xff = request.getHeader("X-Forwarded-For");
            return xff != null ? xff.split(",")[0].trim() : request.getRemoteAddr();
        } catch (Exception e) {
            return "unknown";
        }
    }

    // ── Helper: Clearance Hierarchy ───────────────────────────────────────────

    private static final Map<String, Integer> CLEARANCE_LEVELS = Map.of(
        "public",       0,
        "internal",     1,
        "confidential", 2,
        "secret",       3
    );

    private boolean isClearanceSufficient(String userClearance, String requiredClearance) {
        int userLevel = CLEARANCE_LEVELS.getOrDefault(userClearance, 0);
        int required  = CLEARANCE_LEVELS.getOrDefault(requiredClearance, 0);
        return userLevel >= required;
    }

    // ── Simulate resource attribute lookup ────────────────────────────────────

    private Map<String, String> getReportAttributes(Long reportId) {
        // In a real app, fetch from DB or a policy information point (PIP)
        if (reportId % 2 == 0) {
            return Map.of("department", "engineering", "sensitivity", "internal");
        } else {
            return Map.of("department", "finance", "sensitivity", "confidential");
        }
    }
}
