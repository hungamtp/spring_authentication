package com.example.security.config;

import com.example.security.model.Permission;
import com.example.security.model.Role;
import com.example.security.model.User;
import com.example.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import jakarta.persistence.*;
import java.util.Optional;
import java.util.Set;

/**
 * ── Data Initializer ─────────────────────────────────────────────────────────
 *
 * Seeds the in-memory H2 database with:
 *   Permissions → Roles → Users
 *
 * RBAC hierarchy seeded:
 *
 *   ROLE_ADMIN   → [USER_READ, USER_WRITE, USER_DELETE,
 *                   REPORT_READ, REPORT_WRITE, INVOICE_APPROVE]
 *   ROLE_MANAGER → [USER_READ, REPORT_READ, REPORT_WRITE]
 *   ROLE_USER    → [USER_READ, REPORT_READ]
 *
 * Users seeded:
 *   admin   / admin123   → ROLE_ADMIN,   dept=engineering, clearance=secret
 *   manager / manager123 → ROLE_MANAGER, dept=finance,     clearance=confidential
 *   alice   / alice123   → ROLE_USER,    dept=engineering, clearance=internal
 *   bob     / bob123     → ROLE_USER,    dept=finance,     clearance=internal
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
public class DataInitializer {

    private final PasswordEncoder passwordEncoder;

    @Bean
    CommandLineRunner seedData(
        UserRepository userRepository,
        PermissionRepository permissionRepository,
        RoleRepository2 roleRepository
    ) {
        return args -> {
            log.info("═══ Seeding RBAC data ═══");

            // ── Permissions (fine-grained) ────────────────────────────────────
            Permission userRead       = perm(permissionRepository, "USER_READ",       "Read user profiles");
            Permission userWrite      = perm(permissionRepository, "USER_WRITE",      "Create/update users");
            Permission userDelete     = perm(permissionRepository, "USER_DELETE",     "Delete users");
            Permission reportRead     = perm(permissionRepository, "REPORT_READ",     "View reports");
            Permission reportWrite    = perm(permissionRepository, "REPORT_WRITE",    "Create/edit reports");
            Permission invoiceApprove = perm(permissionRepository, "INVOICE_APPROVE", "Approve invoices");

            // ── Roles (groups of permissions) ─────────────────────────────────
            Role adminRole = role(roleRepository, "ROLE_ADMIN", "System administrator",
                Set.of(userRead, userWrite, userDelete, reportRead, reportWrite, invoiceApprove));

            Role managerRole = role(roleRepository, "ROLE_MANAGER", "Team manager",
                Set.of(userRead, reportRead, reportWrite));

            Role userRole = role(roleRepository, "ROLE_USER", "Regular user",
                Set.of(userRead, reportRead));

            // ── Users ─────────────────────────────────────────────────────────
            createUser(userRepository, "admin", "admin123", "admin@example.com",
                "engineering", "secret", true, Set.of(adminRole));

            createUser(userRepository, "manager", "manager123", "manager@example.com",
                "finance", "confidential", true, Set.of(managerRole));

            createUser(userRepository, "alice", "alice123", "alice@example.com",
                "engineering", "internal", true, Set.of(userRole));

            createUser(userRepository, "bob", "bob123", "bob@example.com",
                "finance", "internal", true, Set.of(userRole));

            log.info("═══ Seeding complete ═══");
            log.info("Users: admin/admin123, manager/manager123, alice/alice123, bob/bob123");
        };
    }

    private Permission perm(PermissionRepository repo, String name, String desc) {
        return repo.findByName(name).orElseGet(() ->
            repo.save(Permission.builder().name(name).description(desc).build()));
    }

    private Role role(RoleRepository2 repo, String name, String desc, Set<Permission> permissions) {
        return repo.findByName(name).orElseGet(() ->
            repo.save(Role.builder().name(name).description(desc).permissions(permissions).build()));
    }

    private void createUser(UserRepository repo, String username, String rawPassword,
                            String email, String dept, String clearance,
                            boolean active, Set<Role> roles) {
        if (repo.findByUsername(username).isEmpty()) {
            repo.save(User.builder()
                .username(username)
                .password(passwordEncoder.encode(rawPassword))
                .email(email)
                .department(dept)
                .clearanceLevel(clearance)
                .active(active)
                .provider("local")
                .roles(roles)
                .build());
            log.info("  Created user: {} | dept={} | clearance={} | roles={}",
                username, dept, clearance, roles.stream().map(Role::getName).toList());
        }
    }
}
