package com.example.security.model;

import jakarta.persistence.*;
import lombok.*;
import java.util.HashSet;
import java.util.Set;

/**
 * ── Role Entity (RBAC) ───────────────────────────────────────────────────────
 *
 * A Role groups a set of Permissions.
 * Users are assigned Roles. Roles contain fine-grained Permissions.
 *
 * RBAC hierarchy:
 *   ADMIN   → [USER_READ, USER_WRITE, USER_DELETE, REPORT_READ, REPORT_WRITE]
 *   MANAGER → [USER_READ, REPORT_READ, REPORT_WRITE]
 *   USER    → [USER_READ, REPORT_READ]
 */
@Entity
@Table(name = "roles")
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Stored as "ROLE_ADMIN", "ROLE_MANAGER", etc. to align with Spring Security
    @Column(unique = true, nullable = false)
    private String name;

    private String description;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "role_permissions",
        joinColumns = @JoinColumn(name = "role_id"),
        inverseJoinColumns = @JoinColumn(name = "permission_id")
    )
    @Builder.Default
    private Set<Permission> permissions = new HashSet<>();
}
