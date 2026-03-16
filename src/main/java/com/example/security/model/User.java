package com.example.security.model;

import jakarta.persistence.*;
import lombok.*;
import java.util.HashSet;
import java.util.Set;

/**
 * ── User Entity ──────────────────────────────────────────────────────────────
 *
 * Supports both:
 *  - Local users (username/password + roles → RBAC)
 *  - Federated users (from OIDC/IdP — sub claim stored as externalId)
 *
 * RBAC is modeled as a many-to-many: User ↔ Role ↔ Permission
 */
@Entity
@Table(name = "users")
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    private String password;   // null for federated/OIDC users

    @Column(unique = true)
    private String email;

    // OIDC 'sub' claim — links a federated IdP identity to this local user
    @Column(name = "external_id")
    private String externalId;

    // Which IdP issued this user (auth0, okta, keycloak, google, local)
    private String provider;

    // ── ABAC attributes ──────────────────────────────────────────────────────
    private String department;    // e.g. "engineering", "finance", "hr"
    private String clearanceLevel; // e.g. "public", "internal", "confidential", "secret"
    private boolean active = true;

    // ── RBAC: Roles ──────────────────────────────────────────────────────────
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "user_roles",
        joinColumns = @JoinColumn(name = "user_id"),
        inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @Builder.Default
    private Set<Role> roles = new HashSet<>();
}
