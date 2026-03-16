package com.example.security.model;

import jakarta.persistence.*;
import lombok.*;

/**
 * ── Permission Entity (fine-grained RBAC) ────────────────────────────────────
 *
 * Permissions represent specific actions on resources.
 * They are grouped into Roles and checked via @PreAuthorize("hasAuthority('X')")
 *
 * Examples: USER_READ, USER_WRITE, REPORT_READ, REPORT_WRITE, INVOICE_APPROVE
 */
@Entity
@Table(name = "permissions")
@Getter @Setter @Builder
@NoArgsConstructor @AllArgsConstructor
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String name;   // e.g. "USER_READ", "REPORT_WRITE"

    private String description;
}
