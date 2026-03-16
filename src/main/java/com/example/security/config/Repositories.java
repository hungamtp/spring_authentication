package com.example.security.config;

import com.example.security.model.Permission;
import com.example.security.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

interface PermissionRepository extends JpaRepository<Permission, Long> {
    Optional<Permission> findByName(String name);
}

interface RoleRepository2 extends JpaRepository<Role, Long> {
    Optional<Role> findByName(String name);
}
