package com.example.security.service;

import com.example.security.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(String name);
}

@Service
public class RoleService {
    private final RoleRepository roleRepository;

    public RoleService(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    public Role findOrCreate(String name) {
        return roleRepository.findByName(name)
            .orElseGet(() -> roleRepository.save(
                Role.builder().name(name).description("Auto-created from IdP").build()
            ));
    }
}
