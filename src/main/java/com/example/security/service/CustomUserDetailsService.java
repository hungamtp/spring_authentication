package com.example.security.service;

import com.example.security.model.Permission;
import com.example.security.model.Role;
import com.example.security.model.User;
import com.example.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

import jakarta.persistence.*;
import java.util.*;
import java.util.stream.*;

/**
 * Loads user from DB and maps roles + permissions to Spring GrantedAuthorities.
 *
 * RBAC mapping:
 *   Role "ROLE_ADMIN" + Permission "USER_READ"
 *   → authorities: [ROLE_ADMIN, USER_READ]
 *   → hasRole('ADMIN') ✅  hasAuthority('USER_READ') ✅
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        return org.springframework.security.core.userdetails.User.builder()
            .username(user.getUsername())
            .password(user.getPassword() != null ? user.getPassword() : "")
            .authorities(buildAuthorities(user))
            .accountExpired(false)
            .accountLocked(!user.isActive())
            .credentialsExpired(false)
            .disabled(!user.isActive())
            .build();
    }

    /**
     * Build GrantedAuthorities from RBAC model:
     *   - Each Role → "ROLE_X" authority
     *   - Each Permission within each Role → authority (without prefix)
     */
    private Collection<GrantedAuthority> buildAuthorities(User user) {
        Set<GrantedAuthority> authorities = new HashSet<>();

        for (Role role : user.getRoles()) {
            // Add the role itself (e.g. ROLE_ADMIN)
            authorities.add(new SimpleGrantedAuthority(role.getName()));

            // Add all permissions the role grants (e.g. USER_READ, REPORT_WRITE)
            for (Permission permission : role.getPermissions()) {
                authorities.add(new SimpleGrantedAuthority(permission.getName()));
            }
        }

        return authorities;
    }
}

