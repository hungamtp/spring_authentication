package com.example.security.repository;

import com.example.security.model.User;

import java.util.Optional;

public interface UserRepository extends org.springframework.data.jpa.repository.JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByExternalId(String externalId);
}
