package com.example.security.service;

import com.example.security.model.*;
import com.example.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public Optional<User> findByExternalId(String externalId) {
        return userRepository.findByExternalId(externalId);
    }

    public User save(User user) {
        return userRepository.save(user);
    }
}
