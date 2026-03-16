package com.example.security.service;

import com.example.security.model.Role;
import com.example.security.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

/**
 * ═══════════════════════════════════════════════════════════════════
 *  CUSTOM OIDC USER SERVICE — IdP / CIAM Integration
 *
 *  Called by Spring Security after successful OIDC login.
 *  Receives the ID Token from the IdP (Auth0, Okta, Keycloak, Google).
 *
 *  Responsibilities:
 *   1. Extract identity from ID Token claims (sub, email, name)
 *   2. Map IdP-specific role claims → local RBAC roles
 *   3. Provision user in local DB if first login (JIT provisioning)
 *   4. Sync attributes on subsequent logins
 *
 *  ID Token claim differences per IdP:
 *   Auth0:    roles in "https://myapp.com/roles" (custom namespace)
 *   Okta:     groups in "groups" claim
 *   Keycloak: roles in "realm_access.roles"
 *   Google:   no roles — assign default USER role
 * ═══════════════════════════════════════════════════════════════════
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOidcUserService extends OidcUserService {

    private final UserService userService;
    private final RoleService roleService;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        // 1. Let Spring fetch the ID Token and UserInfo from the IdP
        OidcUser oidcUser = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        log.info("OIDC login via provider: {}", registrationId);

        // 2. Extract standard OIDC claims from the ID Token
        String sub   = oidcUser.getSubject();                      // unique user ID from IdP
        String email = oidcUser.getEmail();
        String name  = oidcUser.getFullName();

        // 3. Extract roles from IdP-specific claim structure
        Set<String> idpRoles = extractRolesFromIdp(oidcUser, registrationId);
        log.info("Roles from IdP '{}': {}", registrationId, idpRoles);

        // 4. JIT Provisioning: create or update user in local DB
        User localUser = userService.findByExternalId(sub)
            .orElseGet(() -> createLocalUserFromOidc(sub, email, name, registrationId));

        // Sync roles from IdP to local RBAC
        syncRoles(localUser, idpRoles);

        log.info("OIDC user '{}' provisioned with roles: {}", email, idpRoles);

        return oidcUser; // Return the original OIDC user — Spring manages the session
    }

    /**
     * Extract roles from different IdP claim structures.
     * Each IdP puts roles in different places in the JWT.
     */
    private Set<String> extractRolesFromIdp(OidcUser oidcUser, String registrationId) {
        return switch (registrationId) {
            case "auth0" -> {
                // Auth0: custom namespace claim (configured in Auth0 Action/Rule)
                Object roles = oidcUser.getClaim("https://myapp.com/roles");
                yield toStringSet(roles);
            }
            case "okta" -> {
                // Okta: groups claim (configured in Okta app's Groups Claims filter)
                Object groups = oidcUser.getClaim("groups");
                yield toStringSet(groups);
            }
            case "keycloak" -> {
                // Keycloak: nested claim — realm_access.roles
                Map<String, Object> realmAccess = oidcUser.getClaim("realm_access");
                if (realmAccess != null) {
                    yield toStringSet(realmAccess.get("roles"));
                }
                yield Set.of("USER"); // default
            }
            case "google" -> {
                // Google doesn't provide app roles — assign default
                yield Set.of("USER");
            }
            default -> Set.of("USER");
        };
    }

    @SuppressWarnings("unchecked")
    private Set<String> toStringSet(Object value) {
        if (value instanceof List<?> list) {
            return list.stream().map(Object::toString).collect(Collectors.toSet());
        }
        return Set.of("USER");
    }

    /**
     * Just-In-Time (JIT) user provisioning.
     * Creates a local user record on first OIDC login.
     */
    private User createLocalUserFromOidc(String sub, String email, String name, String provider) {
        User user = User.builder()
            .externalId(sub)
            .email(email)
            .username(email)  // use email as username for federated users
            .provider(provider)
            .active(true)
            .department("general") // default; update via profile flow
            .clearanceLevel("internal")
            .build();

        return userService.save(user);
    }

    private void syncRoles(User user, Set<String> idpRoles) {
        Set<Role> roles = idpRoles.stream()
            .map(roleName -> roleService.findOrCreate("ROLE_" + roleName.toUpperCase()))
            .collect(Collectors.toSet());

        user.setRoles(roles);
        userService.save(user);
    }
}
