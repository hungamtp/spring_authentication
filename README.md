# Spring Security Demo
### OAuth2 · OIDC · JWT · RBAC/ABAC · IdP/CIAM · mTLS/TLS · PKI

A fully-documented Spring Boot 3 project demonstrating every major identity
and security concept in one cohesive codebase.

---

## Project Structure

```
src/main/java/com/example/security/
├── SecurityDemoApplication.java
│
├── config/
│   ├── SecurityConfig.java       ← OAuth2, JWT RS, mTLS, RBAC rules
│   ├── MtlsConfig.java           ← X.509 client cert logging
│   ├── DataInitializer.java      ← Seeds users/roles/permissions on startup
│   └── Repositories.java         ← JPA repositories
│
├── filter/
│   └── JwtAuthenticationFilter.java  ← Extracts + validates local JWTs
│
├── service/
│   ├── CustomUserDetailsService.java ← Loads user, maps roles → authorities
│   ├── CustomOidcUserService.java    ← OIDC login + JIT user provisioning
│   ├── AbacPolicyService.java        ← ABAC policy evaluation engine
│   ├── UserService.java
│   └── RoleService.java
│
├── controller/
│   ├── AuthController.java       ← POST /api/auth/login → JWT
│   └── ResourceController.java   ← Protected endpoints (RBAC + ABAC)
│
├── model/
│   ├── User.java                 ← User entity with ABAC attributes
│   ├── Role.java                 ← Role entity (RBAC)
│   └── Permission.java           ← Fine-grained permission entity
│
└── util/
    └── JwtUtil.java              ← JWT create / validate / extract claims
```

---

## Concepts Covered

### 1. TLS (Transport Layer Security)
Configured in `application.yml`:
```yaml
server:
  ssl:
    enabled: true
    key-store: classpath:certs/server-keystore.p12
```
All traffic is encrypted in transit. The server presents its certificate
(signed by your CA) and the client verifies it.

---

### 2. mTLS (Mutual TLS)
```yaml
server:
  ssl:
    client-auth: need         # server also requires a client certificate
    trust-store: classpath:certs/truststore.p12
```
In `SecurityConfig.java`:
```java
.x509(x509 -> x509
    .subjectPrincipalRegex("CN=(.*?)(?:,|$)")
    .userDetailsService(userDetailsService)
)
```
The server extracts `CN=dev-client` from the client cert and uses it as
the principal name. `MtlsConfig.java` logs the full cert details.

---

### 3. PKI (Public Key Infrastructure)
Run `./generate-certs.sh` to create a minimal PKI chain:

```
Root CA (self-signed, 4096-bit RSA)
    └── Server Cert  (signed by Root CA, SAN=localhost)
    └── Client Cert  (signed by Root CA, EKU=clientAuth)
```

The **truststore** holds the Root CA cert. The server uses it to verify
that the client cert was signed by a trusted CA — that's PKI in action.

Test with curl (mTLS):
```bash
curl --cacert src/main/resources/certs/rootca.cer \
     --cert    src/main/resources/certs/client-cert.pem \
     --key     src/main/resources/certs/client-key.pem \
     https://localhost:8443/api/public/health
```

---

### 4. OAuth2 + OIDC
Two flows configured in `SecurityConfig.java`:

**Authorization Code Flow (OIDC login — web browser):**
```
Browser → GET /oauth2/authorization/auth0
        → Redirect to Auth0 login page
        → Auth0 → POST /login/oauth2/code/auth0 (with code)
        → Spring exchanges code → Access Token + ID Token
        → CustomOidcUserService extracts claims, provisions user
        → Session created, user logged in
```

**Resource Server (API — Bearer JWT):**
```
Client → POST /api/auth/login { username, password }
       → Receives JWT (locally issued)

     OR

Client → Obtains JWT from IdP (Auth0/Okta/Keycloak)
       → GET /api/reports/1
         Authorization: Bearer <jwt>
       → Spring validates JWT signature via JWKS endpoint
       → Extracts roles from claims → RBAC applied
```

---

### 5. JWT (JSON Web Token)
`JwtUtil.java` creates and validates locally-issued JWTs:

```
HEADER:  { "alg": "HS256", "typ": "JWT" }
PAYLOAD: {
  "sub":   "alice",
  "roles": ["ROLE_USER"],
  "perms": ["USER_READ", "REPORT_READ"],
  "dept":  "engineering",         ← ABAC attribute embedded in token
  "exp":   1710003600,
  "jti":   "unique-token-id"
}
SIGNATURE: HMACSHA256(header + "." + payload, secret)
```

`JwtAuthenticationConverter` maps JWT claims → Spring `GrantedAuthority` list.

---

### 6. IdP / CIAM Integration
`CustomOidcUserService.java` handles OIDC login from any provider:

| Provider  | Type      | Roles Claim                        |
|-----------|-----------|------------------------------------|
| Auth0     | CIAM      | `https://myapp.com/roles` (custom) |
| Okta      | Workforce | `groups`                           |
| Keycloak  | Self-host | `realm_access.roles`               |
| Google    | Social    | *(none — default USER role)*       |

**JIT Provisioning**: On first OIDC login, a local `User` record is created
from the ID Token claims (`sub`, `email`, `name`). On subsequent logins,
roles are synced from the IdP.

---

### 7. RBAC (Role-Based Access Control)
Modeled as `User → Role → Permission` in the DB.

```
ROLE_ADMIN   → USER_READ, USER_WRITE, USER_DELETE, REPORT_READ, REPORT_WRITE
ROLE_MANAGER → USER_READ, REPORT_READ, REPORT_WRITE
ROLE_USER    → USER_READ, REPORT_READ
```

Enforced at the endpoint level via `@PreAuthorize`:
```java
@PreAuthorize("hasRole('ADMIN')")               // role check
@PreAuthorize("hasAuthority('REPORT_WRITE')")   // permission check
@PreAuthorize("hasAnyRole('ADMIN', 'MANAGER')") // multi-role
```

---

### 8. ABAC (Attribute-Based Access Control)
`AbacPolicyService.java` evaluates access based on:
- **Subject attributes**: `user.department`, `user.clearanceLevel`, `user.active`
- **Resource attributes**: `report.department`, `report.sensitivity`
- **Environment**: time of day, IP address

```java
@PreAuthorize("@abacService.canAccess(authentication, #reportId, 'REPORT')")
```

Example policy for reports:
```
ALLOW if:
  user.active == true
  AND (user.role == ADMIN OR user.department == report.department)
  AND user.clearanceLevel >= report.sensitivity
  AND (report.sensitivity != 'confidential' OR isWithinOfficeHours())
```

---

## Quick Start

### Prerequisites
- Java 21
- Maven 3.8+
- openssl + keytool (for cert generation)

### 1. Generate certificates
```bash
chmod +x generate-certs.sh
./generate-certs.sh
```

### 2. Configure your IdP (optional for OIDC)
Edit `application.yml` and replace placeholder values:
```yaml
spring.security.oauth2.client.registration.auth0:
  client-id:     YOUR_AUTH0_CLIENT_ID
  client-secret: YOUR_AUTH0_CLIENT_SECRET
```
> Skip this to use local JWT auth only (no OIDC needed).

### 3. Run
```bash
mvn spring-boot:run
```

### 4. Test endpoints

**Login (local JWT):**
```bash
TOKEN=$(curl -sk -X POST https://localhost:8443/api/auth/login \
  --cert src/main/resources/certs/client-cert.pem \
  --key  src/main/resources/certs/client-key.pem \
  --cacert src/main/resources/certs/rootca.cer \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' \
  | jq -r .accessToken)
```

**RBAC-protected endpoint (Admin only):**
```bash
curl -sk https://localhost:8443/api/admin/dashboard \
  --cert src/main/resources/certs/client-cert.pem \
  --key  src/main/resources/certs/client-key.pem \
  --cacert src/main/resources/certs/rootca.cer \
  -H "Authorization: Bearer $TOKEN"
```

**ABAC-protected endpoint (dept + clearance + office hours):**
```bash
curl -sk https://localhost:8443/api/reports/1 \
  --cert src/main/resources/certs/client-cert.pem \
  --key  src/main/resources/certs/client-key.pem \
  --cacert src/main/resources/certs/rootca.cer \
  -H "Authorization: Bearer $TOKEN"
```

**H2 Console (for inspecting the DB):**
```
https://localhost:8443/h2-console
JDBC URL: jdbc:h2:mem:securitydb
Username: sa  |  Password: (empty)
```

---

## Seeded Users

| Username | Password    | Role         | Dept        | Clearance    |
|----------|-------------|--------------|-------------|--------------|
| admin    | admin123    | ROLE_ADMIN   | engineering | secret       |
| manager  | manager123  | ROLE_MANAGER | finance     | confidential |
| alice    | alice123    | ROLE_USER    | engineering | internal     |
| bob      | bob123      | ROLE_USER    | finance     | internal     |

---

## Key Files Reference

| File | Concept |
|------|---------|
| `SecurityConfig.java` | OAuth2, JWT RS, mTLS X.509, RBAC rules |
| `JwtUtil.java` | JWT creation, signing, validation, claim extraction |
| `JwtAuthenticationFilter.java` | Bearer token extraction per-request |
| `CustomOidcUserService.java` | OIDC login, JIT provisioning, IdP role mapping |
| `AbacPolicyService.java` | ABAC policy evaluation (dept, clearance, time) |
| `ResourceController.java` | @PreAuthorize RBAC + ABAC examples |
| `DataInitializer.java` | Seeds Permission → Role → User hierarchy |
| `generate-certs.sh` | PKI: Root CA → Server Cert + Client Cert |
| `application.yml` | TLS, mTLS, OAuth2 client + resource server config |


## Provider
Keycloak 22.0.1 (self-hosted IdP)
- Realm: `demo`
- Client: `demo-app` (confidential, auth code flow, JWKS endpoint enabled)
- Roles: `admin`, `manager`, `user`
- Users: `alice` (user), `bob` (manager), `carol` (admin) with password `password123`
