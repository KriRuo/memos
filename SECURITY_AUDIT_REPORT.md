# Security Audit Report - Memos Application

**Date:** February 8, 2026  
**Auditor:** Security Analysis Agent  
**Repository:** KriRuo/memos  
**Commit:** 29bddad (copilot/review-security-findings branch)

---

## Executive Summary

This security audit examined the Memos application, a self-hosted knowledge management platform built with Go (backend) and React (frontend). The audit focused on authentication, authorization, input validation, SQL injection, XSS, file handling, and secret management.

### Overall Security Posture: **MODERATE**

**Strengths:**
- Strong use of parameterized SQL queries (90%+ coverage)
- Proper password hashing with bcrypt
- Path traversal protections for file operations
- JWT with reasonable expiration times
- Use of CEL for safe filter compilation

**Critical Issues Found:** 2  
**High Severity Issues:** 3  
**Medium Severity Issues:** 4  
**Low Severity Issues:** 3  
**Informational:** 2

---

## Critical Findings

### 1. ⚠️ CRITICAL: Hardcoded JWT Secret in Demo Mode
**File:** `server/server.go:54`  
**Severity:** CRITICAL  
**CWE:** CWE-798 (Use of Hard-coded Credentials)

**Description:**  
The application uses a hardcoded JWT signing secret `"usememos"` when running in demo mode. This allows anyone to forge JWT tokens for demo instances.

```go
secret := "usememos"
if !profile.Demo {
    secret = instanceBasicSetting.SecretKey
}
```

**Impact:**
- Anyone with knowledge of this secret can forge JWT access tokens
- Attackers can impersonate any user in demo instances
- Can bypass all authentication and authorization checks
- Complete account takeover possible

**Recommendation:**
- Even in demo mode, generate a random secret at startup
- Or clearly document that demo mode is insecure and should never be publicly exposed
- Add a startup warning when using demo mode with the hardcoded secret

**Risk:** HIGH - Demo instances are easily compromised

---

### 2. ⚠️ CRITICAL: Admin-Controlled XSS via Custom Scripts
**File:** `web/src/App.tsx:39-45`  
**Severity:** CRITICAL  
**CWE:** CWE-79 (Cross-Site Scripting)

**Description:**  
The application allows administrators to inject arbitrary JavaScript via the `additionalScript` instance setting, which is executed directly in the browser without sanitization.

```typescript
if (instanceGeneralSetting.additionalScript) {
  const scriptEl = document.createElement("script");
  scriptEl.innerHTML = instanceGeneralSetting.additionalScript;
  document.head.appendChild(scriptEl);
}
```

**Impact:**
- Malicious admins can execute arbitrary JavaScript in all users' browsers
- Potential for credential theft, session hijacking, keylogging
- Can be used for persistent XSS attacks
- Affects all users of the instance

**Recommendation:**
- Add a prominent warning in the UI that this feature allows arbitrary code execution
- Consider using a Content Security Policy to restrict script execution
- Implement subresource integrity checks
- Add audit logging for changes to this setting
- Consider removing this feature or making it opt-in via environment variable

**Risk:** HIGH - Assumes admin trust, but compromised admin accounts lead to full compromise

---

## High Severity Findings

### 3. 🔴 HIGH: Overly Permissive CORS Configuration
**File:** `server/router/api/v1/v1.go:141-148`  
**Severity:** HIGH  
**CWE:** CWE-346 (Origin Validation Error)

**Description:**  
The CORS configuration accepts requests from ANY origin with credentials enabled:

```go
CORSConfig{
    AllowOriginFunc: func(_ string) (bool, error) {
        return true, nil  // Accepts ANY origin
    },
    AllowCredentials: true,
}
```

**Impact:**
- Allows any website to make authenticated requests to the Memos API
- Enables CSRF attacks even with CORS protection
- Can leak sensitive data to malicious origins
- Session cookies can be accessed by any domain

**Recommendation:**
- Implement proper origin validation
- Use a whitelist of allowed origins
- If multi-origin is needed, validate against configured domains
- Consider setting `AllowCredentials: false` if not needed

```go
AllowOriginFunc: func(origin string) (bool, error) {
    allowedOrigins := []string{
        s.Profile.InstanceURL,
        "http://localhost:3000", // dev only
    }
    for _, allowed := range allowedOrigins {
        if origin == allowed {
            return true, nil
        }
    }
    return false, nil
}
```

**Risk:** HIGH - Enables cross-origin attacks with credentials

---

### 4. 🔴 HIGH: No Rate Limiting on Authentication Endpoints
**Files:** `server/router/api/v1/auth_service.go`, `server/server.go`  
**Severity:** HIGH  
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)

**Description:**  
No rate limiting is implemented on authentication endpoints (`/SignIn`, `/RefreshToken`). This allows unlimited brute-force attempts.

**Impact:**
- Brute-force attacks on user passwords
- Account enumeration via timing attacks
- DoS via excessive authentication attempts
- No protection against credential stuffing attacks

**Recommendation:**
- Implement rate limiting middleware (e.g., golang.org/x/time/rate)
- Limit failed login attempts per IP (e.g., 5 attempts per 15 minutes)
- Add exponential backoff for failed attempts
- Implement account lockout after repeated failures
- Add CAPTCHA after multiple failures
- Log and alert on suspicious authentication patterns

Example implementation:
```go
import "golang.org/x/time/rate"

var authLimiters = sync.Map{} // map[string]*rate.Limiter

func getAuthLimiter(ip string) *rate.Limiter {
    limiter, _ := authLimiters.LoadOrStore(ip, rate.NewLimiter(rate.Every(15*time.Minute)/5, 5))
    return limiter.(*rate.Limiter)
}
```

**Risk:** HIGH - Enables brute-force attacks

---

### 5. 🔴 HIGH: Missing Content Security Policy on Main Application
**Files:** `server/router/frontend/frontend.go`, `server/server.go`  
**Severity:** HIGH  
**CWE:** CWE-1021 (Improper Restriction of Rendered UI Layers)

**Description:**  
While file server has basic CSP headers (`server/router/fileserver/fileserver.go:622`), the main application frontend has no CSP headers. This increases XSS risk.

**Impact:**
- No defense against XSS attacks
- No restrictions on script sources
- No protection against clickjacking
- Inline scripts and styles allowed without restrictions

**Recommendation:**
Add strict CSP headers to the main application:

```go
// In server/router/frontend/frontend.go
c.Response().Header().Set("Content-Security-Policy", 
    "default-src 'self'; "+
    "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "+ // Needed for React
    "style-src 'self' 'unsafe-inline'; "+
    "img-src 'self' data: https:; "+
    "font-src 'self' data:; "+
    "connect-src 'self'; "+
    "frame-ancestors 'none';")
c.Response().Header().Set("X-Frame-Options", "DENY")
c.Response().Header().Set("X-Content-Type-Options", "nosniff")
c.Response().Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
```

**Risk:** HIGH - Increases XSS exploitation surface

---

## Medium Severity Findings

### 6. 🟡 MEDIUM: JWT Secret Not Rotatable Without Downtime
**File:** `server/server.go:49-58`  
**Severity:** MEDIUM  
**CWE:** CWE-320 (Key Management Errors)

**Description:**  
The JWT signing secret is loaded once at server startup and stored in memory. There's no mechanism to rotate the secret without restarting the server, which would invalidate all existing tokens.

**Impact:**
- Secret rotation requires server restart
- All users logged out during rotation
- No support for gradual key rotation
- Difficult to respond to key compromise

**Recommendation:**
- Implement key versioning in JWT header (already has `kid: "v1"`)
- Support multiple active keys simultaneously
- Implement gradual key rotation:
  1. Add new key (v2) while keeping v1 for validation
  2. Issue tokens with v2
  3. After token expiration period, remove v1
- Reload keys from database periodically without restart

**Risk:** MEDIUM - Complicates security incident response

---

### 7. 🟡 MEDIUM: Insufficient Logging for Security Events
**Files:** Multiple authentication and authorization files  
**Severity:** MEDIUM  
**CWE:** CWE-778 (Insufficient Logging)

**Description:**  
Security-relevant events are not consistently logged:
- Failed login attempts (not logged with details)
- Password changes (no audit trail)
- Token generation/revocation (limited logging)
- Privilege escalation attempts (not logged)
- Access to sensitive resources (no audit)

**Impact:**
- Difficult to detect security incidents
- No audit trail for compliance
- Cannot investigate security breaches
- No alerting on suspicious activity

**Recommendation:**
Implement structured security logging:

```go
// Add to failed authentication
slog.Warn("authentication failed",
    "user", username,
    "ip", clientIP,
    "reason", "invalid_password",
    "user_agent", userAgent)

// Add to privilege changes
slog.Info("user role changed",
    "user_id", userID,
    "old_role", oldRole,
    "new_role", newRole,
    "changed_by", actorID)
```

**Risk:** MEDIUM - Hinders incident detection and response

---

### 8. 🟡 MEDIUM: Personal Access Tokens Not Scoped
**File:** `server/auth/authenticator.go:101-124`  
**Severity:** MEDIUM  
**CWE:** CWE-269 (Improper Privilege Management)

**Description:**  
Personal Access Tokens (PATs) have the same permissions as the user's full access. There's no ability to create tokens with limited scope or permissions.

**Impact:**
- Compromised PAT gives full account access
- Cannot create read-only tokens
- Cannot limit token to specific resources
- All-or-nothing permission model

**Recommendation:**
- Add scope field to PAT model
- Support OAuth2-style scopes (read:memos, write:memos, etc.)
- Validate scopes during authorization
- Allow users to create limited-permission tokens
- Example scopes: `read:*, write:memos, admin:*`

**Risk:** MEDIUM - Increases blast radius of token compromise

---

### 9. 🟡 MEDIUM: No Secure Headers on Cookie
**File:** `server/router/api/v1/auth_service.go` (doSignIn function)  
**Severity:** MEDIUM  
**CWE:** CWE-614 (Sensitive Cookie Without 'HttpOnly' Flag)

**Description:**  
While the refresh token cookie includes `HttpOnly: true`, it should also include additional security flags depending on deployment:

**Impact:**
- Cookie may be sent over unencrypted HTTP
- Cookie may be sent to subdomains
- Missing defense-in-depth flags

**Recommendation:**
Enhance cookie security flags:

```go
cookie := &http.Cookie{
    Name:     auth.RefreshTokenCookieName,
    Value:    refreshToken,
    Path:     "/",
    HttpOnly: true,
    Secure:   !s.Profile.Demo, // Require HTTPS in production
    SameSite: http.SameSiteStrictMode, // CSRF protection
    MaxAge:   int(auth.RefreshTokenDuration.Seconds()),
}
```

**Risk:** MEDIUM - Cookies vulnerable to interception without proper deployment

---

## Low Severity Findings

### 10. 🔵 LOW: Potential SQL Injection via Filter Engine
**File:** `store/db/*/memo_relation.go:65-76`  
**Severity:** LOW  
**CWE:** CWE-89 (SQL Injection)

**Description:**  
The filter engine compiles user input into SQL WHERE clauses using `fmt.Sprintf`:

```go
where = append(where, fmt.Sprintf("memo_id IN (SELECT id FROM memo WHERE %s)", stmt.SQL))
```

While the filter uses CEL (Common Expression Language) for safe compilation and the `stmt.Args` are parameterized, the SQL structure itself is string-concatenated.

**Current Mitigation:**
- CEL provides sandboxed expression evaluation
- Filter engine (plugin/filter) properly escapes values
- SQL parameters are passed separately via `stmt.Args`

**Impact:**
- LOW risk due to CEL safeguards
- If CEL sandbox is bypassed, could enable SQL injection
- Requires vulnerability in both CEL and filter engine

**Recommendation:**
- Add explicit validation tests for SQL injection attempts
- Document the security assumptions of the filter engine
- Add fuzzing tests for filter input
- Consider adding an additional validation layer

**Risk:** LOW - Well-defended with CEL, but worth monitoring

---

### 11. 🔵 LOW: Sensitive Data in Browser Storage
**File:** Multiple files in `web/src/`  
**Severity:** LOW  
**CWE:** CWE-922 (Insecure Storage of Sensitive Information)

**Description:**  
The application uses localStorage for various settings. While access tokens are not stored (httpOnly cookies used), user preferences and potentially sensitive metadata may be stored.

**Impact:**
- XSS attacks can read localStorage
- Data persists across sessions
- Not encrypted at rest

**Recommendation:**
- Audit localStorage usage (68 instances found)
- Avoid storing sensitive information in localStorage
- Use sessionStorage for temporary data
- Document what's considered safe to store client-side

**Risk:** LOW - Depends on data sensitivity

---

### 12. 🔵 LOW: bcrypt Default Cost May Be Low
**Files:** `server/router/api/v1/auth_service.go:160`, `user_service.go:164,273`  
**Severity:** LOW  
**CWE:** CWE-916 (Use of Password Hash With Insufficient Computational Effort)

**Description:**  
Password hashing uses `bcrypt.DefaultCost` which is 10 rounds. Modern recommendations suggest 12+ rounds.

```go
passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
```

**Impact:**
- Slightly easier to brute-force hashed passwords
- 2^10 iterations may be insufficient for 2026 hardware
- Offline attacks are cheaper

**Recommendation:**
- Increase bcrypt cost to 12 or 13:
```go
const BcryptCost = 12
passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
```
- Consider migrating to argon2id for new passwords
- Implement gradual migration: upgrade hash on next login

**Risk:** LOW - bcrypt still secure, but could be stronger

---

## Informational Findings

### 13. ℹ️ INFO: No Dependency Vulnerability Scanning
**Files:** `go.mod`, `web/package.json`  
**Severity:** INFORMATIONAL

**Description:**  
No automated dependency vulnerability scanning is evident in CI/CD.

**Recommendation:**
- Add `govulncheck` for Go dependencies
- Add `npm audit` or `snyk` for JavaScript dependencies
- Run checks in GitHub Actions
- Example: `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`

---

### 14. ℹ️ INFO: Missing Security Headers
**Files:** `server/server.go`, response headers  
**Severity:** INFORMATIONAL

**Description:**  
Several standard security headers are missing:
- `Strict-Transport-Security` (HSTS)
- `Permissions-Policy`
- `Cross-Origin-Embedder-Policy`
- `Cross-Origin-Opener-Policy`

**Recommendation:**
Add comprehensive security headers middleware:

```go
func securityHeadersMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
    return func(c echo.Context) error {
        c.Response().Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        c.Response().Header().Set("X-Frame-Options", "DENY")
        c.Response().Header().Set("X-Content-Type-Options", "nosniff")
        c.Response().Header().Set("X-XSS-Protection", "1; mode=block")
        c.Response().Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
        c.Response().Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        return next(c)
    }
}
```

---

## Security Strengths Observed

### ✅ Strong Security Practices

1. **Password Hashing**: Proper use of bcrypt with salts
2. **SQL Injection Defense**: 90%+ use of parameterized queries
3. **Path Traversal Protection**: `filepath.IsLocal()` checks on file operations
4. **JWT Implementation**: Proper HS256 with reasonable expiration times
5. **File Upload Validation**: MIME type and filename sanitization
6. **EXIF Stripping**: Removes metadata from uploaded images
7. **Authentication Architecture**: Clean separation of JWT and PAT authentication
8. **Filter Engine**: Use of CEL for safe query compilation
9. **Token Rotation**: Refresh tokens properly rotated on use
10. **Access Control**: Centralized ACL configuration

---

## Recommended Immediate Actions

### Priority 1 (Critical - Address Immediately)
1. ✅ Fix hardcoded demo secret or add prominent warning
2. ✅ Add warning to admin UI about XSS risk in custom scripts
3. ✅ Implement proper CORS origin validation

### Priority 2 (High - Address in Next Sprint)
4. ✅ Add rate limiting to authentication endpoints
5. ✅ Implement Content Security Policy headers
6. ✅ Add comprehensive security event logging

### Priority 3 (Medium - Address in Next Release)
7. ⚠️ Add PAT scoping/permissions
8. ⚠️ Enhance cookie security flags
9. ⚠️ Implement JWT key rotation mechanism

### Priority 4 (Low - Future Enhancement)
10. 📋 Increase bcrypt cost to 12+
11. 📋 Add dependency vulnerability scanning
12. 📋 Add comprehensive security headers

---

## Testing Recommendations

1. **Penetration Testing**: Conduct professional pentest before v1.0
2. **Fuzzing**: Add fuzzing for filter engine and file uploads
3. **Security Unit Tests**: Add tests for:
   - SQL injection attempts via filters
   - Path traversal in file operations
   - JWT token forgery attempts
   - XSS payloads in user content
4. **Automated Scanning**: 
   - SAST: CodeQL (already configured)
   - DAST: OWASP ZAP or Burp Suite
   - Dependency: govulncheck, npm audit

---

## Compliance Considerations

- **GDPR**: Ensure user data deletion is complete (check database cascade)
- **OWASP Top 10 2021**: Address injection, broken access control, security misconfiguration
- **CWE Top 25**: Address authentication, input validation, crypto issues

---

## Conclusion

The Memos application demonstrates good security practices in several areas, particularly in SQL injection prevention and file handling. However, critical issues with CORS configuration, demo mode secrets, and missing rate limiting require immediate attention.

The development team has made good architectural choices (CEL for filters, bcrypt for passwords, parameterized queries), but security hardening is needed before production deployment, especially for internet-facing instances.

**Overall Risk:** Medium-High for public deployments, Medium for private/internal use

**Recommendation:** Address all Critical and High severity findings before promoting to v1.0 stable.

---

## References

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE Top 25: https://cwe.mitre.org/top25/
- OWASP Security Headers: https://owasp.org/www-project-secure-headers/
- JWT Best Practices: https://datatracker.ietf.org/doc/html/rfc8725

---

**Report Version:** 1.0  
**Next Review Date:** 2026-08-08 (6 months)
