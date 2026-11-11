# Test Login Endpoint Security

## Overview

The `/obp-oidc/test-login` endpoint is a standalone testing tool that allows manual authentication verification without requiring a full OAuth 2.0 client application.

## Purpose

This endpoint was designed for:
- **Development**: Quick testing of authentication without setting up a full OAuth client
- **Debugging**: Manual verification of username/password/provider combinations
- **Testing**: Simplified testing workflow during development

## Security Implications

### Why It's Dangerous in Production

The `/obp-oidc/test-login` endpoint **bypasses the normal OAuth 2.0 authorization flow**:

1. **No Client Validation**: Does not require a registered `client_id`
2. **No Redirect URI Validation**: Does not validate redirect URIs
3. **Direct Credentials**: Exposes a form that directly accepts credentials
4. **Information Disclosure**: Shows all available authentication providers in a dropdown
5. **Testing Interface**: Clearly identifies itself as a test interface

### Normal OAuth Flow (Secure)

```
User → Client App → /obp-oidc/auth (with client_id, redirect_uri) 
  → Login Form → Validate Client → Authenticate 
  → Generate Code → Redirect to Client
```

### Test Login Flow (Insecure for Production)

```
User → /obp-oidc/test-login → Enter Credentials Directly 
  → No Client Validation → Authenticate → Show Results
```

## Protection Mechanism

### Implementation

The endpoint is conditionally enabled based on the `LOCAL_DEVELOPMENT_MODE` configuration:

**Location**: `src/main/scala/com/tesobe/oidc/endpoints/AuthEndpoint.scala`

```scala
case GET -> Root / "obp-oidc" / "test-login"
    if config.localDevelopmentMode =>
  showStandaloneLoginForm()
```

### Configuration

```bash
# Production (default) - test-login disabled
LOCAL_DEVELOPMENT_MODE=false

# Development - test-login enabled
LOCAL_DEVELOPMENT_MODE=true
```

### Behavior

| Mode | test-login Status | Use Case |
|------|------------------|----------|
| `LOCAL_DEVELOPMENT_MODE=false` | **404 Not Found** | Production deployment |
| `LOCAL_DEVELOPMENT_MODE=true` | **200 OK** (form displayed) | Development/Testing |

## Usage

### Development Environment

When `LOCAL_DEVELOPMENT_MODE=true`:

1. Navigate to `http://localhost:9000/obp-oidc/test-login`
2. Fill in the form:
   - **Client ID**: Any valid registered client ID
   - **Redirect URI**: Registered redirect URI for that client
   - **Scope**: `openid email profile` (or other valid scopes)
   - **State**: Optional state parameter
   - **Nonce**: Optional nonce parameter
   - **Username**: Username (not empty, at most 100 characters)
   - **Password**: Password (not empty, at most 512 characters)
   - **Provider**: Authentication provider (not empty, at most 512 characters)
3. Click "Sign In"
4. On success, redirected to the redirect URI with authorization code

### Production Environment

When `LOCAL_DEVELOPMENT_MODE=false`:

Accessing `http://your-server/obp-oidc/test-login` returns:
```
404 Not Found
Endpoint not enabled
```

## Comparison with Production Endpoint

### `/obp-oidc/test-login` (Development Only)

- ❌ Form includes client_id, redirect_uri, scope fields
- ❌ No pre-validation of client
- ❌ Direct submission without client app
- ❌ Exposes provider list in HTML
- ✅ Quick testing without OAuth client

### `/obp-oidc/auth` (Production)

- ✅ Requires query parameters from OAuth client
- ✅ Validates client_id and redirect_uri before showing form
- ✅ Only shows username/password/provider fields
- ✅ Follows standard OAuth 2.0 flow
- ✅ Full security controls

## Security Checklist

Before deploying to production:

- [ ] Verify `LOCAL_DEVELOPMENT_MODE=false` is set
- [ ] Test that `/obp-oidc/test-login` returns 404
- [ ] Verify `/obp-oidc/auth` still works with valid OAuth parameters
- [ ] Check logs to ensure no one is accessing test-login in production
- [ ] Document this endpoint's purpose for future developers

## Alternative Testing Approaches

For production-like testing without exposing test-login:

1. **Use Real OAuth Client**: Set up Portal/Explorer as OAuth client
2. **Postman/OAuth Testing Tools**: Use OAuth 2.0 testing tools
3. **Integration Tests**: Automated tests that use proper OAuth flow
4. **Staging Environment**: Enable test-login only in staging, not production

## Related Documentation

- Local Development Mode: `README.md` (Local Development Mode section)
- OAuth 2.0 Flow: `README.md` (Authorization Endpoint section)
- Security Improvements: `notes/security-improvements-summary.md`

## Summary

The `/obp-oidc/test-login` endpoint is a convenient development tool that must be disabled in production. The `LOCAL_DEVELOPMENT_MODE` configuration provides clear control over this and other development-only features, ensuring production security while maintaining development convenience.
