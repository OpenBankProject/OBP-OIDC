# OBP-OIDC

# TLDR;

This is a bare bones OpenID Connect (OIDC) provider built with http4s and functional programming in Scala.

This implementation follows the same technology stack as OBP-API-II and integrates with PostgreSQL database for real user authentication.

It's meant to be used with OBP-API and apps such as the OBP Portal by developers.

**For External Access**: To run behind a TLS terminating proxy with HTTPS URLs, set `OIDC_EXTERNAL_URL` environment variable:

```bash
export OIDC_EXTERNAL_URL="https://oidc.yourdomain.com"
./run-server.sh
```

Its not a production grade OIDC server. For that use Keyclock or Hydra etc.

If you're having trouble understanding OIDC with OBP this tool might help.

Designed to create clients for the OBP Apps as it starts up. It will print client_id, secrets and other info so you can copy and paste into your Props or env files.

Designed to read / write to the OBP Users and Consumers tables via SQL views defined in [OBP-API](https://github.com/OpenBankProject/OBP-API/blob/develop/obp-api/src/main/scripts/sql/create_oidc_user_and_views.sql)

### 1. Create OIDC Database Users and Views

This application assumes you have an OBP database running locally.

Please see the following folder which has the SQL scripts to create the users and views:

https://github.com/OpenBankProject/OBP-API/blob/develop/obp-api/src/main/scripts/OIDC

Note: You should edit host and credentials in OBP-API-C/OBP-API/obp-api/src/main/scripts/sql/OIDC/set_and_connect.sql

If you have OBP source code locally you can run the file thus:

```bash
psql -h localhost -p 5432 -d sandbox -U obp -f workspace_2024/OBP-API-C/OBP-API/obp-api/src/main/scripts/sql/OIDC/give_read_access_to_users.sql
psql -h localhost -p 5432 -d sandbox -U obp -f workspace_2024/OBP-API-C/OBP-API/obp-api/src/main/scripts/sql/OIDC/give_read_access_to_clients.sql
psql -h localhost -p 5432 -d sandbox -U obp -f workspace_2024/OBP-API-C/OBP-API/obp-api/src/main/scripts/sql/OIDC/give_admin_access_to_consumers.sql



```

or from with in psql thus

```psql

\i PATH-TO-OBP-API-SOURCE-CODE/obp-api/src/main/scripts/sql/OIDC/FILE_NAME.sql

```

### Step 2: Make sure your passwords are good.

# Configure Environment Variables

Copy the example environment file and edit it with your configuration:

```bash
cp .env.example .env
```

Edit `.env` and update the following important values:

```bash
# Database passwords (CHANGE THESE!)
OIDC_USER_PASSWORD=YourGeneratedPassword123!
OIDC_ADMIN_PASSWORD=YourGeneratedAdminPass456#

# Database connection (verify these match your setup)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=sandbox
```

**Note:** The `.env` file is ignored by git and contains sensitive data. Never commit it to version control!

**Client Configuration:** OIDC client IDs and secrets are automatically generated on first startup. After starting the server, copy the printed client configurations to your client applications (OBP-API Props, Portal env, etc.).

Now you can run the server:

```bash
./run-server.sh
```

NOTE: you should make sure the OBP-API well known url returns the OBP-OIDC address.

**That's it!** 🎉 Copy the printed OIDC client configurations to your OBP projects.

# The long story.

## Prerequisites

- Java 11 or higher
- Maven 3.6+
- PostgreSQL database with OBP schema
- OBP authuser table with validated users

## Database Setup

### 1. PostgreSQL Database

Ensure you have a PostgreSQL database with the OBP authuser table populated with users.

See above.

### 3. Database Configuration

Set environment variables for database connection:

**Read-Only Database User** (for user authentication):

See the sql script.

### Build and Run

1. **Compile the project:**

   ```bash
   mvn clean compile
   ```

2. **Run the server:**

   ```bash
   mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"
   ```

3. **The server starts on http://localhost:9000** and automatically:
   - Creates OIDC clients for OBP-API, Portal, Explorer II, and Opey II
   - Prints complete client configurations for easy integration
   - Tests all database connections

### Using the Run Script (Recommended)

For easier configuration and running:

1. **Copy the example script:**

   ```bash
   cp run-server.example.sh run-server.sh
   ```

2. **Edit your database credentials:**

   ```bash
   vim run-server.sh
   # Edit the DB_* environment variables with your actual database settings
   ```

3. **Make it executable and run:**
   ```bash
   chmod +x run-server.sh
   ./run-server.sh
   ```

The script will:

- ✅ Set all necessary environment variables
- ✅ Build the project
- ✅ Start the server with helpful output
- ✅ Show available endpoint URLs
- ✅ Print ready-to-use OBP-API configuration

### Server Configuration

#### Local Development Mode

By default, the server only exposes OIDC endpoints under `/obp-oidc/*` for security. Administrative and debugging pages are disabled in production.

To enable additional pages for local development and testing, set `LOCAL_DEVELOPMENT_MODE=true`:

```bash
# Enable local development mode (shows /, /health, /stats, /clients pages)
export LOCAL_DEVELOPMENT_MODE=true
mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"
```

**When `LOCAL_DEVELOPMENT_MODE=false` (default/production):**

- ✅ `/obp-oidc/auth` (authorization endpoint) - **ENABLED**
- ✅ `/obp-oidc/token` (token endpoint) - **ENABLED**
- ✅ `/obp-oidc/userinfo` (user info endpoint) - **ENABLED**
- ✅ `/obp-oidc/jwks` (JSON Web Key Set) - **ENABLED**
- ✅ `/obp-oidc/.well-known/openid-configuration` (discovery) - **ENABLED**
- ✅ `/` (root landing page with links) - **ENABLED**
- ✅ `/health` (health check) - **ENABLED**
- ❌ `/obp-oidc/test-login` (standalone test form) - **DISABLED**
- ❌ `/info` (detailed server info) - **DISABLED**
- ❌ `/stats` (statistics dashboard) - **DISABLED**
- ❌ `/clients` (client list) - **DISABLED**

**When `LOCAL_DEVELOPMENT_MODE=true` (development/testing):**

- ✅ All `/obp-oidc/*` endpoints - **ENABLED**
- ✅ `/obp-oidc/test-login` (standalone test form) - **ENABLED**
- ✅ `/` (root landing page with links to /info and /health) - **ENABLED**
- ✅ `/info` (detailed server information and configuration) - **ENABLED**
- ✅ `/health` (health check) - **ENABLED**
- ✅ `/stats` (statistics dashboard) - **ENABLED**
- ✅ `/clients` (client list) - **ENABLED**

**⚠️ Security Note:** Never set `LOCAL_DEVELOPMENT_MODE=true` in production environments, as it exposes:

- Server information page (`/info`) showing configuration and database details
- The `/obp-oidc/test-login` endpoint which bypasses normal OAuth flow
- Statistics and debugging information (`/stats`)
- Client configuration details (`/clients`)

#### Verification Method (Database vs OBP API)

OBP-OIDC supports two modes for verifying users, clients, and listing providers, controlled by a single env var `USE_VERIFY_ENDPOINTS`:

**1. Database Views (Default):** `USE_VERIFY_ENDPOINTS=false`
- Verifies credentials against the `v_oidc_users` database view
- Verifies clients against the `v_oidc_clients` database view
- Lists providers from the `v_oidc_users` database view
- Requires database access to the OBP user/client tables

**2. OBP API Endpoints:** `USE_VERIFY_ENDPOINTS=true`
- Verifies credentials via `POST /obp/v6.0.0/users/verify-credentials`
- Verifies clients via `GET /obp/v6.0.0/oidc/clients/CLIENT_ID`
- Lists providers via `GET /obp/v6.0.0/providers`
- Useful when you don't want to grant direct database access to OBP-OIDC
- Requires `OBP_API_USERNAME` to have `CanVerifyUserCredentials`, `CanGetAnyUser`, `CanGetOidcClient` and `CanGetConsumers` roles
- When combined with `OIDC_SKIP_CLIENT_BOOTSTRAP=true`, no database connection is needed at all

**Configuration:**

```bash
# Default: Use database views (no extra configuration needed)
USE_VERIFY_ENDPOINTS=false

# Alternative: Use OBP API endpoints
USE_VERIFY_ENDPOINTS=true
OBP_API_URL=http://localhost:8080
OBP_API_USERNAME=admin_user          # Needs CanVerifyUserCredentials + CanGetAnyUser + CanGetOidcClient + CanGetConsumers roles
OBP_API_PASSWORD=admin_password
OBP_API_CONSUMER_KEY=your_consumer_key
```

**Startup Output:**

When using database views (`USE_VERIFY_ENDPOINTS=false`):
```
Database connection successful. Found X validated users in v_oidc_users view.
...
USE_VERIFY_ENDPOINTS: false
  Credential verification: v_oidc_users (database view)
  Client verification: v_oidc_clients (database view)
  Provider listing: v_oidc_users (database view)
```

When using OBP API endpoints (`USE_VERIFY_ENDPOINTS=true`):
```
USE_VERIFY_ENDPOINTS: true
  All verification methods use OBP API endpoints
  OBP API Username: admin_user
```

**Note:** When using `USE_VERIFY_ENDPOINTS=true`, the server will retry connecting to the OBP API on startup. It will fail if:
- The OBP API is unreachable after all retry attempts
- The username/password/consumer_key is invalid

The `/info` page (available in Local Development Mode) also displays the current verification method, username, and role status.

#### Authentication Provider Dropdown

The login form intelligently handles the authentication provider selection:

**Production Mode (`LOCAL_DEVELOPMENT_MODE=false`):**

- **Single Provider**: Dropdown is hidden, value submitted via hidden field (cleaner UX)
- **Multiple Providers**: Dropdown is visible for user selection

**Development Mode (`LOCAL_DEVELOPMENT_MODE=true`):**

- **Always shows** the provider dropdown (even with single provider) for testing/debugging

This provides a clean, professional login experience in production while maintaining flexibility for development.

#### Logo Configuration

The login page displays the **Open Bank Project logo by default**. You can customize it with your own logo by setting these environment variables:

```bash
# Set custom logo URL (displays at top of login page)
export LOGO_URL="https://example.com/logo.png"

# Set logo alt text for accessibility
export LOGO_ALT_TEXT="Company Logo"

# Set OBP Portal base URL (used for forgot password and register links)
# Defaults to http://localhost:5174
export OBP_PORTAL_BASE_URL="https://portal.example.com"

# Optional: override the register link (defaults to $OBP_PORTAL_BASE_URL/register).
# Set to an empty string to hide the "Register" link entirely.
export OIDC_REGISTRATION_URL="https://portal.example.com/register"
```

**Default Logo:**

- URL: `https://static.openbankproject.com/images/OBP/OBP_Horizontal_2025.png`
- Alt Text: "Open Bank Project"

**Logo Display:**

- Maximum width: 200px (150px on mobile)
- Maximum height: 80px (60px on mobile)
- Image automatically scales to fit while maintaining aspect ratio
- Appears at the top of the login form, above the "Sign In" heading
- **Clickable** - Links back to the origin domain of the calling application

**Logo Interaction:**

The logo is clickable and links to the origin (domain) of the `redirect_uri` parameter. This provides users an intuitive way to cancel authentication and return to the calling application.

Examples:

- `http://localhost:5174/login/callback` → Logo links to `http://localhost:5174`
- `https://portal.example.com/oauth/callback` → Logo links to `https://portal.example.com`
- `https://api.bank.com:8080/auth/callback` → Logo links to `https://api.bank.com:8080`

**Forgot Password Link:**

The login page includes a "Forgot password?" link that sends users to the OBP Portal's `/forgot-password` page:

- **Default**: Links to `http://localhost:5174/forgot-password`
- **Custom Portal URL**: Set `OBP_PORTAL_BASE_URL` to your Portal host
  - Example: `export OBP_PORTAL_BASE_URL="https://portal.example.com"` → link becomes `https://portal.example.com/forgot-password`

**Register Link:**

The login page also shows a "Don't have an account? Register" link:

- **Default**: Links to `${OBP_PORTAL_BASE_URL}/register` (i.e. `http://localhost:5174/register`)
- **Custom URL**: Set `OIDC_REGISTRATION_URL` to any absolute URL to use a different sign-up page
- **Disable**: Set `OIDC_REGISTRATION_URL=""` to hide the link (for deployments that don't allow self-registration)
- The link carries a `return_to` query parameter containing the original `/obp-oidc/auth?...` authorize URL, so the Portal can send the user straight back into the OAuth flow after they have registered.

**Example (Using Default OBP Logo):**

```bash
# Default logo displays automatically - no configuration needed
mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"
```

**Example (Custom Logo):**

```bash
export LOGO_URL="https://mybank.com/logo.png"
export LOGO_ALT_TEXT="My Bank"
mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"
```

**To remove the logo entirely**, set `LOGO_URL` to an empty string:

```bash
export LOGO_URL=""
mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"
```

#### Port Configuration

The server runs on port **9000** by default. You can change this by setting the `OIDC_PORT` environment variable:

```bash
# Run on default port 9000
mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"

# Run on custom port (e.g., 8080)
export OIDC_PORT=8080
mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"

# Or set inline
OIDC_PORT=8080 mvn exec:java -Dexec.mainClass="com.tesobe.oidc.server.OidcServer"
```

#### Version Configuration

The version displayed on the index page is read from the `VERSION` file in the project root, along with the current full git commit hash. To change the version:

```bash
echo "2.1.0" > VERSION
```

**Examples of version display formats:**

- With git: `v2.1.0 (985212327034751417dfce9845877b627dfff1de)` - Shows version from VERSION file + full git commit hash
- Without git: `v2.1.0 (no-git)` - Shows version from VERSION file when git is unavailable
- Missing VERSION file: `vunknown (985212327034751417dfce9845877b627dfff1de)` - Fallback when VERSION file doesn't exist
- No git, no VERSION: `vunknown (no-git)` - Complete fallback scenario

**Common version formats you can use:**

```bash
# Release versions
echo "2.1.0" > VERSION

# Pre-release versions
echo "2.1.0-BETA" > VERSION
echo "2.1.0-RC1" > VERSION

# Development versions
echo "2.1.0-SNAPSHOT" > VERSION
echo "3.0.0-dev" > VERSION
```

The version will be displayed on the server's index page at `http://localhost:9000/`.

### Discovery Document

```
GET /.well-known/openid-configuration
```

Returns the OIDC discovery document with all endpoint URLs and supported features.

### Authorization Endpoint

```
GET /auth?response_type=code&client_id=YOUR_CLIENT&redirect_uri=YOUR_REDIRECT&scope=openid%20profile%20email&state=ABC123
```

Shows HTML login form for user authentication. Supports authorization code flow.

### Token Endpoint

#### Authorization Code Flow

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=AUTH_CODE&redirect_uri=YOUR_REDIRECT&client_id=YOUR_CLIENT
```

Exchanges authorization code for ID token and access token.

#### Client Credentials Flow

```
POST /token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic BASE64(client_id:client_secret)

grant_type=client_credentials&scope=openid
```

Or using form parameters:

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id=YOUR_CLIENT&client_secret=YOUR_SECRET&scope=openid
```

Returns an access token for service-to-service authentication (no user context). This flow is useful for:

- Backend services accessing APIs
- Machine-to-machine authentication
- Automated processes that don't involve user interaction

Note: Client credentials flow does not return an ID token or refresh token, only an access token.

#### Refresh Token Flow

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=YOUR_REFRESH_TOKEN&client_id=YOUR_CLIENT
```

Exchanges a refresh token for a new access token.

### UserInfo Endpoint

```
GET /userinfo
Authorization: Bearer ACCESS_TOKEN
```

Returns user claims based on token scope.

### JWKS Endpoint

```
GET /jwks
```

Returns JSON Web Key Set for token verification.

## Testing the Server

### Quick Health Check

Test the discovery endpoint:

```bash
curl http://localhost:9000/obp-oidc/.well-known/openid-configuration
```

### Test Client Credentials Flow

```bash
# Using Basic Authentication
curl -X POST http://localhost:9000/obp-oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Authorization: Basic $(echo -n 'YOUR_CLIENT_ID:YOUR_CLIENT_SECRET' | base64)" \
  -d "grant_type=client_credentials&scope=openid"

# Or using form parameters
curl -X POST http://localhost:9000/obp-oidc/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&scope=openid"
```

Replace `YOUR_CLIENT_ID` and `YOUR_CLIENT_SECRET` with the values printed when the server starts.

### Quick Health Check (Legacy)

Once the server is running, test it with these curl commands:

```bash
# Health check
curl -v http://localhost:9000/health
# Expected: "OIDC Provider is running"

# Root welcome page
curl -v http://localhost:9000/
# Expected: HTML page with endpoint documentation
```

### OIDC Discovery Document ⭐

This is the standard OIDC well-known URL that clients use to discover your service:

```bash
curl http://localhost:9000/.well-known/openid-configuration
```

**Expected JSON response:**

```json
{
  "issuer": "http://localhost:9000",
  "authorization_endpoint": "http://localhost:9000/auth",
  "token_endpoint": "http://localhost:9000/token",
  "userinfo_endpoint": "http://localhost:9000/userinfo",
  "jwks_uri": "http://localhost:9000/jwks",
  "response_types_supported": ["code"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email"],
  "token_endpoint_auth_methods_supported": ["client_secret_post"],
  "claims_supported": ["sub", "name", "email", "email_verified"]
}
```

### JSON Web Key Set (JWKS)

```bash
curl http://localhost:9000/jwks
```

**Expected JSON response:**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "your-key-id",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### Authorization Endpoint (Login Form)

```bash
curl "http://localhost:9000/auth?response_type=code&client_id=test-client&redirect_uri=https://example.com/callback&scope=openid%20profile%20email&state=test123"
```

**Expected:** HTML login form

### Browser Testing

Open these URLs in your browser:

- **Welcome Page**: `http://localhost:9000/`
- **Discovery**: `http://localhost:9000/.well-known/openid-configuration`
- **JWKS**: `http://localhost:9000/jwks`
- **Login Form**: `http://localhost:9000/auth?response_type=code&client_id=test-client&redirect_uri=https://example.com/callback&scope=openid&state=test123`

## Authentication

### Database Views

This OIDC provider uses three PostgreSQL database views:

#### User Authentication (`v_oidc_users`)

- Authenticates users from the validated authuser table
- BCrypt password verification
- User profile information (name, email)

#### Client Registration (`v_oidc_clients`)

- Validates registered OIDC clients
- Controls allowed redirect URIs
- Manages client permissions and scopes

#### Client Management (`v_oidc_admin_clients`)

- Provides write access for client administration
- Used by admin database user for CRUD operations
- Supports creating, updating, and deleting OIDC clients

### Supported Database Fields

#### User Fields (`v_oidc_users` view)

- `user_id`: Internal unique identifier
- `username`: Login identifier, used as OIDC subject (`sub`) claim for OBP-API compatibility
- `firstname`, `lastname`: User's full name
- `email`: User's email address
- `provider`: Authentication provider, used as OIDC issuer (`iss`) claim for OBP-API compatibility
- `validated`: Must be true for authentication

#### Client Fields (`v_oidc_clients` and `v_oidc_admin_clients` views)

- `client_id`: Unique client identifier
- `client_secret`: Client authentication secret
- `client_name`: Human-readable client name
- `redirect_uris`: Comma-separated list of allowed redirect URIs
- `grant_types`: Supported OAuth2 grant types
- `response_types`: Supported OAuth2 response types
- `scopes`: Available OAuth2 scopes
- `token_endpoint_auth_method`: Client authentication method
- `created_at`: Client registration timestamp
- `password_pw`: BCrypt password hash
- `password_slt`: Password salt for verification

#### Client Fields (`v_oidc_clients` view)

- `client_id`: Unique client identifier
- `client_secret`: Secret for confidential clients (optional)
- `client_name`: Human-readable application name
- `redirect_uris`: JSON array of allowed callback URLs
- `grant_types`: Supported OAuth2 grant types (default: authorization_code)
- `scopes`: Allowed access scopes (default: openid, profile, email)
- `token_endpoint_auth_method`: Client authentication method

## OBP-API Integration

### JWT Token Claims

For compatibility with OBP-API, JWT tokens are generated with specific claim mappings from the `v_oidc_users` database view:

- **`sub` (Subject)**: Contains the user's `username` field from `v_oidc_users`
  - Source: `v_oidc_users.username`
  - Purpose: OBP-API uses this to identify the user
- **`iss` (Issuer)**: Contains the user's `provider` field from `v_oidc_users`
  - Source: `v_oidc_users.provider`
  - Purpose: OBP-API uses this to identify the authentication provider
- **Standard claims**: Populated from user data in `v_oidc_users`
  - `name`: Combined from `v_oidc_users.firstname` and `v_oidc_users.lastname`
  - `email`: From `v_oidc_users.email`
  - `email_verified`: From `v_oidc_users.validated`

This ensures that OBP-API can correctly identify users using the `sub` field as username and `iss` field as provider, exactly as required for proper integration.

### Token Validation

The OIDC server accepts tokens with various provider-based issuers, providing flexibility for different authentication providers while maintaining security.

## Example OIDC Flow

1. **Authorization Request:**

   ```
   http://localhost:9000/auth?response_type=code&client_id=test-client&redirect_uri=https://example.com/callback&scope=openid%20profile%20email&state=abc123
   ```

2. **User Login:** Enter valid database user credentials

3. **Authorization Code:** Redirected to your callback URL with code parameter

4. **Token Exchange:**

   ```bash
   curl -X POST http://localhost:9000/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code&code=YOUR_CODE&redirect_uri=https://example.com/callback&client_id=test-client"
   ```

5. **UserInfo Request:**
   ```bash
   curl http://localhost:9000/userinfo \
     -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
   ```

## Testing

### Database Connection Test

The server will test the database connection on startup and log the results.

### Integration Tests

Run the test suite:

```bash
mvn test
```

The tests demonstrate:

- Discovery document validation
- JWKS endpoint functionality
- Authorization flow with login forms
- Token generation and validation
- UserInfo endpoint with Bearer tokens
- Complete end-to-end OIDC flow

## Development

### Project Structure

```
src/main/scala/com/tesobe/oidc/
├── server/           # Main server setup
├── endpoints/        # OIDC endpoint implementations
├── auth/            # Database authentication service
├── tokens/          # JWT token handling
├── models/          # Data models with Circe JSON support
└── config/          # Configuration management
```

### Key Components

- **HybridAuthService**: PostgreSQL-based user authentication
- **JwtService**: JWT token generation and validation with RSA256
- **CodeService**: Authorization code management with expiration
- **Endpoints**: Individual OIDC endpoint implementations
- **OidcServer**: Main application with http4s routing

### Database Integration

- **Doobie**: Functional database access with connection pooling
- **HikariCP**: Connection pool management with proper timeouts

### Client Management

- **Automatic Bootstrap**: Creates standard OBP ecosystem clients on startup
- **Environment Configuration**: Fully customizable via environment variables
- **Secure Secret Generation**: Auto-generates cryptographically secure client secrets
- **Update Detection**: Intelligently updates clients when configuration changes
- **BCrypt**: Password verification compatible with OBP-API
- **Read-only Access**: Uses dedicated `oidc_user` with minimal permissions

#### Adding New Startup Clients

To add a new client that gets automatically created during server startup:

1. **Edit the ClientBootstrap.scala file:**

   ```
   OBP-OIDC/src/main/scala/com/tesobe/oidc/bootstrap/ClientBootstrap.scala
   ```

2. **Add your client definition to the `CLIENT_DEFINITIONS` list:**

   ```scala
   ClientDefinition(
     name = "your-new-client-id",
     redirect_uris = "http://localhost:PORT/callback,http://localhost:PORT/oauth/callback"
   )
   ```

3. **Restart the server** - Your new client will be automatically created and its configuration printed to the console for integration with your application.

**Example:** The existing `obp-opey-ii-client` is defined as:

```scala
ClientDefinition(
  name = "obp-opey-ii-client",
  redirect_uris = "http://localhost:5000/callback,http://localhost:5000/oauth/callback"
)
```

### Functional Programming Principles

- Pure functions where possible
- Cats Effect IO for side effects
- Immutable data structures
- Monadic error handling with Either types
- Thread-safe database access with connection pooling

## Security Considerations

- Database user has read-only access to validated users only
- BCrypt password verification with proper salt handling
- Connection pooling with leak detection and timeouts
- SSL/TLS preference for database connections
- Comprehensive logging for security monitoring
- No password storage in memory beyond verification

## Database Callback URL Fix

### Issue: Wrong Callback URL in Database

If you encounter redirect issues where the system redirects to `http://localhost:8080/oauth/callback` instead of `http://localhost:8080/auth/openid-connect/callback`, you need to update the database record.

**Root Cause:** The `consumer` table stores the client's `redirecturl` field, which may have been set incorrectly during initial client creation.

**Fix Steps:**

1. **Run the SQL fix script:**

   ```bash
   psql -d sandbox -f fix-callback-url.sql
   ```

2. **Or manually update via SQL:**

   ```sql
   UPDATE consumer
   SET redirecturl = 'http://localhost:8080/auth/openid-connect/callback'
   WHERE consumerid = 'obp-api-client';
   ```

3. **Verify the fix:**
   ```sql
   SELECT consumerid, name, redirecturl FROM consumer WHERE consumerid = 'obp-api-client';
   ```

**Expected Output:**

```
 client_id    | client_name           | redirecturl
--------------+-----------------------+------------------------------------------------
 obp-api-client| OBP-API Core Service | http://localhost:8080/auth/openid-connect/callback
```

This ensures the OAuth authorization flow redirects to the correct OBP-API endpoint.

## Password Verification Fix

### Issue Resolution - OBP-API Password Hash Compatibility

**Problem:** OBP-OIDC was unable to verify passwords hashed by OBP-API due to incompatible BCrypt format handling.

**Root Cause:** OBP-API uses Lift framework's MegaProtoUser which stores BCrypt hashes in a custom format:

- Format: `password_pw = "b;" + BCrypt.hashpw(password, salt).substring(0, 44)`
- The "b;" prefix indicates BCrypt format
- Hash is truncated to 44 characters
- Salt is stored separately in `password_slt` field

**Solution Implemented:**

1. **Added jBCrypt dependency** (same library used by OBP-API):

   ```xml
   <dependency>
     <groupId>org.mindrot</groupId>
     <artifactId>jbcrypt</artifactId>
     <version>0.4</version>
   </dependency>
   ```

2. **Updated password verification logic** in `HybridAuthService.scala`:

   ```scala
   if (storedHash.startsWith("b;")) {
     val hashWithoutPrefix = storedHash.substring(2) // Remove "b;" prefix
     val generatedHash = JBCrypt.hashpw(plainPassword, salt).substring(0, 44)
     val isMatch = generatedHash == hashWithoutPrefix
   }
   ```

3. **Database view compatibility** - Uses existing `v_oidc_users` view fields:
   - `password_pw` - Contains "b;" + truncated hash
   - `password_slt` - Contains BCrypt salt

**Verification Process:**

1. Detect "b;" prefix format
2. Extract hash without prefix
3. Generate hash using `JBCrypt.hashpw(password, salt)`
4. Truncate to 44 characters
5. Compare with stored hash

**Testing:**

- Use `test-password-verification.scala` to validate implementation
- Comprehensive debug logging added for troubleshooting
- Character-by-character comparison for failed attempts

This fix ensures 100% compatibility with OBP-API password verification.

## Troubleshooting

### Server Startup Hanging

If the server hangs during startup (especially after showing "🚀 Initializing OBP ecosystem OIDC clients..."):

1. **Admin Database Issues**: The server may be waiting for admin database connection

   ```bash
   # Check if admin database user exists and has permissions
   ./test-admin-db.sh
   ```

2. **Quick Fix**: The server has built-in timeouts (15 seconds) and will continue startup
   - Wait up to 30 seconds for automatic recovery
   - Look for timeout warnings in logs
   - Server will provide manual SQL commands if admin DB unavailable

3. **Manual Client Creation**: If admin database unavailable, copy SQL from server logs:

   ```sql
   INSERT INTO v_oidc_admin_clients (client_id, client_secret, client_name, ...)
   VALUES ('obp-api-client', 'your-secret', 'OBP-API', ...);
   ```

4. **Disable Client Bootstrap**: Set environment variable to skip:
   ```bash
   export OIDC_SKIP_CLIENT_BOOTSTRAP=true
   ```

### Database Connection Issues

1. Verify PostgreSQL is running and accessible
2. Check database credentials and permissions:
   - `OIDC_USER_USERNAME` and `OIDC_USER_PASSWORD` for read-only access
   - `OIDC_ADMIN_USERNAME` and `OIDC_ADMIN_PASSWORD` for client management
3. Ensure database views exist:
   - `v_oidc_users` for user authentication
   - `v_oidc_clients` for client validation
   - `v_oidc_admin_clients` for client management (optional)
4. Review database logs for connection errors

### Authentication Failures

1. Verify user exists and is validated in authuser table
2. Check password hash format - should start with "b;" for OBP-API compatibility
3. Verify jBCrypt library is available (org.mindrot:jbcrypt:0.4)
4. Review application logs for detailed password verification debug output
5. Use test-password-verification.scala to validate hash generation
6. Ensure database view returns expected user data

### Callback URL Issues

If authentication succeeds but redirects to wrong URL:

1. Check the `consumer` table `redirecturl` field:

   ```sql
   SELECT consumerid, redirecturl FROM consumer WHERE consumerid = 'obp-api-client';
   ```

2. Should be: `http://localhost:8080/auth/openid-connect/callback` (not `/oauth/callback`)

3. Fix with: `psql -d sandbox -f fix-callback-url.sql`

4. Restart OBP-OIDC service after database changes

## TRACE Logging

### Enabling Detailed Debug Logs

For troubleshooting authentication flows, token generation, and other detailed operations, you can enable TRACE level logging:

**Normal logging (DEBUG level):**

```bash
./run-server.sh
```

**TRACE logging enabled:**

```bash
OIDC_ENABLE_TRACE_LOGGING=true ./run-server.sh
```

### What TRACE Logs Show

When TRACE logging is enabled, you'll see detailed information about:

- **Authorization code validation**: Entry points, code lookup, validation results
- **Token generation**: ID token creation, access token creation, JWT signing
- **User authentication**: Database queries, password verification steps
- **Client operations**: Client lookup, validation processes
- **Internal state**: Memory storage contents, processing steps

**Example TRACE output:**

```
validateAndConsumeCode ENTRY - code: 12345678..., clientId: abc123
Found 5 stored codes in memory
Authorization code validation SUCCESS for sub: user123
Generating ID token for user: user123, client: abc123
Setting azp (Authorized Party) claim to: abc123
ID token generated successfully with azp: abc123
```

### Use Cases for TRACE Logging

- **Debugging authentication failures**: See exactly where the process fails
- **Token generation issues**: Track JWT creation and claims
- **Integration problems**: Understand the complete OIDC flow
- **Performance analysis**: Identify bottlenecks in the authentication process
- **Development**: Understand internal workings during feature development

**Note:** TRACE logging is temporary per session and doesn't modify configuration files. It uses system properties to override the default DEBUG level logging.

## License

This project is licensed under the same terms as the Open Bank Project.

## Features

- **Pure Functional Programming**: Built with Cats Effect IO and immutable data structures
- **Modern Scala**: Uses http4s, Circe for JSON, and functional error handling
- **PostgreSQL Database**: Authenticates real users from OBP authuser table via read-only view
- **Complete OIDC Support**: All essential endpoints for authorization code flow
- **Client Management**: CRUD operations for OIDC clients via admin database user
- **Automatic Client Creation**: Auto-creates OBP-API, Portal, Explorer II, and Opey II clients on startup
- **JWT Tokens**: RS256 signed ID tokens and access tokens
- **BCrypt Password Verification**: Compatible with OBP-API password hashing
- **Integration Tests**: Comprehensive test suite demonstrating full OIDC flow

## Technology Stack

- **Language**: Scala 2.13 with functional programming principles
- **HTTP Framework**: http4s with Ember server
- **Effect System**: Cats Effect IO
- **Database**: PostgreSQL with Doobie for functional database access
- **JSON**: Circe for serialization/deserialization
- **JWT**: Auth0 Java JWT library
- **Build Tool**: Maven
- **Testing**: ScalaTest
