# Security Policy

## Supported Versions


| Version | Supported          |
| ------- | ------------------ |
 |
| < 4.0   | :x:                |

## Reporting a Vulnerability
During security testing of MuninnDB I identified a couple of vulnerabilities, mostly around exposure of lesser-skilled users who need more guardrails. 
The most critical issues involve default network binding to 0.0.0.0 (exposing the database to all interfaces) and hard-coded default credentials, 
which could lead to unauthorized access and data exfiltration in production deployments.
I am reporting these issues privately and I have not and will not publicly disclose these vulnerabilities. I think the project is fantastic. 

## Default Binding to 0.0.0.0
CWE-346: Origin Validation Error
Component: docker-compose.yml, muninndb-server flags
Issue:
The current docker-compose.yml and muninndb-server flags default to binding all services to 0.0.0.0 (all interfaces). 
In a cloud environment, this instantly exposes the database to the internet with no authentication barrier on the default vault.
Attack Scenario:
bash# Attacker scans for open ports
nmap -p 8475,8476,8750 target.com

### Finds MuninnDB exposed
curl http://target.com:8475/api/engrams?vault=default
### Returns all engrams with no authentication

### Exfiltrate data
curl http://target.com:8475/api/engrams/export?vault=default > stolen_data.json
Affected Versions: All versions through v0.3.6-alpha
Recommendation:
Change the default listen-host to 127.0.0.1. Users should have to explicitly opt-in to public exposure by typing 0.0.0.0.
Proposed Fix:
yaml# docker-compose.yml
services:
  muninndb:
    environment:
      - MUNINN_LISTEN_HOST=127.0.0.1  # Was: 0.0.0.0

### Or in server flags:
muninndb-server --listen-host 127.0.0.1

## Mandatory First-Run Password Change
CWE-798: Use of Hard-coded Credentials

Issue:
The "root/password" default credential is printed on the login page and documented in the README. There is no enforcement mechanism to change it on first run. Users can (and likely will) forget to change it, leaving databases exposed with known credentials.
Attack Scenario:
bash# Attacker finds MuninnDB instance
### Tries default credentials
curl -X POST http://target.com:8476/api/admin/login \
  -d '{"username":"root","password":"password"}'
### Success → full admin access
Recommendation:
Implement a "Setup State" check. On the first run:

API blocks all ingest and activate calls
Returns HTTP 412 (Precondition Failed) with message: "Initial setup required"
Only allows: PUT /api/admin/password to set initial password
After password set, normal operations resume

Proposed Fix:
go// In server initialization
if !config.HasCompletedSetup() {
    return errors.New("Setup required: POST /api/admin/setup with new password")
}

// Setup endpoint
func (s *Server) HandleSetup(w http.ResponseWriter, r *http.Request) {
    var req struct {
        NewPassword string `json:"new_password"`
    }
    // Validate strong password
    // Save to persistent storage
    // Mark setup as complete
    config.SetSetupComplete(true)
}

# Support Non-Interactive Password Management
CWE-255: Credentials Management
Issue:
The muninn admin change-password command is strictly interactive and requires a TTY. This makes it impossible to secure the database in Docker-heavy or CI/CD environments where automated provisioning is standard practice.
Impact:
DevOps teams cannot automate secure deployments. This leads to:

Skipping password changes (using default)
Manual intervention required for every deployment
Inability to use secrets management tools (Vault, AWS Secrets Manager)

Recommendation:
Add support for:

Environment variable: MUNINN_ADMIN_PASSWORD
CLI flag: --new-password or --password-file

Proposed Fix:
bash# Via environment variable
MUNINN_ADMIN_PASSWORD="$(openssl rand -base64 32)" muninn start

### Via CLI flag
muninn admin change-password --new-password "$(cat /run/secrets/muninn_password)"

### Via file (for Docker secrets)
muninn admin change-password --password-file /run/secrets/muninn_password

# Unified REST API Authentication
CWE-287: Improper Authentication
Issue:
Currently, the REST API (port 8475) requires an "admin session," but the login logic is handled exclusively by the UI server (port 8476). 
This creates a circular dependency that breaks API-first usage.
Impact:
Cannot use REST API without running the web UI
API-first tools (curl, SDKs, Postman) cannot authenticate
Forces developers to enable web UI for API access
Recommendation:
Move handleAdminLogin into the core REST API so it can be managed via standard HTTP headers (Bearer token, API key) without needing the Web UI active.
Proposed Architecture:
POST /api/v1/auth/login
  → Returns: JWT token or API key

All subsequent requests:
  Authorization: Bearer <token>

OR

All requests:
  X-API-Key: <key>

# Path "Guardrails" for Watcher
CWE-22: Improper Limitation of a Pathname
Issue:
MuninnDB allows watch_paths to point anywhere on the filesystem. A naive user could accidentally point it at /, /etc, /root, or ~/.ssh, causing it to embed sensitive system secrets into its vector space.
Attack Scenario:
yaml# User makes innocent mistake
watch_paths:
  - /var/log  # Thinks: "I want application logs"

### MuninnDB now ingests:
- /var/log/auth.log (failed login attempts, usernames)
- /var/log/syslog (internal IPs, service configs)
- Private keys if any service logs them

### Attacker queries:
curl http://localhost:8475/api/activate \
  -d '{"context":["password"]}'
### Returns engrams containing logged passwords
Recommendation:
Implement a "Sensitive Path Blocklist":
Blocked by default:
- /etc/*
- /root/*
- /var/log/auth.log
- /var/log/secure
- ~/.ssh/*
- ~/.aws/*
- ~/.config/*
- /proc/*
- /sys/*
If a user wants to watch these paths, require explicit opt-in:
bashmuninn start --allow-sensitive-paths
 Or in config:
allow_sensitive_paths: true
Show WARNING on startup:
⚠️  WARNING: Watching sensitive path '/etc/'. 
   This may embed system secrets in vector space.
   Use --allow-sensitive-paths to suppress this warning.

# Improve "Not Found" Error Clarity
CWE-209: Information Exposure Through Error Message
Issue:
When attempting to change the admin password, the error message admin user not found: pebble:
not found is highly misleading because the user can still log in with the default credentials.
Impact:

User confusion
Delayed security hardening (users give up on password change)
Potential information disclosure (reveals internal database structure "pebble")

Recommendation:
Distinguish between a "Bootstrap Fallback" user (hardcoded, not in DB) and a "Persistent" user (in DB). Provide clear error messages:
Current:
admin user not found: pebble: not found
Proposed:
Operation failed: Default 'root' user is not yet persisted. 
Please complete first-time setup via POST /api/admin/setup.


Credit
If these issues are fixed and disclosed, I suggest credit in the security advisory as:
Oksana Sudoma, PMP, @boonespacedog  - Security Researcher

Contact Information
Email: boonespacedog@gmail.com

Attestatiion
I certify that:

I have not and will not publicly disclose these vulnerabilities before coordinated disclosure
I have not exploited these vulnerabilities for malicious purposes
I have not shared these details with any third party
I discovered these issues through legitimate security research, as a user

Thank you for your attention and all the best with the project! 
