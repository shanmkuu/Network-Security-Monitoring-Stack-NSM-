---
# Agent Security Guide — NSM Stack
# Instructs all future agents operating on this repository
---

# Security Guide for AI Agents — NSM Stack

This guide is mandatory reading for any AI agent (Antigravity, Claude, GPT, Copilot, etc.)
tasked with modifying, extending, or operating this repository. All changes must adhere
to the principles below.

---

## 1. Encrypted Communication — Non-Negotiable

- **Always use TLS** for inter-service communication in staging and production.
  - Elasticsearch: Set `xpack.security.http.ssl.enabled: true` with valid certs.
  - Kibana → Elasticsearch: Use HTTPS, never plain HTTP outside of local dev.
  - Logstash → Elasticsearch: Use TLS output plugin with certificate verification.
- The current `xpack.security.enabled=false` setting is **local development only**.
  Document any exception clearly with a `# LOCAL DEV ONLY` comment.
- Do **not** introduce new services that communicate over unencrypted channels.

## 2. Minimal Privilege — Least Authority Principle

- **No `--privileged` flag** in Docker Compose unless the specific capability requires
  it (e.g., `NET_RAW` for packet capture). If you add privileged mode, document why.
- Use specific `cap_add` capabilities instead of `--privileged`:
  - Acceptable: `NET_ADMIN`, `NET_RAW` (Zeek only)
  - Not acceptable: `SYS_ADMIN`, `ALL`
- Containers must run as **non-root users** wherever possible. Example:
  ```dockerfile
  RUN useradd -m -u 1001 appuser
  USER appuser
  ```
- Agents must **not** remove `USER` directives from Dockerfiles without explicit approval.

## 3. Read-Only Filesystems

- Mount configuration directories as **read-only** (`:ro`) unless a service explicitly
  requires write access. This prevents container breakout via config tampering.
- Shared volumes (e.g., `zeek-logs`) should be mounted `:ro` for consumers (Logstash).

## 4. Secret Management

- **No hardcoded credentials** in any file. Use Docker secrets or environment variables
  sourced from a `.env` file (which must be in `.gitignore`).
- Never log credentials, API keys, or tokens — even in debug output.
- Logstash `cleartext_auth_attempt` tags are for detection only; the payload should be
  hashed before long-term storage.

## 5. Network Exposure

- Only expose ports that are necessary. The current exposed ports are:
  - `9200` (Elasticsearch) — **bind to 127.0.0.1 in production** (`127.0.0.1:9200:9200`)
  - `5601` (Kibana) — expose through a reverse proxy (Nginx/Caddy) with authentication
- Do **not** expose Logstash ports (5044) to the host unless required.

## 6. Image Hygiene

- Pin image versions (e.g., `elasticsearch:8.13.4`, not `:latest`) for reproducibility
  and security auditability.
- Run `docker scan` or `trivy image` on all custom-built images before pushing to a registry.
- Minimize image layers; combine `RUN` statements and clean up package manager caches.

## 7. Log Security

- Zeek logs may contain PII (IP addresses, HTTP payloads). Handle with care:
  - Do not store raw logs longer than required by your data retention policy.
  - Set ILM (Index Lifecycle Management) policies in Elasticsearch to auto-delete old indices.
- Kibana access must be authenticated in non-local environments.

## 8. Change Review

- Any agent changing Docker Compose service definitions (especially `cap_add`, `volumes`,
  `network_mode`, or environment secrets) **must** note the change in the PR description
  with a security impact assessment.
- Changes to Logstash pipeline filters that affect which fields are indexed must be reviewed
  to ensure no credential or PII fields are being indexed in plaintext.

---

*This guide aligns with NIST SP 800-190 (Container Security), CIS Docker Benchmark v1.6,
and the principle of least privilege from NIST SP 800-53 AC-6.*
