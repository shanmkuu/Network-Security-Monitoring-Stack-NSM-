# =============================================================================
# Zeek Local Site Configuration — NSM Stack
# Outputs all logs as JSON for Logstash ingestion
# =============================================================================

# ── Core protocol analyzers ──────────────────────────────────────────────────
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ftp
@load base/protocols/http
@load base/protocols/smtp
@load base/protocols/ssh
@load base/protocols/ssl
@load base/protocols/rdp
@load base/protocols/smb

# ── File analysis ────────────────────────────────────────────────────────────
@load base/files/hash
@load base/files/extract

# ── Detection frameworks ─────────────────────────────────────────────────────
@load policy/frameworks/notice/weird-conn-state
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/dns/detect-MHR
@load policy/protocols/http/detect-sqli
@load policy/protocols/http/detect-webapps
@load policy/protocols/ssh/interesting-hostnames
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssl/log-hostcerts-only

# ── Port scan detection ──────────────────────────────────────────────────────
@load policy/misc/scan

# ── Weird activity notices ───────────────────────────────────────────────────
@load misc/weird-stats

# ── JSON output (required for Logstash pipeline) ─────────────────────────────
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# ── Site configuration ───────────────────────────────────────────────────────
redef Site::local_nets = { 172.28.0.0/16, 10.0.0.0/8, 192.168.0.0/16 };

# ── Port scan thresholds (lower for demo visibility) ─────────────────────────
redef Scan::addr_scan_threshold   = 10.0;
redef Scan::port_scan_threshold   = 10.0;

# ── HTTP credential logging (cleartext auth detection) ───────────────────────
redef HTTP::default_capture_password = T;

# ── Notice actions — log all to notice.log ───────────────────────────────────
hook Notice::policy(n: Notice::Info) {
    add n$actions[Notice::ACTION_LOG];
}
