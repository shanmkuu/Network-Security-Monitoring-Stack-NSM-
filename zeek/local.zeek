# =============================================================================
# Zeek Local Site Configuration — NSM Stack
# Outputs all logs as JSON for Logstash ingestion
# Compatible with zeek/zeek:lts
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


# ── File analysis ────────────────────────────────────────────────────────────
@load base/files/hash


# ── Detection frameworks ─────────────────────────────────────────────────────
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/http/detect-sqli
@load policy/protocols/http/detect-webapps
@load policy/protocols/ssl/validate-certs





# ── JSON output (required for Logstash pipeline) ─────────────────────────────
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# ── Site configuration ───────────────────────────────────────────────────────
redef Site::local_nets = { 172.28.0.0/16, 10.0.0.0/8, 192.168.0.0/16 };



# ── HTTP credential logging (cleartext auth detection) ───────────────────────
redef HTTP::default_capture_password = T;

# ── Notice actions — log all to notice.log ───────────────────────────────────
hook Notice::policy(n: Notice::Info) {
    add n$actions[Notice::ACTION_LOG];
}
