#!/usr/bin/env bash
# =============================================================================
# import_dashboards.sh — NSM Stack
# Waits for Kibana to be healthy then imports all saved objects/dashboards.
# Run this after `docker-compose up -d`
# =============================================================================
set -euo pipefail

KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
DASHBOARD_FILE="${DASHBOARD_FILE:-$(dirname "$0")/../kibana/dashboards/nsm_dashboards.ndjson}"
MAX_WAIT=180  # seconds
INTERVAL=10

echo "════════════════════════════════════════════"
echo " NSM Dashboard Import Script"
echo " Kibana: ${KIBANA_URL}"
echo "════════════════════════════════════════════"

# ── Wait for Kibana to be ready ───────────────────────────────────────────────
echo "Waiting for Kibana to become available (max ${MAX_WAIT}s)…"
elapsed=0
until curl -sf "${KIBANA_URL}/api/status" | grep -q '"level":"available"' 2>/dev/null; do
    if [ "$elapsed" -ge "$MAX_WAIT" ]; then
        echo "ERROR: Kibana did not become ready within ${MAX_WAIT}s. Aborting."
        exit 1
    fi
    echo "  Kibana not ready yet (${elapsed}s elapsed). Retrying in ${INTERVAL}s…"
    sleep "$INTERVAL"
    elapsed=$((elapsed + INTERVAL))
done
echo "✔ Kibana is ready!"

# ── Create index pattern via API ──────────────────────────────────────────────
echo ""
echo "Setting up default index pattern: zeek-*"
curl -sf -X POST "${KIBANA_URL}/api/index_patterns/index_pattern" \
    -H "Content-Type: application/json" \
    -H "kbn-xsrf: true" \
    -d '{
        "index_pattern": {
            "id": "zeek-index-pattern",
            "title": "zeek-*",
            "timeFieldName": "@timestamp"
        },
        "override": true
    }' | python3 -m json.tool 2>/dev/null || echo "  (Index pattern may already exist)"

# Set as default index pattern
curl -sf -X POST "${KIBANA_URL}/api/kibana/settings" \
    -H "Content-Type: application/json" \
    -H "kbn-xsrf: true" \
    -d '{"changes":{"defaultIndex":"zeek-index-pattern"}}' > /dev/null
echo "✔ Default index pattern set to zeek-*"

# ── Import saved objects (dashboards, visualizations, searches) ───────────────
echo ""
echo "Importing dashboard NDJSON: ${DASHBOARD_FILE}"
IMPORT_RESPONSE=$(curl -sf -X POST \
    "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
    -H "kbn-xsrf: true" \
    --form "file=@${DASHBOARD_FILE}" 2>&1)

echo "$IMPORT_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$IMPORT_RESPONSE"

if echo "$IMPORT_RESPONSE" | grep -q '"success":true'; then
    echo ""
    echo "✔ Dashboards imported successfully!"
    echo ""
    echo "════════════════════════════════════════════"
    echo " Open Kibana: ${KIBANA_URL}"
    echo " → Dashboard: NSM Security Overview"
    echo " → Stack Mgmt: ${KIBANA_URL}/app/management/kibana/objects"
    echo "════════════════════════════════════════════"
else
    echo ""
    echo "⚠ Import response did not confirm success. Check the output above."
    echo "  You can manually import via: Kibana → Stack Management → Saved Objects → Import"
    echo "  File: ${DASHBOARD_FILE}"
fi
