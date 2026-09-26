#!/bin/sh
# ==============================================================================
# sync-freeradius-crl.sh
# ------------------------------------------------------------------------------
# Synchronizes the Certificate Revocation List (CRL) from the Spoutin PKI portal
# into OPNsense FreeRADIUS with zero unnecessary disk writes and zero redundant
# service reloads.
#
# How it works:
#   1. Sends an HTTP conditional request using curl with ETag / If-None-Match.
#   2. If the CRL is unchanged, the server returns HTTP 304 Not Modified.
#      curl skips opening/creating any output file, and the script exits 0.
#   3. If a certificate was revoked, the server returns HTTP 200 OK.
#      curl writes the new CRL to RAM (/tmp), the script updates FreeRADIUS's
#      CA bundle (/usr/local/etc/raddb/certs/ca_opn.pem), and gracefully reloads
#      radiusd.
#
# Requirements on OPNsense:
#   - In Services -> FreeRADIUS -> EAP:
#       * "Enable Client Certificate" is checked.
#       * A CRL is selected in the "Certificate Revocation List" dropdown.
#         (Import initial CRL into System -> Trust -> Revocation first).
#
# Recommended Cron Schedule:
#   Run every 5 to 15 minutes via cron or OPNsense Monit / Cron GUI.
# ==============================================================================

set -e

CRL_URL="${CRL_URL:-https://wifi.int.spoutin.org/crl.pem}"
ETAG_FILE="${ETAG_FILE:-/tmp/step-ca.crl.etag}"
TEMP_FILE="${TEMP_FILE:-/tmp/step-ca.crl.incoming}"
INSTALLED_CRL="${INSTALLED_CRL:-/usr/local/etc/raddb/certs/step-ca.crl}"
CA_OPN="${CA_OPN:-/usr/local/etc/raddb/certs/ca_opn.pem}"
CA_BASE="${CA_BASE:-/usr/local/etc/raddb/certs/ca_base.pem}"

# Fetch with ETag tracking (in-memory in /tmp)
HTTP_CODE=$(curl -s -w "%{http_code}" \
    --etag-compare "$ETAG_FILE" \
    --etag-save "$ETAG_FILE" \
    "$CRL_URL" \
    -o "$TEMP_FILE")

# HTTP 304 Not Modified: CRL is identical, nothing to do
if [ "$HTTP_CODE" = "304" ]; then
    rm -f "$TEMP_FILE"
    exit 0
fi

# HTTP 200 OK: New CRL available, install and reload FreeRADIUS
if [ "$HTTP_CODE" = "200" ]; then
    if [ ! -s "$TEMP_FILE" ]; then
        logger -t sync-freeradius-crl "Received empty CRL payload from $CRL_URL (HTTP 200); aborting."
        rm -f "$TEMP_FILE"
        exit 1
    fi

    # Create a base backup of the CA certificates without CRL on first run
    if [ ! -f "$CA_BASE" ] && [ -f "$CA_OPN" ]; then
        # Strip any existing CRL block to create a clean base CA file
        awk 'BEGIN{c=1} /BEGIN X509 CRL/{c=0} {if(c) print} /END X509 CRL/{c=1}' "$CA_OPN" > "$CA_BASE"
    fi

    # Update installed CRL file
    mv -f "$TEMP_FILE" "$INSTALLED_CRL"
    chmod 644 "$INSTALLED_CRL"

    # Re-assemble ca_opn.pem with clean base CA + new CRL
    if [ -f "$CA_BASE" ]; then
        cat "$CA_BASE" "$INSTALLED_CRL" > "$CA_OPN"
        chmod 600 "$CA_OPN"
    fi

    # Gracefully reload radiusd to refresh certificate store
    if service radiusd status >/dev/null 2>&1; then
        service radiusd reload
        logger -t sync-freeradius-crl "Successfully updated FreeRADIUS CRL from $CRL_URL and reloaded radiusd."
    else
        logger -t sync-freeradius-crl "Updated FreeRADIUS CRL, but radiusd is not currently running."
    fi

    exit 0
fi

# Error: cleanup and log failure
rm -f "$TEMP_FILE"
logger -t sync-freeradius-crl "Failed to synchronize CRL from $CRL_URL: HTTP $HTTP_CODE"
exit 1
