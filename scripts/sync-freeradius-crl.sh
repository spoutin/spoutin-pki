#!/bin/sh
# ==============================================================================
# sync-freeradius-crl.sh
# ------------------------------------------------------------------------------
# Synchronizes the Certificate Revocation List (CRL) from the Spoutin PKI portal
# into OPNsense FreeRADIUS with zero unnecessary disk writes and zero redundant
# service reloads.
#
# Self-Initialization:
#   On the very first run (or if FreeRADIUS CRL checking is not yet enabled),
#   this script automatically registers the CRL in OPNsense's Trust Store,
#   wires it into the FreeRADIUS EAP configuration, regenerates templates, and
#   restarts the daemon. No manual GUI imports or clicks required!
#
# Fast Path (Every 5-15 mins):
#   Uses HTTP ETag / 304 Not Modified in RAM (/tmp). If the CRL has not
#   changed, zero disk writes and zero service reloads occur.
# ==============================================================================

set -e

CRL_URL="${CRL_URL:-https://wifi.int.spoutin.org/crl.pem}"
ETAG_FILE="${ETAG_FILE:-/tmp/step-ca.crl.etag}"
TEMP_FILE="${TEMP_FILE:-/tmp/step-ca.crl.incoming}"
INSTALLED_CRL="${INSTALLED_CRL:-/usr/local/etc/raddb/certs/step-ca.crl}"
CA_OPN="${CA_OPN:-/usr/local/etc/raddb/certs/ca_opn.pem}"
CA_BASE="${CA_BASE:-/usr/local/etc/raddb/certs/ca_base.pem}"
EAP_CONF="/usr/local/etc/raddb/mods-enabled/eap"

# ------------------------------------------------------------------------------
# 1. AUTO-INITIALIZATION CHECK
# ------------------------------------------------------------------------------
# Verify if FreeRADIUS currently has "check_crl = yes" active in eap.conf
CRL_ACTIVE=""
if [ -f "$EAP_CONF" ]; then
    CRL_ACTIVE=$(grep -E '^[[:space:]]*check_crl[[:space:]]*=[[:space:]]*yes' "$EAP_CONF" 2>/dev/null || true)
fi

if [ -z "$CRL_ACTIVE" ]; then
    echo "Notice: FreeRADIUS CRL checking is not yet enabled. Running automated initialization..."
    logger -t sync-freeradius-crl "FreeRADIUS CRL checking not detected. Initializing OPNsense Trust Store and EAP config..."

    # Download initial CRL to /tmp
    INIT_CRL="/tmp/step-ca.crl.init"
    if ! curl -s -f "$CRL_URL" -o "$INIT_CRL"; then
        echo "Error: Failed to download initial CRL from $CRL_URL"
        logger -t sync-freeradius-crl "Failed to download initial CRL from $CRL_URL"
        exit 1
    fi

    # Run embedded PHP script to register CRL and ensure both Root & Intermediate CAs are enabled in OPNsense
    /usr/local/bin/php << 'EOF'
<?php
require_once('config.inc');
use OPNsense\Core\Config;

$configObj = Config::getInstance()->object();

// 1. Identify Root CA and Step-CA Intermediate CA in OPNsense
$caref = '';
$inter_ref = '';
$root_ref = '';

if (isset($configObj->ca)) {
    foreach ($configObj->ca as $ca) {
        $descr = (string)$ca->descr;
        $name = (string)$ca->name;
        if (stripos($descr, 'step-ca') !== false || stripos($descr, 'intermediate') !== false || stripos($name, 'intermediate') !== false) {
            $inter_ref = (string)$ca->refid;
        }
        if (stripos($descr, 'wifi') !== false || stripos($descr, 'main') !== false || stripos($name, 'root') !== false) {
            $root_ref = (string)$ca->refid;
        }
    }
}

// CRL was signed by Step-CA Intermediate CA; prefer intermediate, fall back to root or first CA
if (!empty($inter_ref)) {
    $caref = $inter_ref;
} elseif (!empty($root_ref)) {
    $caref = $root_ref;
} elseif (isset($configObj->ca)) {
    foreach ($configObj->ca as $ca) {
        $caref = (string)$ca->refid;
        break;
    }
}

if (empty($caref)) {
    fwrite(STDERR, "Error: No Certificate Authority found in OPNsense configuration.\n");
    exit(1);
}

// Ensure FreeRADIUS EAP has BOTH Root CA and Intermediate CA configured so it trusts the full chain
if (isset($configObj->OPNsense->freeradius->eap)) {
    $current_cas = explode(',', (string)$configObj->OPNsense->freeradius->eap->ca);
    if (!empty($root_ref) && !in_array($root_ref, $current_cas)) {
        $current_cas[] = $root_ref;
    }
    if (!empty($inter_ref) && !in_array($inter_ref, $current_cas)) {
        $current_cas[] = $inter_ref;
    }
    $configObj->OPNsense->freeradius->eap->ca = implode(',', array_unique(array_filter($current_cas)));
}

// 2. Read the initial CRL PEM
$crl_text = file_get_contents('/tmp/step-ca.crl.init');
if (empty($crl_text)) {
    fwrite(STDERR, "Error: Initial CRL file is empty.\n");
    exit(1);
}

// 3. Find or create the CRL entry in OPNsense Trust
$target_crl = null;
if (isset($configObj->crl)) {
    foreach ($configObj->crl as $crl) {
        if ((string)$crl->descr == 'Spoutin Wi-Fi CRL') {
            $target_crl = $crl;
            break;
        }
    }
}
if ($target_crl === null) {
    $target_crl = $configObj->addChild('crl');
    $target_crl->refid = uniqid();
}
$target_crl->caref = $caref;
$target_crl->descr = 'Spoutin Wi-Fi CRL';
$target_crl->crlmethod = 'existing';
$target_crl->text = base64_encode($crl_text);

// 4. Link FreeRADIUS EAP settings to the CRL
if (!isset($configObj->OPNsense->freeradius)) {
    fwrite(STDERR, "Error: FreeRADIUS plugin configuration not found.\n");
    exit(1);
}
$configObj->OPNsense->freeradius->eap->crl = (string)$target_crl->refid;
$configObj->OPNsense->freeradius->eap->enable_client_cert = '1';

// 5. Save changes
Config::getInstance()->save();
echo "Successfully registered Spoutin Wi-Fi CRL in OPNsense config.xml (caref: " . $caref . ", refid: " . $target_crl->refid . ")\n";
EOF

    # Regenerate FreeRADIUS templates and certificates
    if command -v configctl >/dev/null 2>&1; then
        configctl template reload OPNsense/Freeradius || true
    fi

    if [ -f "/usr/local/opnsense/scripts/Freeradius/generate_certs.php" ]; then
        /usr/local/opnsense/scripts/Freeradius/generate_certs.php || true
    fi

    # Restart FreeRADIUS daemon
    if command -v configctl >/dev/null 2>&1; then
        configctl freeradius restart || service radiusd restart || true
    else
        service radiusd restart || true
    fi

    # Save initial ETag so next run uses 304 Not Modified
    curl -s -I "$CRL_URL" | awk -F': ' '/[Ee][Tt][Aa][Gg]/ {gsub(/[\r\n"]/, "", $2); print "\"" $2 "\""}' > "$ETAG_FILE" 2>/dev/null || true
    rm -f "$INIT_CRL"

    echo "Auto-initialization complete! FreeRADIUS CRL checking is now active."
    logger -t sync-freeradius-crl "Auto-initialization complete. FreeRADIUS CRL validation is active."
    exit 0
fi

# ------------------------------------------------------------------------------
# 2. FAST PATH: CONDITIONAL ETAG REFRESH (Zero Flash Wear)
# ------------------------------------------------------------------------------
# Fetch with ETag tracking (in-memory in /tmp)
HTTP_CODE=$(curl -s -w "%{http_code}" \
    --etag-compare "$ETAG_FILE" \
    --etag-save "$ETAG_FILE" \
    "$CRL_URL" \
    -o "$TEMP_FILE")

# HTTP 304 Not Modified: CRL is identical, zero disk writes, nothing to do
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

    # Update installed CRL file
    mv -f "$TEMP_FILE" "$INSTALLED_CRL"
    chmod 644 "$INSTALLED_CRL"

    # Always ensure clean base CA certificates (Root + Intermediate) are refreshed from OPNsense templates
    if [ -f "/usr/local/opnsense/scripts/Freeradius/generate_certs.php" ]; then
        /usr/local/opnsense/scripts/Freeradius/generate_certs.php >/dev/null 2>&1 || true
    fi

    if [ -f "$CA_OPN" ]; then
        # Strip any existing CRL block to create a clean base CA file
        awk 'BEGIN{c=1} /BEGIN X509 CRL/{c=0} {if(c) print} /END X509 CRL/{c=1}' "$CA_OPN" > "$CA_BASE"
        # Re-assemble ca_opn.pem with clean base CA + new CRL
        cat "$CA_BASE" "$INSTALLED_CRL" > "$CA_OPN"
        chmod 600 "$CA_OPN"
    fi

    # Update OPNsense Trust Store config.xml so the Web GUI reflects the latest CRL
    if [ -f "/usr/local/bin/php" ]; then
        /usr/local/bin/php << 'PHP_UPDATE_CRL' >/dev/null 2>&1 || true
<?php
require_once('config.inc');
use OPNsense\Core\Config;
$crl_text = @file_get_contents('/usr/local/etc/raddb/certs/step-ca.crl');
if (!empty($crl_text)) {
    $configObj = Config::getInstance()->object();
    if (isset($configObj->crl)) {
        foreach ($configObj->crl as $crl) {
            if ((string)$crl->descr == 'Spoutin Wi-Fi CRL') {
                $crl->text = base64_encode($crl_text);
                Config::getInstance()->save();
                break;
            }
        }
    }
}
PHP_UPDATE_CRL
    fi

    # Restart radiusd to refresh certificate store and flush SSL session cache
    if service radiusd status >/dev/null 2>&1; then
        service radiusd restart
        logger -t sync-freeradius-crl "Successfully updated FreeRADIUS CRL from $CRL_URL and restarted radiusd."
    else
        logger -t sync-freeradius-crl "Updated FreeRADIUS CRL, but radiusd is not currently running."
    fi

    exit 0
fi

# Error: cleanup and log failure
rm -f "$TEMP_FILE"
logger -t sync-freeradius-crl "Failed to synchronize CRL from $CRL_URL: HTTP $HTTP_CODE"
exit 1
