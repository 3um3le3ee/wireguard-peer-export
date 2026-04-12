#!/bin/sh

echo "========================================================"
echo "=          WireGuard Peer Export uninstaller           ="
echo "========================================================"

# 1. Check for and remove the official FreeBSD package
echo "-> Checking for official pkg installation..."
if pkg info -e pfSense-pkg-wg-export; then
    echo "-> Package found. Uninstalling via pkg manager..."
    pkg delete -y pfSense-pkg-wg-export
else
    echo "-> Package not found. Proceeding to legacy cleanup..."
fi

# 2. Force remove the physical files (Catches legacy installs)
echo "-> Scrubbing physical application files..."
rm -f /usr/local/www/vpn_wg_export.php
rm -f /usr/local/www/widgets/widgets/wg_client_export.widget.php

# 3. Scrub the XML database safely using an inline PHP execution
echo "-> Cleaning up pfSense configuration database..."
/usr/local/bin/php << 'PHP_EOF'
<?php
require_once("config.inc");
require_once("util.inc");
global $config;

$modified = false;

// Remove the GUI Menu Link
if (isset($config["installedpackages"]["menu"]) && is_array($config["installedpackages"]["menu"])) {
    foreach ($config["installedpackages"]["menu"] as $k => $m) {
        if (isset($m["name"]) && $m["name"] === "WG Client Export") {
            unset($config["installedpackages"]["menu"][$k]);
            $modified = true;
            break;
        }
    }
}

// Remove the Package Manager Receipt (Just in case)
if (isset($config["installedpackages"]["package"]) && is_array($config["installedpackages"]["package"])) {
    foreach ($config["installedpackages"]["package"] as $k => $p) {
        if (isset($p["name"]) && ($p["name"] === "wg-export" || $p["name"] === "pfSense-pkg-wg-export")) {
            unset($config["installedpackages"]["package"][$k]);
            $modified = true;
            break;
        }
    }
}

if ($modified) {
    write_config("Universal Uninstall: Cleaned WG Client Export from database");
    echo "-> Database successfully scrubbed.\n";
} else {
    echo "-> Database is already clean.\n";
}
?>
PHP_EOF

# 4. Restart the WebGUI
echo "-> Restarting pfSense WebGUI..."
/etc/rc.restart_webgui

echo "========================================================"
echo "                  Removal Successful!                  ="
echo "========================================================"
