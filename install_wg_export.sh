#!/bin/sh

echo "==========================================================="
echo "=         Deploying WireGuard Client Exporter...          ="
echo "==========================================================="

# Navigate to the web directory
cd /usr/local/www || exit 1

# ---------------------------------------------------------
# 1. CREATE THE MAIN EXPORT UTILITY
# ---------------------------------------------------------
echo "[1/3] Creating /usr/local/www/vpn_wg_export.php..."
cat << 'EOF' > vpn_wg_export.php
<?php
/*
 * vpn_wg_export.php
 * Custom pfSense page to export WireGuard peer configurations.
 * Includes dynamic OS-level Key Gen, QR coding, Client-Side Bulk ZIP Export, and Advanced Tunnel Settings.
 */

require_once("guiconfig.inc");

// --- HELPER FUNCTION FOR CONFIG COMPATIBILITY ---
function get_wg_config_array($type) {
    global $config;
    $data = [];
    $plural = $type . 's';

    if (isset($config['installedpackages']['wireguard'][$plural])) {
        $pkg_data = $config['installedpackages']['wireguard'][$plural];
        if (isset($pkg_data['item'])) {
            $data = $pkg_data['item'];
        } else {
            $data = $pkg_data;
        }
    }
    elseif (function_exists('config_get_path') && config_get_path("wireguard/{$type}") !== null) {
        $data = config_get_path("wireguard/{$type}", []);
    } 
    elseif (isset($config['wireguard'][$type])) {
        $data = $config['wireguard'][$type];
    }

    if (!is_array($data)) { $data = []; }
    if (!empty($data) && !isset($data[0])) { $data = [$data]; }

    return $data;
}

// 1. HANDLE AJAX REQUESTS (Key Generation & Config Fetching)
if (isset($_GET['action'])) {
    
    // ACTION: Generate new WireGuard Keypair using the OS CLI
    if ($_GET['action'] === "gen_keys") {
        header('Content-Type: application/json');
        
        $wg_bin = '';
        $possible_paths = ['/sbin/wg', '/usr/bin/wg', '/usr/local/bin/wg'];
        foreach ($possible_paths as $path) {
            if (file_exists($path)) {
                $wg_bin = $path;
                break;
            }
        }
        
        if (empty($wg_bin)) {
            echo json_encode(['error' => 'Critical: Could not locate the "wg" executable on this firewall.']);
            exit;
        }

        $priv = trim(shell_exec("{$wg_bin} genkey 2>/dev/null"));
        if (!empty($priv)) {
            $pub = trim(shell_exec("echo " . escapeshellarg($priv) . " | {$wg_bin} pubkey 2>/dev/null"));
            if (!empty($pub)) {
                echo json_encode(['priv' => $priv, 'pub' => $pub]);
                exit;
            } else {
                echo json_encode(['error' => 'Generated private key, but failed to derive public key.']);
                exit;
            }
        } else {
            echo json_encode(['error' => "Failed to execute {$wg_bin} genkey"]);
            exit;
        }
    }
    
    // ACTION: Fetch raw template text for a SINGLE peer
    if ($_GET['action'] === "get_conf_text" && isset($_GET['peer_idx'])) {
        $peer_idx = htmlspecialchars($_GET['peer_idx']);
        $a_tunnels = get_wg_config_array('tunnel');
        $a_peers = get_wg_config_array('peer');
        
        if (isset($a_peers[$peer_idx])) {
            $peer = $a_peers[$peer_idx];
            $tun_name = $peer['tun'] ?? '';
            
            $server_tun = null;
            if (is_array($a_tunnels)) {
                foreach ($a_tunnels as $tun) {
                    if (isset($tun['name']) && $tun['name'] === $tun_name) {
                        $server_tun = $tun;
                        break;
                    }
                }
            }
            
            if ($server_tun) {
                $conf = "[Interface]\n";
                if (!empty($peer['privatekey'])) {
                    $conf .= "PrivateKey = " . $peer['privatekey'] . "\n";
                } else {
                    $conf .= "PrivateKey = __PRIVATE_KEY_PLACEHOLDER__\n";
                }
                
                $client_ips_arr = [];
                if (isset($peer['allowedips']['row'])) {
                    $rows = $peer['allowedips']['row'];
                    if (isset($rows['address'])) { $rows = array($rows); }
                    foreach ($rows as $row) {
                        if (isset($row['address']) && !empty($row['address'])) {
                            $mask = !empty($row['mask']) ? '/' . $row['mask'] : '/32';
                            $client_ips_arr[] = $row['address'] . $mask;
                        }
                    }
                }
                if (empty($client_ips_arr)) {
                    $client_ips_arr[] = "10.x.x.x/32 # ERROR: ASSIGN AN IP IN PFSENSE PEER SETTINGS";
                }
                $conf .= "Address = " . implode(', ', $client_ips_arr) . "\n";
                
                $conf .= "\n[Peer]\n";
                $conf .= "PublicKey = " . ($server_tun['publickey'] ?? '') . "\n";
                if (!empty($peer['presharedkey'])) {
                    $conf .= "PresharedKey = " . $peer['presharedkey'] . "\n";
                }
                
                $endpoint_ip = get_interface_ip("wan"); 
                $endpoint_port = !empty($server_tun['listenport']) ? $server_tun['listenport'] : "51820";
                
                // Placeholders for live editing in JS
                $conf .= "Endpoint = __ENDPOINT_PLACEHOLDER__\n";
                $conf .= "AllowedIPs = __ALLOWED_IPS_PLACEHOLDER__\n";
                $conf .= "__KEEPALIVE_PLACEHOLDER__\n";

                header("Content-Type: application/json");
                echo json_encode([
                    'template' => $conf,
                    'endpoint' => $endpoint_ip . ":" . $endpoint_port
                ]);
                exit;
            }
        }
    }

    // ACTION: Fetch ALL configurations for the Bulk Exporter
    if ($_GET['action'] === "get_all_configs") {
        $a_tunnels = get_wg_config_array('tunnel');
        $a_peers = get_wg_config_array('peer');
        $export_data = [];

        foreach ($a_peers as $idx => $peer) {
            $tun_name = $peer['tun'] ?? '';
            $server_tun = null;
            
            if (is_array($a_tunnels)) {
                foreach ($a_tunnels as $tun) {
                    if (isset($tun['name']) && $tun['name'] === $tun_name) {
                        $server_tun = $tun;
                        break;
                    }
                }
            }

            if ($server_tun) {
                $desc = $peer['descr'] ?? "wg_client_" . $idx;
                $filename = preg_replace('/[^a-zA-Z0-9_-]/', '_', $desc) . ".conf";

                $conf = "[Interface]\n";
                if (!empty($peer['privatekey'])) {
                    $conf .= "PrivateKey = " . $peer['privatekey'] . "\n";
                } else {
                    $conf .= "# PrivateKey = <INSERT_CLIENT_PRIVATE_KEY_HERE>\n";
                }
                
                $client_ips_arr = [];
                if (isset($peer['allowedips']['row'])) {
                    $rows = $peer['allowedips']['row'];
                    if (isset($rows['address'])) { $rows = array($rows); }
                    foreach ($rows as $row) {
                        if (isset($row['address']) && !empty($row['address'])) {
                            $mask = !empty($row['mask']) ? '/' . $row['mask'] : '/32';
                            $client_ips_arr[] = $row['address'] . $mask;
                        }
                    }
                }
                if (empty($client_ips_arr)) {
                    $client_ips_arr[] = "10.x.x.x/32";
                }
                $conf .= "Address = " . implode(', ', $client_ips_arr) . "\n";
                
                $conf .= "\n[Peer]\n";
                $conf .= "PublicKey = " . ($server_tun['publickey'] ?? '') . "\n";
                if (!empty($peer['presharedkey'])) {
                    $conf .= "PresharedKey = " . $peer['presharedkey'] . "\n";
                }
                
                $endpoint_ip = get_interface_ip("wan"); 
                $endpoint_port = !empty($server_tun['listenport']) ? $server_tun['listenport'] : "51820";
                $conf .= "Endpoint = " . $endpoint_ip . ":" . $endpoint_port . "\n";
                $conf .= "AllowedIPs = 0.0.0.0/0, ::/0\n";
                $conf .= "PersistentKeepalive = 25\n";

                $export_data[] = [
                    'filename' => $filename,
                    'content' => $conf
                ];
            }
        }
        
        header('Content-Type: application/json');
        echo json_encode($export_data);
        exit;
    }
}

// 2. RENDER THE GUI PAGE
$pgtitle = array(gettext("VPN"), gettext("WireGuard"), gettext("Client Export"));
include("head.inc");

$a_tunnels = get_wg_config_array('tunnel');
$a_peers = get_wg_config_array('peer');

?>

<div class="panel panel-default">
    <div class="panel-heading">
        <h2 class="panel-title"><?=gettext("WireGuard Client Configuration Exporter");?></h2>
    </div>
    <div class="panel-body">
        <div class="table-responsive">
            <table class="table table-striped table-hover table-condensed">
                <thead>
                    <tr>
                        <th>Description (User/Device)</th>
                        <th>Assigned Tunnel</th>
                        <th>Assigned Allowed IPs</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($a_peers)): ?>
                        <tr>
                            <td colspan="4" class="text-center">No WireGuard peers configured. Please set up a peer in VPN > WireGuard first.</td>
                        </tr>
                    <?php else: ?>
                        <?php foreach ($a_peers as $idx => $peer): 
                            $display_desc = $peer['descr'] ?? "Peer {$idx}";
                            $display_tun = $peer['tun'] ?? "Unknown";
                            
                            $client_ips_arr = [];
                            if (isset($peer['allowedips']['row'])) {
                                $rows = $peer['allowedips']['row'];
                                if (isset($rows['address'])) { $rows = array($rows); }
                                foreach ($rows as $row) {
                                    if (isset($row['address'])) {
                                        $mask = isset($row['mask']) ? '/' . $row['mask'] : '';
                                        $client_ips_arr[] = htmlspecialchars($row['address'] . $mask);
                                    }
                                }
                            }
                            $client_ips_display = implode(', ', $client_ips_arr);
                        ?>
                        <tr>
                            <td><strong><?=htmlspecialchars($display_desc);?></strong></td>
                            <td><?=htmlspecialchars($display_tun);?></td>
                            <td><?=$client_ips_display;?></td>
                            <td>
                                <button type="button" class="btn btn-sm btn-success" onclick="openExportModal(<?=$idx;?>, '<?=addslashes($display_desc);?>')">
                                    <i class="fa fa-cogs icon-embed-btn"></i> Export Config
                                </button>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
    <?php if (!empty($a_peers)): ?>
    <div class="panel-footer text-right">
        <button type="button" class="btn btn-info" id="bulkExportBtn" onclick="downloadAllConfigs()">
            <i class="fa fa-archive icon-embed-btn"></i> &nbsp;Download All Configs
        </button>
    </div>
    <?php endif; ?>
</div>

<div class="modal fade" id="exportModal" tabindex="-1" role="dialog">
  <div class="modal-dialog modal-lg" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
        <h4 class="modal-title" id="exportModalLabel">Exporting...</h4>
      </div>
      <div class="modal-body">
        
        <div class="form-group">
            <label for="clientPrivKey">Client Private Key</label>
            <div class="input-group">
                <input type="text" id="clientPrivKey" class="form-control" placeholder="Paste existing private key here...">
                <span class="input-group-btn">
                    <button class="btn btn-warning" type="button" onclick="generateNewKeys()" id="genKeyBtn">
                        <i class="fa fa-refresh icon-embed-btn"></i> Generate New Keypair
                    </button>
                </span>
            </div>
            <small class="text-muted">Paste your device's private key to build the config, or generate a new one.</small>
        </div>

        <div id="newKeyAlert" class="alert alert-danger" style="display:none; text-align:center;">
            <strong>Action Required:</strong> You generated a new keypair. For this tunnel to work, you MUST edit this Peer in pfSense and paste this Public Key into the Peer settings:<br><br>
            <code id="newPubKey" style="user-select: all; font-size: 130%; cursor: text;"></code>
        </div>
        
        <div class="panel panel-default">
            <div class="panel-heading"><h3 class="panel-title">Advanced Settings</h3></div>
            <div class="panel-body">
                <div class="row">
                    <div class="col-sm-4">
                        <label>Endpoint IP:Port</label>
                        <input type="text" id="clientEndpoint" class="form-control" placeholder="WAN_IP:51820">
                    </div>
                    <div class="col-sm-5">
                        <label>Allowed IPs (Split Tunnel)</label>
                        <input type="text" id="clientAllowedIPs" class="form-control" placeholder="0.0.0.0/0, ::/0">
                    </div>
                    <div class="col-sm-3">
                        <label>Keepalive</label>
                        <input type="number" id="clientKeepalive" class="form-control" placeholder="25">
                    </div>
                </div>
            </div>
        </div>
        <hr>

        <div class="row">
            <div class="col-sm-5 text-center">
                <p><strong>Mobile QR Code</strong></p>
                <div id="qrcode_canvas" style="display:inline-block; padding:15px; background: white; border: 1px solid #ccc; border-radius: 5px;">
                    </div>
            </div>
            <div class="col-sm-7">
                <p><strong>Raw Configuration</strong></p>
                <textarea id="confText" class="form-control" rows="8" readonly></textarea>
                <br>
                <button type="button" class="btn btn-primary btn-block" onclick="downloadConfFile()">
                    <i class="fa fa-download icon-embed-btn"></i> Download .conf File
                </button>
            </div>
        </div>

      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>

<script>
let rawTemplateText = "";
let currentPeerName = "";

function openExportModal(peerIdx, peerName) {
    currentPeerName = peerName;
    $('#exportModalLabel').text('Exporting: ' + peerName);
    
    $('#clientPrivKey').val('');
    $('#newKeyAlert').hide();
    $('#confText').val('Loading configuration...');
    $('#qrcode_canvas').empty();
    
    $.getJSON('vpn_wg_export.php?action=get_conf_text&peer_idx=' + peerIdx, function(data) {
        if (data && data.template) {
            rawTemplateText = data.template;
            
            $('#clientEndpoint').val(data.endpoint);
            $('#clientAllowedIPs').val('0.0.0.0/0, ::/0');
            $('#clientKeepalive').val('25');
            
            updateDisplays();
            $('#exportModal').modal('show');
        } else {
            alert("Error parsing configuration template.");
        }
    }).fail(function() {
        alert("Error fetching configuration from pfSense.");
    });
}

$('#clientPrivKey, #clientEndpoint, #clientAllowedIPs, #clientKeepalive').on('input', function() {
    updateDisplays();
});

function updateDisplays() {
    let privKey = $('#clientPrivKey').val().trim();
    let displayKey = privKey === "" ? "<PASTE_PRIVATE_KEY_HERE>" : privKey;
    
    let endpoint = $('#clientEndpoint').val().trim() || "<ENDPOINT_IP:PORT>";
    let allowedIPs = $('#clientAllowedIPs').val().trim() || "0.0.0.0/0";
    let keepalive = $('#clientKeepalive').val().trim();
    
    let finalConfig = rawTemplateText
        .replace('__PRIVATE_KEY_PLACEHOLDER__', displayKey)
        .replace('__ENDPOINT_PLACEHOLDER__', endpoint)
        .replace('__ALLOWED_IPS_PLACEHOLDER__', allowedIPs);
        
    if (keepalive !== "") {
        finalConfig = finalConfig.replace('__KEEPALIVE_PLACEHOLDER__', "PersistentKeepalive = " + keepalive);
    } else {
        finalConfig = finalConfig.replace('__KEEPALIVE_PLACEHOLDER__\n', ""); 
    }
        
    $('#confText').val(finalConfig.trim());
    
    $('#qrcode_canvas').empty();
    if (privKey !== "") {
        try {
            new QRCode(document.getElementById("qrcode_canvas"), {
                text: finalConfig.trim(), width: 180, height: 180,
                colorDark : "#000000", colorLight : "#ffffff", correctLevel : QRCode.CorrectLevel.M
            });
        } catch(e) {
             console.error("QR Error", e);
        }
    } else {
        $('#qrcode_canvas').html('<br><span class="text-muted">Enter Private Key<br>to generate QR</span>');
    }
}

function generateNewKeys() {
    $('#genKeyBtn').prop('disabled', true).html('<i class="fa fa-spinner fa-spin icon-embed-btn"></i> Generating...');
    
    $.getJSON('vpn_wg_export.php?action=gen_keys', function(data) {
        if(data && data.priv && data.pub) {
            $('#clientPrivKey').val(data.priv);
            $('#newPubKey').text(data.pub);
            $('#newKeyAlert').fadeIn();
            updateDisplays();
        } else if (data && data.error) {
            alert("Execution Error: " + data.error);
        } else {
            alert("Failed to generate keys.");
        }
        $('#genKeyBtn').prop('disabled', false).html('<i class="fa fa-refresh icon-embed-btn"></i> Generate New Keypair');
    }).fail(function(jqXHR, textStatus, errorThrown) {
        alert("HTTP Error " + jqXHR.status + " - " + errorThrown);
        $('#genKeyBtn').prop('disabled', false).html('<i class="fa fa-refresh icon-embed-btn"></i> Generate New Keypair');
    });
}

function downloadConfFile() {
    let textToSave = $('#confText').val();
    let blob = new Blob([textToSave], { type: 'text/plain' });
    let a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = currentPeerName.replace(/[^a-zA-Z0-9_-]/g, '_') + '.conf';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

function downloadAllConfigs() {
    let btn = $('#bulkExportBtn');
    btn.prop('disabled', true);

    $.getJSON('vpn_wg_export.php?action=get_all_configs', function(data) {
        if (!data || data.length === 0) {
            alert("No peers found to export.");
            btn.prop('disabled', false);
            return;
        }

        let zip = new JSZip();
        
        data.forEach(function(peer) {
            zip.file(peer.filename, peer.content);
        });

        zip.generateAsync({type:"blob"}).then(function(content) {
            let a = document.createElement("a");
            a.href = URL.createObjectURL(content);
            a.download = "pfSense_WireGuard_Clients.zip";
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            
            btn.prop('disabled', false);
        });

    }).fail(function() {
        alert("Server Error: Could not fetch bulk configurations.");
        btn.prop('disabled', false);
    });
}
</script>

<?php include("foot.inc"); ?>
EOF

chmod 644 vpn_wg_export.php

# ---------------------------------------------------------
# 2. CREATE THE DASHBOARD WIDGET
# ---------------------------------------------------------
echo "[2/3] Creating Widget at /usr/local/www/widgets/widgets/wg_client_export.widget.php..."
mkdir -p /usr/local/www/widgets/widgets/
cat << 'EOF' > /usr/local/www/widgets/widgets/wg_client_export.widget.php
<?php
/*
 * wg_client_export.widget.php
 * Custom dashboard widget for the WireGuard Export tool.
 */
require_once("guiconfig.inc");
?>

<div class="content">
    <table class="table table-striped table-hover">
        <tbody>
            <tr>
                <td class="text-center">
                    <br>
                    <a href="/vpn_wg_export.php" class="btn btn-lg btn-success">
                        <i class="fa fa-qrcode icon-embed-btn"></i> Open WireGuard Exporter
                    </a>
                    <br><br>
                </td>
            </tr>
        </tbody>
    </table>
</div>
EOF

chmod 644 /usr/local/www/widgets/widgets/wg_client_export.widget.php

# ---------------------------------------------------------
# 3. REGISTER IN THE pfSense XML DATABASE
# ---------------------------------------------------------
echo "[3/3] Registering menu link in pfSense configuration..."

cat << 'EOF' > /tmp/wg_menu_install.php
<?php
// USE CORE CONFIG FILES TO AVOID GUI AUTHENTICATION REDIRECTS
require_once("config.inc");
require_once("util.inc");
global $config;

// Ensure configuration arrays exist
if (!is_array($config['installedpackages'])) {
    $config['installedpackages'] = array();
}
if (!is_array($config['installedpackages']['menu'])) {
    $config['installedpackages']['menu'] = array();
}

// Check if menu already exists
$menu_exists = false;
foreach ($config['installedpackages']['menu'] as $menu) {
    if ($menu['name'] === 'WG Client Export') {
        $menu_exists = true;
        break;
    }
}

// Inject if missing
if (!$menu_exists) {
    $new_menu = array();
    $new_menu['name'] = 'WG Client Export';
    $new_menu['section'] = 'VPN';
    $new_menu['url'] = '/vpn_wg_export.php';
    $new_menu['tooltiptext'] = 'Export WireGuard configurations and QR codes';
    
    $config['installedpackages']['menu'][] = $new_menu;
    write_config("Installed WG Client Export utility to VPN menu");
    echo "  -> Successfully registered WG Client Export in the VPN menu.\n";
} else {
    echo "  -> Menu link is already registered in pfSense. Skipping.\n";
}
?>
EOF

# Execute the PHP injection securely using the firewall's internal engine
/usr/local/bin/php -f /tmp/wg_menu_install.php
rm /tmp/wg_menu_install.php

echo "=========================================================="
echo "=    Restarting the pfSense WebGUI to apply changes...   ="
echo "=========================================================="

/etc/rc.restart_webgui

echo "=========================================================="
echo "= Deployment Complete! You can now refresh your browser. ="
echo "=========================================================="
