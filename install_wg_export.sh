#!/bin/sh

echo "Deploying WG Peer Export (v3.3 with Auto-Provisioning)..."

# Navigate to the web directory
cd /usr/local/www || exit 1

# ---------------------------------------------------------
# 1. CREATE THE MAIN EXPORTER PAGE
# ---------------------------------------------------------
echo "Building /usr/local/www/vpn_wg_export.php..."
cat << 'EOF' > /usr/local/www/vpn_wg_export.php
<?php
/*
 * vpn_wg_export.php
 * Ultimate pfSense WG Peer Export (v3.3)
 * Features: Native OS Crypto, Auto-Assignment, Zip/Tar Fallbacks, Split Tunnels, Live Status, Dark Mode, Widget Integration.
 */

require_once("guiconfig.inc");

// 1. SECURITY LOCKDOWN: Enforce Admin Privilege
if (session_status() == PHP_SESSION_NONE) { session_start(); }
$user_groups = (isset($_SESSION['Groups']) && is_array($_SESSION['Groups'])) ? $_SESSION['Groups'] : [];
if ((!isset($_SESSION['Username']) || $_SESSION['Username'] !== 'admin') && !in_array('admins', $user_groups)) {
    require_once("head.inc");
    print_info_box("Access Denied: You must be an administrator to use this tool.", "danger");
    include("foot.inc");
    exit;
}

// --- GLOBAL OS BINARY FINDER ---
$wg_bin = '';
foreach (['/sbin/wg', '/usr/bin/wg', '/usr/local/bin/wg'] as $path) {
    if (file_exists($path)) { $wg_bin = $path; break; }
}

// --- HELPER FUNCTION FOR CONFIG COMPATIBILITY ---
function get_wg_config_array($type) {
    global $config;
    $data = [];
    $plural = $type . 's';

    if (isset($config['installedpackages']['wireguard'][$plural])) {
        $pkg_data = $config['installedpackages']['wireguard'][$plural];
        $data = isset($pkg_data['item']) ? $pkg_data['item'] : $pkg_data;
    } elseif (function_exists('config_get_path') && config_get_path("wireguard/{$type}") !== null) {
        $data = config_get_path("wireguard/{$type}", []);
    } elseif (isset($config['wireguard'][$type])) {
        $data = $config['wireguard'][$type];
    }

    if (!is_array($data)) { $data = []; }
    if (!empty($data) && !isset($data[0])) { $data = [$data]; }
    return $data;
}

// --- HELPER: BUILD RAW CONFIG STRING ---
function build_wg_conf($peer, $server_tun) {
    $conf = "[Interface]\n";
    $conf .= "PrivateKey = __PRIVATE_KEY_PLACEHOLDER__\n";
    
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
    if (empty($client_ips_arr)) { $client_ips_arr[] = "10.x.x.x/32 # ERROR: ASSIGN AN IP IN PFSENSE PEER SETTINGS"; }
    $conf .= "Address = " . implode(', ', $client_ips_arr) . "\n";
    
    $conf .= "\n[Peer]\n";
    $conf .= "PublicKey = " . ($server_tun['publickey'] ?? '') . "\n";
    $conf .= "__PSK_PLACEHOLDER__\n"; 
    
    $conf .= "Endpoint = __ENDPOINT_PLACEHOLDER__\n";
    $conf .= "AllowedIPs = __ALLOWEDIPS_PLACEHOLDER__\n";
    $conf .= "PersistentKeepalive = 25\n";
    
    return $conf;
}

// 2. HANDLE AJAX & DOWNLOAD REQUESTS
if (isset($_GET['action'])) {
    
    // BULK EXPORT (WITH OS FAILSAFE FOR MISSING ZIPARCHIVE)
    if ($_GET['action'] === "bulk_export") {
        $a_tunnels = get_wg_config_array('tunnel');
        $a_peers = get_wg_config_array('peer');
        
        // Stage files in a temporary directory
        $tmp_dir = sys_get_temp_dir() . '/wg_export_' . uniqid();
        mkdir($tmp_dir);
        
        foreach ($a_peers as $idx => $peer) {
            $tun_name = $peer['tun'] ?? '';
            $server_tun = null;
            foreach ($a_tunnels as $tun) { if (isset($tun['name']) && $tun['name'] === $tun_name) { $server_tun = $tun; break; } }
            
            if ($server_tun) {
                $raw_conf = build_wg_conf($peer, $server_tun);
                $priv = !empty($peer['privatekey']) ? $peer['privatekey'] : "<INSERT_PRIVATE_KEY_HERE>";
                
                $raw_conf = str_replace('__PRIVATE_KEY_PLACEHOLDER__', $priv, $raw_conf);
                $raw_conf = str_replace('__ALLOWEDIPS_PLACEHOLDER__', '0.0.0.0/0, ::/0', $raw_conf);
                
                if (!empty($peer['presharedkey'])) {
                    $raw_conf = str_replace('__PSK_PLACEHOLDER__', "PresharedKey = " . $peer['presharedkey'], $raw_conf);
                } else {
                    $raw_conf = str_replace("__PSK_PLACEHOLDER__\n", "", $raw_conf);
                }
                
                $ep_ip = get_interface_ip("wan");
                $ep_port = !empty($server_tun['listenport']) ? $server_tun['listenport'] : "51820";
                $raw_conf = str_replace('__ENDPOINT_PLACEHOLDER__', "{$ep_ip}:{$ep_port}", $raw_conf);
                
                $desc = preg_replace('/[^a-zA-Z0-9_-]/', '_', ($peer['descr'] ?? "peer"));
                file_put_contents("{$tmp_dir}/{$desc}_{$idx}.conf", $raw_conf);
            }
        }
        
        // Build the archive (Try PHP Zip first, fallback to OS Tar)
        if (class_exists('ZipArchive')) {
            $zip = new ZipArchive();
            $tmp_file = tempnam(sys_get_temp_dir(), 'wgzip') . '.zip';
            if ($zip->open($tmp_file, ZipArchive::CREATE) === TRUE) {
                $files = glob("{$tmp_dir}/*.conf");
                foreach ($files as $file) { $zip->addFile($file, basename($file)); }
                $zip->close();
            }
            $dl_name = 'wireguard_all_peers.zip';
            $dl_type = 'application/zip';
        } else {
            $tmp_file = tempnam(sys_get_temp_dir(), 'wgtgz') . '.tar.gz';
            shell_exec("tar -czf " . escapeshellarg($tmp_file) . " -C " . escapeshellarg($tmp_dir) . " .");
            $dl_name = 'wireguard_all_peers.tar.gz';
            $dl_type = 'application/gzip';
        }

        // Serve the file
        header('Content-Type: ' . $dl_type);
        header('Content-disposition: attachment; filename=' . $dl_name);
        header('Content-Length: ' . filesize($tmp_file));
        readfile($tmp_file);
        
        // Cleanup temp files
        unlink($tmp_file);
        $files = glob("{$tmp_dir}/*.conf");
        foreach ($files as $file) { unlink($file); }
        rmdir($tmp_dir);
        exit;
    }

    // ACTION: Generate new WireGuard Keypair and PSK, and Auto-Assign to Peer
    if ($_GET['action'] === "gen_keys" && isset($_GET['peer_idx'])) {
        header('Content-Type: application/json');
        $peer_idx = htmlspecialchars($_GET['peer_idx']);
        
        if (empty($wg_bin)) { echo json_encode(['error' => 'Could not locate wg executable.']); exit; }

        $priv = trim(shell_exec("{$wg_bin} genkey 2>/dev/null"));
        if (!empty($priv)) {
            $pub = trim(shell_exec("echo " . escapeshellarg($priv) . " | {$wg_bin} pubkey 2>/dev/null"));
            $psk = trim(shell_exec("{$wg_bin} genpsk 2>/dev/null"));
            
            $applied = false;
            global $config;

            // Auto-assign to the specific peer and save configuration
            if (isset($config['installedpackages']['wireguard']['peers']['item'][$peer_idx])) {
                $config['installedpackages']['wireguard']['peers']['item'][$peer_idx]['publickey'] = $pub;
                if (!empty($psk)) {
                    $config['installedpackages']['wireguard']['peers']['item'][$peer_idx]['presharedkey'] = $psk;
                }
                
                write_config("WireGuard Export Tool: Auto-assigned new Public Key and PSK to peer {$peer_idx}");
                
                // Resync WireGuard to apply the changes immediately
                if (file_exists("/usr/local/pkg/wireguard/wg.inc")) {
                    require_once("/usr/local/pkg/wireguard/wg.inc");
                    if (function_exists("wg_resync")) {
                        wg_resync();
                    }
                }
                $applied = true;
            }

            echo json_encode(['priv' => $priv, 'pub' => $pub, 'psk' => $psk, 'applied' => $applied]); 
            exit;
        } else {
            echo json_encode(['error' => "Command failed."]); exit;
        }
    }
    
    if ($_GET['action'] === "get_conf_data" && isset($_GET['peer_idx'])) {
        $peer_idx = htmlspecialchars($_GET['peer_idx']);
        $a_tunnels = get_wg_config_array('tunnel');
        $a_peers = get_wg_config_array('peer');
        
        if (isset($a_peers[$peer_idx])) {
            $peer = $a_peers[$peer_idx];
            $server_tun = null;
            foreach ($a_tunnels as $tun) { if (isset($tun['name']) && $tun['name'] === ($peer['tun'] ?? '')) { $server_tun = $tun; break; } }
            
            if ($server_tun) {
                $endpoint_ip = get_interface_ip("wan"); 
                $endpoint_port = !empty($server_tun['listenport']) ? $server_tun['listenport'] : "51820";
                
                header('Content-Type: application/json');
                echo json_encode([
                    'template' => build_wg_conf($peer, $server_tun),
                    'default_endpoint' => "{$endpoint_ip}:{$endpoint_port}",
                    'existing_psk' => $peer['presharedkey'] ?? ''
                ]);
                exit;
            }
        }
    }
}

// 3. FETCH LIVE TELEMETRY
$wg_handshakes = [];
if (!empty($wg_bin)) {
    $raw_hs = shell_exec("{$wg_bin} show all latest-handshakes 2>/dev/null");
    if ($raw_hs) {
        foreach (explode("\n", trim($raw_hs)) as $line) {
            $parts = preg_split('/\s+/', $line);
            if (count($parts) >= 3) { $wg_handshakes[trim($parts[1])] = (int)$parts[2]; }
        }
    }
}

// 4. RENDER THE GUI PAGE
$pgtitle = array(gettext("VPN"), gettext("WireGuard"), gettext("WG Peer Export"));
include("head.inc");

$a_peers = get_wg_config_array('peer');
?>

<style>
    @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.3; } 100% { opacity: 1; } }
    .status-pulse { animation: pulse 1.5s infinite; color: #5cb85c; }
</style>

<div class="panel panel-default">
    <div class="panel-heading">
        <h2 class="panel-title"><?=gettext("WG Peer Export");?></h2>
    </div>
    <div class="panel-body">
        
        <div class="row" style="margin-bottom: 15px;">
            <div class="col-sm-8">
                <div class="input-group">
                    <span class="input-group-addon"><i class="fa fa-search"></i></span>
                    <input type="text" id="searchPeers" class="form-control" placeholder="Search peers by name, tunnel, or IP...">
                </div>
            </div>
            <div class="col-sm-4 text-right">
                <a href="vpn_wg_export.php?action=bulk_export" class="btn btn-primary">
                    <i class="fa fa-archive icon-embed-btn"></i> Download All
                </a>
            </div>
        </div>

        <div class="table-responsive">
            <table class="table table-striped table-hover table-condensed" id="peersTable">
                <thead>
                    <tr>
                        <th>Status</th>
                        <th>Description</th>
                        <th>Tunnel</th>
                        <th>Assigned IPs</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($a_peers)): ?>
                        <tr><td colspan="5" class="text-center">No WireGuard peers configured.</td></tr>
                    <?php else: ?>
                        <?php foreach ($a_peers as $idx => $peer): 
                            $display_desc = $peer['descr'] ?? "Peer {$idx}";
                            $display_tun = $peer['tun'] ?? "Unknown";
                            $pubkey = $peer['publickey'] ?? '';
                            
                            $status_html = '<span class="text-muted"><i class="fa fa-circle-o"></i> Offline</span>';
                            if (!empty($pubkey) && isset($wg_handshakes[$pubkey]) && $wg_handshakes[$pubkey] > 0) {
                                $diff = time() - $wg_handshakes[$pubkey];
                                if ($diff < 180) { 
                                    $status_html = '<strong><i class="fa fa-circle status-pulse"></i> Online</strong>';
                                } else {
                                    $mins = round($diff / 60);
                                    if ($mins > 1440) {
                                        $status_html = '<span class="text-warning"><i class="fa fa-clock-o"></i> ' . round($mins/1440) . ' days ago</span>';
                                    } else {
                                        $status_html = '<span class="text-warning"><i class="fa fa-clock-o"></i> ' . $mins . ' mins ago</span>';
                                    }
                                }
                            }

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
                        ?>
                        <tr>
                            <td><?=$status_html;?></td>
                            <td><strong><?=htmlspecialchars($display_desc);?></strong></td>
                            <td><?=htmlspecialchars($display_tun);?></td>
                            <td><?=implode(', ', $client_ips_arr);?></td>
                            <td>
                                <button type="button" class="btn btn-sm btn-success" onclick="openExportModal(<?=$idx;?>, '<?=addslashes($display_desc);?>')">
                                    <i class="fa fa-qrcode icon-embed-btn"></i> Provision Device
                                </button>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>

<div class="modal fade" id="exportModal" tabindex="-1" role="dialog">
  <div class="modal-dialog modal-lg" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <button type="button" class="close" data-dismiss="modal" aria-label="Close"><span aria-hidden="true">&times;</span></button>
        <h4 class="modal-title" id="exportModalLabel">Exporting...</h4>
      </div>
      <div class="modal-body">
        
        <div class="row">
            <div class="col-sm-12">
                <div class="form-group">
                    <label>Client Private Key</label>
                    <div class="input-group">
                        <input type="text" id="clientPrivKey" class="form-control" placeholder="Paste existing private key here...">
                        <span class="input-group-btn">
                            <button class="btn btn-warning" type="button" onclick="generateNewKeys()" id="genKeyBtn">
                                <i class="fa fa-refresh"></i> Generate New Keys
                            </button>
                        </span>
                    </div>
                </div>
            </div>
        </div>

        <div id="newKeyAlert" class="alert" style="display:none; text-align:center;"></div>
        
        <div class="row">
            <div class="col-sm-4">
                <div class="form-group">
                    <label><i class="fa fa-globe"></i> Endpoint Override</label>
                    <input type="text" id="endpointOverride" class="form-control" placeholder="e.g., vpn.domain.com:51820">
                </div>
            </div>
            <div class="col-sm-4">
                <div class="form-group">
                    <label><i class="fa fa-lock"></i> Pre-Shared Key</label>
                    <input type="text" id="clientPsk" class="form-control" placeholder="Optional PSK...">
                </div>
            </div>
            <div class="col-sm-4">
                <div class="form-group">
                    <label><i class="fa fa-exchange"></i> Routing Mode</label>
                    <select id="tunnelMode" class="form-control">
                        <option value="full">Full Tunnel (All Internet)</option>
                        <option value="split">Split Tunnel (Local Only)</option>
                    </select>
                </div>
            </div>
        </div>
        <hr>

        <div class="row">
            <div class="col-sm-4 text-center">
                <p><strong>Mobile QR Code</strong></p>
                <div id="qrcode_canvas" style="display:inline-block; padding:15px; border-radius: 5px;"></div>
            </div>
            <div class="col-sm-8">
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

<script>
let rawTemplateText = "";
let defaultEndpoint = "";
let currentPeerName = "";
let currentPeerIdx = null;

$('#searchPeers').on('keyup', function() {
    let value = $(this).val().toLowerCase();
    $("#peersTable tbody tr").filter(function() {
        $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
});

function openExportModal(peerIdx, peerName) {
    currentPeerName = peerName;
    currentPeerIdx = peerIdx;
    $('#exportModalLabel').text('Provisioning: ' + peerName);
    
    $('#clientPrivKey, #endpointOverride, #clientPsk').val('');
    $('#tunnelMode').val('full');
    $('#newKeyAlert').hide().removeClass('alert-success alert-danger').empty();
    $('#confText').val('Loading configuration...');
    $('#qrcode_canvas').empty();
    
    $.getJSON('vpn_wg_export.php?action=get_conf_data&peer_idx=' + peerIdx, function(data) {
        rawTemplateText = data.template;
        defaultEndpoint = data.default_endpoint;
        $('#endpointOverride').attr('placeholder', 'Default: ' + defaultEndpoint);
        if(data.existing_psk) { $('#clientPsk').val(data.existing_psk); }
        updateDisplays();
        $('#exportModal').modal('show');
    }).fail(function() { alert("Error fetching configuration from pfSense."); });
}

$('#clientPrivKey, #endpointOverride, #clientPsk, #tunnelMode').on('input change', function() { updateDisplays(); });

function updateDisplays() {
    let privKey = $('#clientPrivKey').val().trim();
    let displayKey = privKey === "" ? "<PASTE_PRIVATE_KEY_HERE>" : privKey;
    let finalConfig = rawTemplateText.replace('__PRIVATE_KEY_PLACEHOLDER__', displayKey);
    
    let psk = $('#clientPsk').val().trim();
    if (psk !== "") { finalConfig = finalConfig.replace('__PSK_PLACEHOLDER__', "PresharedKey = " + psk); } 
    else { finalConfig = finalConfig.replace("__PSK_PLACEHOLDER__\n", ""); }
    
    let ep = $('#endpointOverride').val().trim() || defaultEndpoint;
    finalConfig = finalConfig.replace('__ENDPOINT_PLACEHOLDER__', ep);
    
    let isSplit = $('#tunnelMode').val() === 'split';
    let allowedIps = isSplit ? "10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16" : "0.0.0.0/0, ::/0";
    finalConfig = finalConfig.replace('__ALLOWEDIPS_PLACEHOLDER__', allowedIps);
    
    $('#confText').val(finalConfig);
    
    let bgColor = window.getComputedStyle(document.body).backgroundColor;
    let isDark = bgColor.match(/^rgb\((\d+),\s*(\d+),\s*(\d+)\)$/);
    let isPfDark = (isDark && isDark[1] < 100) || $('body').hasClass('pfSense-dark');
    
    let qrDarkColor = isPfDark ? "#ffffff" : "#000000";
    let qrLightColor = isPfDark ? "#212529" : "#ffffff";
    $('#qrcode_canvas').css('background', qrLightColor);
    
    $('#qrcode_canvas').empty();
    if (privKey !== "") {
        try {
            new QRCode(document.getElementById("qrcode_canvas"), {
                text: finalConfig, width: 220, height: 220,
                colorDark : qrDarkColor, colorLight : qrLightColor, correctLevel : QRCode.CorrectLevel.M
            });
        } catch(e) { console.error(e); }
    } else {
        $('#qrcode_canvas').html('<br><br><br><span class="text-muted">Enter Private Key<br>to generate QR</span><br><br>');
    }
}

function generateNewKeys() {
    $('#genKeyBtn').prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Generating...');
    $.getJSON('vpn_wg_export.php?action=gen_keys&peer_idx=' + currentPeerIdx, function(data) {
        if(data && data.priv && data.pub) {
            $('#clientPrivKey').val(data.priv);
            $('#clientPsk').val(data.psk || "");
            
            if (data.applied) {
                $('#newKeyAlert')
                    .removeClass('alert-danger')
                    .addClass('alert-success')
                    .html('<strong>Success!</strong> Keys generated and automatically assigned to this peer in pfSense.<br><br>Public Key: <code style="user-select: all; cursor: text;">' + data.pub + '</code><br>Pre-Shared Key: <code style="user-select: all; cursor: text;">' + (data.psk || "N/A") + '</code>')
                    .fadeIn();
            } else {
                $('#newKeyAlert')
                    .removeClass('alert-success')
                    .addClass('alert-danger')
                    .html('<strong>Action Required:</strong> Could not auto-assign keys. Paste these values into the Peer settings manually:<br><br>Public Key: <code style="user-select: all; cursor: text;">' + data.pub + '</code><br>Pre-Shared Key: <code style="user-select: all; cursor: text;">' + (data.psk || "N/A") + '</code>')
                    .fadeIn();
            }
            
            updateDisplays();
        } else { alert("Error: " + (data.error || "Unknown")); }
        $('#genKeyBtn').prop('disabled', false).html('<i class="fa fa-refresh"></i> Generate New Keys');
    }).fail(function() {
        alert("Server communication failed.");
        $('#genKeyBtn').prop('disabled', false).html('<i class="fa fa-refresh"></i> Generate New Keys');
    });
}

function downloadConfFile() {
    let blob = new Blob([$('#confText').val()], { type: 'text/plain' });
    let a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = currentPeerName.replace(/[^a-zA-Z0-9_-]/g, '_') + '.conf';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
}

// === WIDGET INTEGRATION: AUTO-OPEN MODAL ===
<?php if (isset($_GET['provision_idx']) && is_numeric($_GET['provision_idx']) && isset($a_peers[$_GET['provision_idx']])): ?>
$(document).ready(function() {
    let autoIdx = <?=intval($_GET['provision_idx']);?>;
    let autoName = "<?=addslashes($a_peers[$_GET['provision_idx']]['descr'] ?? 'Peer');?>";
    openExportModal(autoIdx, autoName);
});
<?php endif; ?>
</script>

<?php include("foot.inc"); ?>
EOF
chmod 644 /usr/local/www/vpn_wg_export.php

# ---------------------------------------------------------
# 2. CREATE THE SMART DASHBOARD WIDGET
# ---------------------------------------------------------
echo "Building /usr/local/www/widgets/widgets/wg_client_export.widget.php..."
mkdir -p /usr/local/www/widgets/widgets/
cat << 'EOF' > /usr/local/www/widgets/widgets/wg_client_export.widget.php
<?php
/*
 * wg_client_export.widget.php
 * Smart Dashboard Widget for WireGuard Provisioning
 */
require_once("guiconfig.inc");

// Admin Security Check
if (session_status() == PHP_SESSION_NONE) { session_start(); }
$user_groups = (isset($_SESSION['Groups']) && is_array($_SESSION['Groups'])) ? $_SESSION['Groups'] : [];
$is_admin = ((isset($_SESSION['Username']) && $_SESSION['Username'] === 'admin') || in_array('admins', $user_groups));

// AJAX Action: Restart Service
if (isset($_POST['action']) && $_POST['action'] === 'restart_wg' && $is_admin) {
    shell_exec("service wireguard restart > /dev/null 2>&1");
    echo "ok";
    exit;
}

// Fetch WG Configs
function widget_get_wg_array($type) {
    global $config;
    $plural = $type . 's';
    if (isset($config['installedpackages']['wireguard'][$plural])) {
        $data = $config['installedpackages']['wireguard'][$plural];
        return isset($data['item']) ? $data['item'] : (is_array($data) ? $data : []);
    } elseif (isset($config['wireguard'][$type])) {
        $data = $config['wireguard'][$type];
        if (!empty($data) && !isset($data[0])) return [$data];
        return is_array($data) ? $data : [];
    }
    return [];
}

$tunnels = widget_get_wg_array('tunnel');
$peers = widget_get_wg_array('peer');

// Fetch Live Telemetry
$wg_bin = '';
foreach (['/sbin/wg', '/usr/bin/wg', '/usr/local/bin/wg'] as $path) {
    if (file_exists($path)) { $wg_bin = $path; break; }
}

$online_count = 0;
$activity_feed = [];
if (!empty($wg_bin) && $is_admin) {
    $raw_hs = shell_exec("{$wg_bin} show all latest-handshakes 2>/dev/null");
    if ($raw_hs) {
        foreach (explode("\n", trim($raw_hs)) as $line) {
            $parts = preg_split('/\s+/', $line);
            if (count($parts) >= 3 && (int)$parts[2] > 0) {
                $ts = (int)$parts[2];
                $pubkey = trim($parts[1]);
                if (time() - $ts < 180) { $online_count++; } // Seen in last 3 mins
                $activity_feed[$pubkey] = $ts;
            }
        }
    }
}
arsort($activity_feed);
$activity_feed = array_slice($activity_feed, 0, 3, true); // Keep Top 3
?>

<div class="content" style="padding: 10px;">
    
    <?php if(!$is_admin): ?>
        <div class="alert alert-danger text-center">Admin access required.</div>
    <?php else: ?>
        
        <div class="row text-center" style="margin-bottom: 10px;">
            <div class="col-xs-4">
                <h3 style="margin-top:0; margin-bottom:5px;"><?=$online_count;?></h3>
                <small class="text-success"><i class="fa fa-circle"></i> Online</small>
            </div>
            <div class="col-xs-4">
                <h3 style="margin-top:0; margin-bottom:5px;"><?=count($tunnels);?></h3>
                <small>Tunnels</small>
            </div>
            <div class="col-xs-4">
                <h3 style="margin-top:0; margin-bottom:5px;"><?=count($peers);?></h3>
                <small>Peers</small>
            </div>
        </div>
        
        <hr style="margin: 10px 0;">
        
        <div class="form-group">
            <label>Quick Provision Device</label>
            <div class="input-group">
                <select id="wgQuickProvisionSelect" class="form-control input-sm">
                    <?php if(empty($peers)): ?>
                        <option disabled>No peers found</option>
                    <?php else: ?>
                        <?php foreach($peers as $idx => $p): ?>
                            <option value="<?=$idx;?>"><?=htmlspecialchars($p['descr'] ?? "Peer $idx");?></option>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </select>
                <span class="input-group-btn">
                    <button class="btn btn-sm btn-primary" onclick="wgQuickProvision()">
                        <i class="fa fa-qrcode"></i> Gen
                    </button>
                </span>
            </div>
        </div>
        
        <hr style="margin: 10px 0;">
        
        <label>Recent Connections</label>
        <ul class="list-unstyled">
            <?php if(empty($activity_feed)): ?>
                <li class="text-muted"><small>No recent handshakes detected.</small></li>
            <?php else: ?>
                <?php foreach($activity_feed as $pk => $ts): 
                    $name = "Unknown Device";
                    foreach($peers as $p) { if(($p['publickey']??'') === $pk) { $name = $p['descr'] ?? 'Peer'; break; } }
                    $mins = round((time() - $ts) / 60);
                    $time_str = $mins < 1 ? "Just now" : "{$mins}m ago";
                ?>
                <li>
                    <small>
                        <i class="fa fa-user text-muted"></i> <strong><?=htmlspecialchars($name);?></strong> 
                        <span class="pull-right text-muted"><?=$time_str;?></span>
                    </small>
                </li>
                <?php endforeach; ?>
            <?php endif; ?>
        </ul>
        
        <hr style="margin: 10px 0;">
        
        <div class="text-center">
            <button id="wg_restart_btn" class="btn btn-xs btn-danger" onclick="restartWireGuard()">
                <i class="fa fa-refresh"></i> Restart WG Service
            </button>
        </div>

        <script>
        function wgQuickProvision() {
            let idx = $('#wgQuickProvisionSelect').val();
            if(idx !== null) {
                window.location.href = '/vpn_wg_export.php?provision_idx=' + idx;
            }
        }

        function restartWireGuard() {
            if(confirm("Are you sure you want to restart the WireGuard service? All current connections will drop temporarily.")) {
                $('#wg_restart_btn').prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Restarting...');
                $.post('/widgets/widgets/wg_client_export.widget.php', {action: 'restart_wg'}, function() {
                    setTimeout(function(){
                        $('#wg_restart_btn').prop('disabled', false).html('<i class="fa fa-check"></i> Service Restarted');
                        setTimeout(function(){
                            $('#wg_restart_btn').html('<i class="fa fa-refresh"></i> Restart WG Service');
                        }, 3000);
                    }, 1500);
                });
            }
        }
        </script>
        
    <?php endif; ?>
</div>
EOF
chmod 644 /usr/local/www/widgets/widgets/wg_client_export.widget.php

echo "Deployment complete! Your WG Peer Export tool is fully updated."
