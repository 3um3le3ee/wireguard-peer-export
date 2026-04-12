<?php
/*
 * vpn_wg_export.php
 * Ultimate pfSense WG Peer Export (v0.4.2)
 * Features: Auto-IP Discovery, Version-Aware Save, Offline QR, CSRF Protection.
 */

require_once("guiconfig.inc");
require_once("util.inc");

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
    if (!empty($data) && !isset($data[0])) {
        $is_assoc = false;
        foreach(array_keys($data) as $k) { if(!is_int($k)) { $is_assoc = true; break; } }
        if ($is_assoc) { $data = [$data]; }
    }
    return $data;
}

// --- HELPER: DYNAMIC ENDPOINT ---
function get_best_endpoint($server_tun = null) {
    global $config;
    if (isset($config['dyndnses']['dyndns']) && is_array($config['dyndnses']['dyndns'])) {
        foreach ($config['dyndnses']['dyndns'] as $ddns) {
            if (!empty($ddns['host'])) return $ddns['host'];
        }
    }
    if ($server_tun && !empty($server_tun['interface'])) {
        $if_ip = get_interface_ip($server_tun['interface']);
        if (is_ipaddrv4($if_ip) || is_ipaddrv6($if_ip)) { return $if_ip; }
    }
    return get_interface_ip("wan");
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
    $conf .= "__DNS_PLACEHOLDER__\n";
    
    $conf .= "\n[Peer]\n";
    $conf .= "PublicKey = " . ($server_tun['publickey'] ?? '') . "\n";
    $conf .= "__PSK_PLACEHOLDER__\n"; 
    
    $conf .= "Endpoint = __ENDPOINT_PLACEHOLDER__\n";
    $conf .= "AllowedIPs = __ALLOWEDIPS_PLACEHOLDER__\n";
    $conf .= "PersistentKeepalive = 25\n";
    
    return $conf;
}

// 2. HANDLE POST AJAX (ADD PEER TO PFSENSE)
if (isset($_POST['action']) && $_POST['action'] === "add_peer") {
    header('Content-Type: application/json');
    
    $tun_name = $_POST['tun'] ?? '';
    $publickey = trim($_POST['publickey'] ?? '');
    $assigned_ip = trim($_POST['assignedip'] ?? '');
    $descr = trim($_POST['descr'] ?? 'New Peer');
    
    if (empty($tun_name) || empty($publickey) || empty($assigned_ip)) {
        echo json_encode(['success' => false, 'message' => 'Missing required fields.']); exit;
    }

    $new_peer = [
        'enabled' => 'yes',
        'tun' => $tun_name,
        'descr' => $descr,
        'publickey' => $publickey,
        'presharedkey' => $_POST['presharedkey'] ?? '',
        'persistentkeepalive' => '25',
        'allowedips' => ['row' => []]
    ];
    
    if (strpos($assigned_ip, '/') !== false) {
        list($addr, $mask) = explode('/', $assigned_ip, 2);
    } else {
        $addr = $assigned_ip;
        $mask = '32';
    }
    
    if (!is_ipaddr($addr)) {
        echo json_encode(['success' => false, 'message' => 'Invalid IP address provided.']); exit;
    }

    $new_peer['allowedips']['row'][] = ['address' => $addr, 'mask' => $mask, 'descr' => ''];
    
    // --- VERSION-AWARE CONFIG SAVING ---
    global $config;
    $saved = false;
    
    if (isset($config['wireguard'])) {
        if (!isset($config['wireguard']['peer']) || !is_array($config['wireguard']['peer'])) {
            $config['wireguard']['peer'] = [];
        }
        $config['wireguard']['peer'][] = $new_peer;
        $saved = true;
    } 
    elseif (isset($config['installedpackages']['wireguard'])) {
        if (!isset($config['installedpackages']['wireguard']['peers']['item']) || !is_array($config['installedpackages']['wireguard']['peers']['item'])) {
            $config['installedpackages']['wireguard']['peers']['item'] = [];
        }
        $config['installedpackages']['wireguard']['peers']['item'][] = $new_peer;
        $saved = true;
    }
    
    if (!$saved) { $config['wireguard']['peer'][] = $new_peer; }
    
    write_config("WG Peer Export: Admin auto-provisioned peer '{$descr}'");
    
    @include_once('/usr/local/pkg/wireguard/includes/wg_globals.inc');
    @include_once('/usr/local/pkg/wireguard/includes/wg.inc');
    @include_once('/usr/local/pkg/wireguard/includes/wg_service.inc');
    global $wgg;
    
    if (function_exists('mark_subsystem_dirty') && isset($wgg['subsystems']['wg'])) {
        mark_subsystem_dirty($wgg['subsystems']['wg']);
        if (function_exists('wg_apply_list_add')) { wg_apply_list_add('tunnels', [$tun_name]); }
    }
    
    if (function_exists('wg_tunnel_sync') && function_exists('wg_is_service_running') && wg_is_service_running()) {
        $tunnels_to_apply = function_exists('wg_apply_list_get') ? wg_apply_list_get('tunnels') : [$tun_name];
        $sync_status = wg_tunnel_sync($tunnels_to_apply, true, true);
        if (($sync_status['ret_code'] ?? 1) == 0 && function_exists('clear_subsystem_dirty')) {
            clear_subsystem_dirty($wgg['subsystems']['wg']);
        }
    }
    echo json_encode(['success' => true, 'message' => 'Peer successfully added and synchronized to WireGuard.']); exit;
}

// 3. HANDLE GET AJAX & DOWNLOADS
if (isset($_GET['action'])) {
    
    if ($_GET['action'] === "bulk_export") {
        $a_tunnels = get_wg_config_array('tunnel');
        $a_peers = get_wg_config_array('peer');
        
        $selected_indices = isset($_GET['selected_peers']) ? explode(',', $_GET['selected_peers']) : array_keys($a_peers);
        
        $tmp_dir = sys_get_temp_dir() . '/wg_export_' . uniqid();
        mkdir($tmp_dir);
        
        foreach ($selected_indices as $idx) {
            if (!isset($a_peers[$idx])) continue;
            $peer = $a_peers[$idx];
            $tun_name = $peer['tun'] ?? '';
            $server_tun = null;
            foreach ($a_tunnels as $tun) { if (isset($tun['name']) && $tun['name'] === $tun_name) { $server_tun = $tun; break; } }
            
            if ($server_tun) {
                $raw_conf = build_wg_conf($peer, $server_tun);
                $priv = !empty($peer['privatekey']) ? $peer['privatekey'] : "<INSERT_PRIVATE_KEY_HERE>";
                
                $raw_conf = str_replace('__PRIVATE_KEY_PLACEHOLDER__', $priv, $raw_conf);
                $raw_conf = str_replace('__ALLOWEDIPS_PLACEHOLDER__', '0.0.0.0/0, ::/0', $raw_conf);
                $raw_conf = str_replace("__DNS_PLACEHOLDER__\n", "", $raw_conf);
                
                if (!empty($peer['presharedkey'])) {
                    $raw_conf = str_replace('__PSK_PLACEHOLDER__', "PresharedKey = " . $peer['presharedkey'], $raw_conf);
                } else {
                    $raw_conf = str_replace("__PSK_PLACEHOLDER__\n", "", $raw_conf);
                }
                
                $ep_ip = get_best_endpoint($server_tun);
                $ep_port = !empty($server_tun['listenport']) ? $server_tun['listenport'] : "51820";
                $raw_conf = str_replace('__ENDPOINT_PLACEHOLDER__', "{$ep_ip}:{$ep_port}", $raw_conf);
                
                $desc = preg_replace('/[^a-zA-Z0-9_-]/', '_', ($peer['descr'] ?? "peer"));
                file_put_contents("{$tmp_dir}/{$desc}_{$idx}.conf", $raw_conf);
            }
        }
        
        syslog(LOG_NOTICE, "WireGuard Export: Admin performed bulk configuration download.");

        if (class_exists('ZipArchive')) {
            $zip = new ZipArchive();
            $tmp_file = tempnam(sys_get_temp_dir(), 'wgzip') . '.zip';
            if ($zip->open($tmp_file, ZipArchive::CREATE) === TRUE) {
                $files = glob("{$tmp_dir}/*.conf");
                foreach ($files as $file) { $zip->addFile($file, basename($file)); }
                $zip->close();
            }
            $dl_name = 'wireguard_peers.zip';
            $dl_type = 'application/zip';
        } else {
            $tmp_file = tempnam(sys_get_temp_dir(), 'wgtgz') . '.tar.gz';
            shell_exec("tar -czf " . escapeshellarg($tmp_file) . " -C " . escapeshellarg($tmp_dir) . " .");
            $dl_name = 'wireguard_peers.tar.gz';
            $dl_type = 'application/gzip';
        }

        header('Content-Type: ' . $dl_type);
        header('Content-disposition: attachment; filename=' . $dl_name);
        header('Content-Length: ' . filesize($tmp_file));
        readfile($tmp_file);
        
        unlink($tmp_file);
        $files = glob("{$tmp_dir}/*.conf");
        foreach ($files as $file) { unlink($file); }
        rmdir($tmp_dir);
        exit;
    }

    if ($_GET['action'] === "gen_keys") {
        header('Content-Type: application/json');
        if (empty($wg_bin)) { echo json_encode(['error' => 'Could not locate wg executable.']); exit; }

        $priv = trim(shell_exec("{$wg_bin} genkey 2>/dev/null"));
        if (!empty($priv)) {
            $pub = trim(shell_exec("echo " . escapeshellarg($priv) . " | {$wg_bin} pubkey 2>/dev/null"));
            $psk = trim(shell_exec("{$wg_bin} genpsk 2>/dev/null"));
            echo json_encode(['priv' => $priv, 'pub' => $pub, 'psk' => $psk]); exit;
        } else {
            echo json_encode(['error' => "Command failed."]); exit;
        }
    }
    
    if ($_GET['action'] === "gen_psk") {
        header('Content-Type: application/json');
        if (empty($wg_bin)) { echo json_encode(['error' => 'wg not found']); exit; }
        $psk = trim(shell_exec("{$wg_bin} genpsk 2>/dev/null"));
        echo json_encode(['psk' => $psk]); exit;
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
                $endpoint_ip = get_best_endpoint($server_tun); 
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

// 4. FETCH LIVE TELEMETRY
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

// 5. RENDER THE GUI PAGE
$pgtitle = array(gettext("VPN"), gettext("WireGuard"), gettext("WG Peer Export"));
include("head.inc");

// Native pfSense Tab Integration
$tab_array = array();
$tab_array[] = array(gettext("Tunnels"), false, "/wg/vpn_wg_tunnels.php");
$tab_array[] = array(gettext("Peers"), false, "/wg/vpn_wg_peers.php");
$tab_array[] = array(gettext("Settings"), false, "/wg/vpn_wg_settings.php");
$tab_array[] = array(gettext("Status"), false, "/wg/status_wireguard.php");
$tab_array[] = array(gettext("Peer Export"), true, "/vpn_wg_export.php");
display_top_tabs($tab_array);

$a_peers = get_wg_config_array('peer');
$a_tunnels = get_wg_config_array('tunnel');

// --- AUTO-IP CALCULATION ENGINE ---
$tunnels_json = [];
foreach ($a_tunnels as $tun) {
    $ep_ip = get_best_endpoint($tun);
    $port = !empty($tun['listenport']) ? $tun['listenport'] : "51820";
    $tun_subnet = '';
    $tun_ip_base = '';

    // 1. Find Subnet & Base IP
    foreach ($config['interfaces'] as $ifn => $iface) {
        if (isset($iface['if']) && $iface['if'] === $tun['name'] && !empty($iface['ipaddr']) && !empty($iface['subnet'])) {
            $tun_subnet = gen_subnet($iface['ipaddr'], $iface['subnet']) . '/' . $iface['subnet'];
            $tun_ip_base = $iface['ipaddr'];
            break;
        }
    }
    if (empty($tun_subnet) && isset($tun['addresses']['row'][0]['address'])) {
        $addr = $tun['addresses']['row'][0]['address'];
        $mask = $tun['addresses']['row'][0]['mask'] ?? '24';
        $tun_subnet = gen_subnet($addr, $mask) . '/' . $mask;
        $tun_ip_base = $addr;
    }

    // 2. Calculate Next Available IP
    $next_ip_str = '';
    if (!empty($tun_ip_base) && is_ipaddrv4($tun_ip_base)) {
        $max_ip_long = ip2long($tun_ip_base);
        foreach ($a_peers as $p) {
            if (($p['tun'] ?? '') === $tun['name'] && isset($p['allowedips']['row'])) {
                $rows = $p['allowedips']['row'];
                if (isset($rows['address'])) { $rows = [$rows]; }
                foreach ($rows as $row) {
                    if (isset($row['address']) && is_ipaddrv4($row['address'])) {
                        $p_long = ip2long($row['address']);
                        if ($p_long > $max_ip_long) {
                            $max_ip_long = $p_long;
                        }
                    }
                }
            }
        }
        $next_ip_str = long2ip($max_ip_long + 1) . '/32';
    }

    $tunnels_json[] = [
        'name' => $tun['name'] ?? '', 
        'endpoint' => $ep_ip . ':' . $port, 
        'pubkey' => $tun['publickey'] ?? '', 
        'subnet' => $tun_subnet,
        'next_ip' => $next_ip_str
    ];
}
?>

<style>
    @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.3; } 100% { opacity: 1; } }
    .status-pulse { animation: pulse 1.5s infinite; color: #5cb85c; }
</style>

<div class="panel panel-default">
    <div class="panel-heading">
        <h2 class="panel-title"><?=gettext("WireGuard Provisioning & Export");?></h2>
    </div>
    <div class="panel-body">
        
        <div class="row" style="margin-bottom: 15px;">
            <div class="col-sm-6">
                <div class="input-group">
                    <span class="input-group-addon"><i class="fa fa-search"></i></span>
                    <input type="text" id="searchPeers" class="form-control" placeholder="Search peers by name, tunnel, or IP...">
                </div>
            </div>
            <div class="col-sm-6 text-right">
                <button type="button" class="btn btn-success" onclick="openAddPeerModal()">
                    <i class="fa fa-plus icon-embed-btn"></i> Add New Peer
                </button>
                <button type="button" class="btn btn-info" onclick="downloadSelected()">
                    <i class="fa fa-download icon-embed-btn"></i> Download Selected
                </button>
                <a href="#" onclick="downloadAll(); return false;" class="btn btn-primary">
                    <i class="fa fa-archive icon-embed-btn"></i> Download All
                </a>
            </div>
        </div>

        <div class="table-responsive">
            <table class="table table-striped table-hover table-condensed" id="peersTable">
                <thead>
                    <tr>
                        <th><input type="checkbox" id="selectAll"></th>
                        <th>Status</th>
                        <th>Description</th>
                        <th>Tunnel</th>
                        <th>Assigned IPs</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($a_peers)): ?>
                        <tr><td colspan="6" class="text-center">No WireGuard peers configured.</td></tr>
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
                            <td><input type="checkbox" class="peer-checkbox" value="<?=$idx;?>"></td>
                            <td><?=$status_html;?></td>
                            <td><strong><?=htmlspecialchars($display_desc);?></strong></td>
                            <td><?=htmlspecialchars($display_tun);?></td>
                            <td><?=implode(', ', $client_ips_arr);?></td>
                            <td>
                                <button type="button" class="btn btn-sm btn-info" onclick="openExportModal(<?=$idx;?>, '<?=addslashes($display_desc);?>')">
                                    <i class="fa fa-qrcode icon-embed-btn"></i> Export config
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
        
        <div class="row" id="rowAddNewParams" style="display:none;">
            <div class="col-sm-4">
                <div class="form-group">
                    <label><i class="fa fa-server"></i> Target Tunnel</label>
                    <select id="tunnelSelect" class="form-control" onchange="onTunnelChange()"></select>
                </div>
            </div>
            <div class="col-sm-4">
                <div class="form-group">
                    <label><i class="fa fa-tag"></i> Peer Description</label>
                    <input type="text" id="peerDescription" class="form-control" placeholder="e.g. John's iPhone" oninput="updateDisplays()">
                </div>
            </div>
            <div class="col-sm-4">
                <div class="form-group">
                    <label><i class="fa fa-sitemap"></i> Assigned IP</label>
                    <input type="text" id="peerAssignedIP" class="form-control" placeholder="e.g. 10.0.0.5/32" oninput="updateDisplays()">
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-sm-6">
                <div class="form-group">
                    <label><i class="fa fa-key"></i> Client Public Key</label>
                    <input type="text" id="clientPubKey" class="form-control" readonly>
                </div>
            </div>
            <div class="col-sm-6">
                <div class="form-group">
                    <label><i class="fa fa-lock"></i> Client Private Key</label>
                    <div class="input-group">
                        <input type="text" id="clientPrivKey" class="form-control" placeholder="Provide private key to unlock QR..." oninput="updateDisplays()">
                        <span class="input-group-btn" id="btnWrapGenKeys" style="display:none;">
                            <button class="btn btn-warning" type="button" onclick="refreshKeys()" title="Generate New Keypair">
                                <i class="fa fa-refresh"></i> Gen
                            </button>
                        </span>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-sm-4">
                <div class="form-group">
                    <label><i class="fa fa-exchange"></i> Routing Mode</label>
                    <select id="tunnelMode" class="form-control" onchange="updateDisplays()">
                        <option value="full">Full Tunnel (All Internet)</option>
                        <option value="split">Split Tunnel (Local Only)</option>
                    </select>
                </div>
            </div>
            <div class="col-sm-4">
                <div class="form-group">
                    <label><i class="fa fa-globe"></i> Endpoint Override</label>
                    <input type="text" id="endpointOverride" class="form-control" oninput="updateDisplays()">
                </div>
            </div>
            <div class="col-sm-4">
                <div class="form-group">
                    <label>
                        <span id="pskCheckboxWrapper" style="display:none;">
                            <input type="checkbox" id="pskEnabled" onchange="togglePsk(this)">
                        </span>
                        <i class="fa fa-shield"></i> Pre-Shared Key
                    </label>
                    <div class="input-group">
                        <input type="text" id="clientPsk" class="form-control" oninput="updateDisplays()">
                        <span class="input-group-btn" id="btnWrapGenPsk" style="display:none;">
                            <button class="btn btn-warning" type="button" onclick="refreshPsk()" id="refreshPskBtn" disabled="disabled" title="Generate New PSK">
                                <i class="fa fa-refresh"></i>
                            </button>
                        </span>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-sm-12">
                <div class="form-group">
                    <label><i class="fa fa-wifi"></i> Optional Custom DNS</label>
                    <input type="text" id="peerDNS" class="form-control" placeholder="e.g. 1.1.1.1, 8.8.8.8" oninput="updateDisplays()">
                </div>
            </div>
        </div>
        <hr>

        <div class="row">
            <div class="col-sm-4 text-center">
                <p><strong>Mobile QR Code</strong></p>
                <div id="qrcode_canvas" style="display:inline-block; padding:15px; border-radius: 5px; background: #fff;"></div>
            </div>
            <div class="col-sm-8">
                <p><strong>Raw Configuration</strong></p>
                <textarea id="confText" class="form-control" rows="8" readonly style="font-family: monospace;"></textarea>
                <br>
                <div class="row">
                    <div class="col-sm-6" id="btnWrapDownload">
                        <button type="button" class="btn btn-primary btn-block" onclick="downloadConfFile()">
                            <i class="fa fa-download icon-embed-btn"></i> Download .conf
                        </button>
                    </div>
                    <div class="col-sm-6" id="btnWrapAddPeer" style="display:none;">
                        <button type="button" class="btn btn-success btn-block" onclick="addPeerToTunnel()" id="btnAddPeer">
                            <i class="fa fa-save icon-embed-btn"></i> Provision & Save to pfSense
                        </button>
                    </div>
                </div>
            </div>
        </div>

      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
      </div>
    </div>
  </div>
</div>

<script src="/wg_qrcode.js"></script>

<script>
let tunnelsData = <?=json_encode($tunnels_json);?>;
let rawTemplateText = "";
let defaultEndpoint = "";
let currentPeerName = "";
let modalMode = "export";

function getCsrfToken() {
    return $("input[name='__csrf_magic']").length ? $("input[name='__csrf_magic']").val() : (typeof csrfMagicToken !== 'undefined' ? csrfMagicToken : '');
}

$('#selectAll').click(function() { $('.peer-checkbox').prop('checked', this.checked); });

function downloadSelected() {
    let selected = [];
    $('.peer-checkbox:checked').each(function() { selected.push($(this).val()); });
    if(selected.length === 0) { alert("Please select at least one peer."); return; }
    window.location.href = 'vpn_wg_export.php?action=bulk_export&selected_peers=' + selected.join(',') + '&__csrf_magic=' + getCsrfToken();
}

function downloadAll() {
    window.location.href = 'vpn_wg_export.php?action=bulk_export&__csrf_magic=' + getCsrfToken();
}

$('#searchPeers').on('keyup', function() {
    let value = $(this).val().toLowerCase();
    $("#peersTable tbody tr").filter(function() {
        $(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)
    });
});

function setUIState(mode) {
    modalMode = mode;
    $('#clientPrivKey, #endpointOverride, #clientPsk, #peerDNS, #clientPubKey, #peerDescription, #peerAssignedIP').val('');
    $('#tunnelMode').val('full');
    $('#confText').val('Loading configuration...');
    $('#qrcode_canvas').empty();

    if (mode === "export") {
        $('#rowAddNewParams').hide();
        $('#btnWrapAddPeer').hide();
        $('#btnWrapDownload').removeClass('col-sm-6').addClass('col-sm-12');
        $('#clientPrivKey, #clientPsk').prop('readonly', false);
        $('#btnWrapGenKeys, #btnWrapGenPsk, #pskCheckboxWrapper').hide();
    } else if (mode === "add") {
        $('#rowAddNewParams').show();
        $('#btnWrapAddPeer').show();
        $('#btnWrapDownload').removeClass('col-sm-12').addClass('col-sm-6');
        $('#clientPrivKey, #clientPsk').prop('readonly', true);
        $('#btnWrapGenKeys, #btnWrapGenPsk, #pskCheckboxWrapper').show();
        $("#pskEnabled").prop("checked", false);
        $("#refreshPskBtn").prop("disabled", true);
    }
}

function openExportModal(peerIdx, peerName) {
    currentPeerName = peerName;
    setUIState("export");
    $('#exportModalLabel').text('Export Configuration: ' + peerName);
    
    $.getJSON('vpn_wg_export.php?action=get_conf_data&peer_idx=' + peerIdx + '&__csrf_magic=' + getCsrfToken(), function(data) {
        rawTemplateText = data.template;
        defaultEndpoint = data.default_endpoint;
        $('#endpointOverride').attr('placeholder', 'Default: ' + defaultEndpoint);
        if(data.existing_psk) { $('#clientPsk').val(data.existing_psk); }
        
        let savedKeys = sessionStorage.getItem('wg_keys_' + currentPeerName);
        if (savedKeys) {
            let parsed = JSON.parse(savedKeys);
            $('#clientPrivKey').val(parsed.priv);
            $('#clientPubKey').val(parsed.pub);
        }
        
        updateDisplays();
        $('#exportModal').modal('show');
    }).fail(function() { alert("Error fetching configuration from pfSense."); });
}

function openAddPeerModal() {
    currentPeerName = "NewPeer";
    setUIState("add");
    $('#exportModalLabel').text("Provision New Peer");
    
    rawTemplateText = "[Interface]\nPrivateKey = __PRIVATE_KEY_PLACEHOLDER__\nAddress = 10.x.x.x/32\n\n[Peer]\nPublicKey = __SERVERPUB__\nEndpoint = __ENDPOINT_PLACEHOLDER__\nAllowedIPs = __ALLOWEDIPS_PLACEHOLDER__\n__PSK_PLACEHOLDER__\nPersistentKeepalive = 25\n";
    defaultEndpoint = "";

    populateTunnelSelect();
    generateNewKeys();
    $('#exportModal').modal('show');
}

function populateTunnelSelect() {
    let sel = $('#tunnelSelect');
    sel.empty();
    tunnelsData.forEach(function(t) {
        sel.append($('<option>').val(t.endpoint).text(t.name).data('pubkey', t.pubkey).data('subnet', t.subnet).data('nextip', t.next_ip));
    });
    if (tunnelsData.length > 0) {
        sel.val(tunnelsData[0].endpoint);
        $('#endpointOverride').attr('placeholder', 'Default: ' + tunnelsData[0].endpoint);
        updateTunnelPubKey(tunnelsData[0].pubkey || '');
        if (modalMode === "add") {
            $('#peerAssignedIP').val(tunnelsData[0].next_ip || '');
        }
    }
}

function onTunnelChange() {
    var sel = document.getElementById('tunnelSelect');
    var opt = sel.options[sel.selectedIndex];
    $('#endpointOverride').attr('placeholder', 'Default: ' + sel.value);
    $('#endpointOverride').val('');
    updateTunnelPubKey($(opt).data('pubkey') || '');
    if (modalMode === "add") {
        $('#peerAssignedIP').val($(opt).data('nextip') || '');
    }
    updateDisplays();
}

function updateTunnelPubKey(pubkey) {
    rawTemplateText = rawTemplateText.replace(/PublicKey = .*/,  'PublicKey = ' + pubkey);
}

function updateDisplays() {
    let privKey = $('#clientPrivKey').val().trim();
    let displayKey = privKey === "" ? "<PASTE_PRIVATE_KEY_HERE>" : privKey;
    let finalConfig = rawTemplateText.replace('__PRIVATE_KEY_PLACEHOLDER__', displayKey);
    
    let psk = $('#clientPsk').val().trim();
    if (psk !== "") { finalConfig = finalConfig.replace('__PSK_PLACEHOLDER__', "PresharedKey = " + psk); } 
    else { finalConfig = finalConfig.replace("__PSK_PLACEHOLDER__\n", ""); }
    
    let ep = $('#endpointOverride').val().trim();
    if (ep === "" && modalMode === "add") { ep = $('#tunnelSelect').val(); }
    if (ep === "" && modalMode === "export") { ep = defaultEndpoint; }
    finalConfig = finalConfig.replace(/__ENDPOINT_PLACEHOLDER__|Endpoint = .*/,  'Endpoint = ' + ep);
    
    let isSplit = $('#tunnelMode').val() === 'split';
    let allowedIps = '0.0.0.0/0, ::/0';
    if (isSplit) {
        if (modalMode === "add") {
            allowedIps = $('#tunnelSelect').find(':selected').data('subnet') || '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16';
        } else {
            allowedIps = '10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16'; 
        }
    }
    finalConfig = finalConfig.replace(/__ALLOWEDIPS_PLACEHOLDER__|AllowedIPs = .*/,  'AllowedIPs = ' + allowedIps);

    if (modalMode === "add") {
        let assignedIP = $('#peerAssignedIP').val().trim();
        let addrLine = assignedIP !== '' ? assignedIP : '10.x.x.x/32';
        finalConfig = finalConfig.replace(/Address = .*/,  'Address = ' + addrLine);
    }

    let dns = $('#peerDNS').val().trim();
    finalConfig = finalConfig.replace(/DNS = .*\n/, '');
    if (dns !== '') {
        finalConfig = finalConfig.replace(/Address = (.*)/, 'Address = $1\nDNS = ' + dns);
    }

    if (modalMode === "add") {
        let desc = $('#peerDescription').val().trim();
        if (desc !== '') { finalConfig = '# ' + desc + '\n' + finalConfig; }
    }
    
    $('#confText').val(finalConfig);
    
    $('#qrcode_canvas').empty();
    if (privKey !== "") {
        try {
            if (typeof QRCode !== 'undefined') {
                new QRCode(document.getElementById("qrcode_canvas"), {
                    text: finalConfig, width: 220, height: 220,
                    colorDark : "#000000", colorLight : "#ffffff", correctLevel : QRCode.CorrectLevel.M
                });
            } else { $('#qrcode_canvas').html('<br><span class="text-danger">wg_qrcode.js missing</span><br>'); }
        } catch(e) { console.error(e); }
    } else {
        $('#qrcode_canvas').html('<br><br><br><span class="text-muted">Private Key required<br>for QR Code generation</span><br><br>');
    }
}

function generateNewKeys() {
    $.getJSON('vpn_wg_export.php?action=gen_keys&__csrf_magic=' + getCsrfToken(), function(data) {
        if(data && data.priv && data.pub) {
            $('#clientPubKey').val(data.pub);
            $('#clientPrivKey').val(data.priv);
            updateDisplays();
        } else { alert("Error: " + (data.error || "Unknown")); }
    }).fail(function() { alert("Server communication failed."); });
}

function refreshKeys() { generateNewKeys(); }

function refreshPsk() {
    $.getJSON('vpn_wg_export.php?action=gen_psk&__csrf_magic=' + getCsrfToken(), function(data) {
        if(data && data.psk) {
            $('#clientPsk').val(data.psk);
            updateDisplays();
        } else { alert("Error: " + (data.error || "Unknown")); }
    });
}

function togglePsk(el) {
    if (el.checked) {
        document.getElementById("refreshPskBtn").disabled = false;
        refreshPsk();
    } else {
        document.getElementById("refreshPskBtn").disabled = true;
        document.getElementById("clientPsk").value = "";
        updateDisplays();
    }
}

function validatePeerForm() {
    var desc = $('#peerDescription').val().trim();
    var assignedIP = $('#peerAssignedIP').val().trim();
    var pubKey = $('#clientPubKey').val().trim();

    if (!pubKey) { alert('Error: Public key is missing. Please generate keys first.'); return false; }
    if (!desc) { alert('Please enter a Description for this peer.'); $('#peerDescription').focus(); return false; }
    if (!assignedIP) { alert('Please enter an Assigned IP for this peer.'); $('#peerAssignedIP').focus(); return false; }
    return true;
}

function addPeerToTunnel() {
    var pubKey = $('#clientPubKey').val().trim();
    var desc = $('#peerDescription').val().trim();
    var assignedIP = $('#peerAssignedIP').val().trim();
    var psk = $('#clientPsk').val().trim();
    var sel = document.getElementById('tunnelSelect');
    var tunName = sel.options[sel.selectedIndex].text;

    if (!validatePeerForm()) return;

    if (!confirm('Provision this peer to pfSense tunnel "' + tunName + '"?\n\n⚠️ Ensure you have scanned the QR code or downloaded the .conf file. The private key will be wiped from memory once saved.')) {
        return;
    }

    $('#btnAddPeer').prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Saving to pfSense...');

    $.ajax({
        url: 'vpn_wg_export.php',
        method: 'POST',
        data: {
            action: 'add_peer',
            __csrf_magic: getCsrfToken(),
            tun: tunName,
            publickey: pubKey,
            descr: desc,
            assignedip: assignedIP,
            presharedkey: psk
        },
        dataType: 'json',
        success: function(data) {
            if (data && data.success) {
                alert('Peer securely added and synchronized! The page will reload.');
                location.reload();
            } else {
                alert('pfSense rejected the addition: ' + (data.message || 'Unknown error'));
                $('#btnAddPeer').prop('disabled', false).html('<i class="fa fa-save icon-embed-btn"></i> Provision & Save to pfSense');
            }
        },
        error: function() {
            alert('Server communication failed.');
            $('#btnAddPeer').prop('disabled', false).html('<i class="fa fa-save icon-embed-btn"></i> Provision & Save to pfSense');
        }
    });
}

function downloadConfFile() {
    if (modalMode === "add" && !validatePeerForm()) return;
    let desc = (modalMode === "add") ? $('#peerDescription').val().trim() : currentPeerName;
    let fileName = desc.replace(/[^a-zA-Z0-9_-]/g, '_');
    let blob = new Blob([$('#confText').val()], { type: 'text/plain' });
    let a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = fileName + '.conf';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
}

<?php if (isset($_GET['provision_idx']) && is_numeric($_GET['provision_idx']) && isset($a_peers[$_GET['provision_idx']])): ?>
$(document).ready(function() {
    let autoIdx = <?=intval($_GET['provision_idx']);?>;
    let autoName = "<?=addslashes($a_peers[$_GET['provision_idx']]['descr'] ?? 'Peer');?>";
    openExportModal(autoIdx, autoName);
});
<?php endif; ?>
</script>

<?php include("foot.inc"); ?>
