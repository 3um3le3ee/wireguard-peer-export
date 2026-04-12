<?php
/*
 * wg_client_export.widget.php
 * Smart Dashboard Widget for WireGuard Provisioning (Pro Edition)
 */
require_once("guiconfig.inc");
require_once("util.inc");

if (session_status() == PHP_SESSION_NONE) { session_start(); }
$user_groups = (isset($_SESSION['Groups']) && is_array($_SESSION['Groups'])) ? $_SESSION['Groups'] : [];
$is_admin = ((isset($_SESSION['Username']) && $_SESSION['Username'] === 'admin') || in_array('admins', $user_groups));

if (isset($_POST['action']) && $_POST['action'] === 'restart_wg' && $is_admin) {
    shell_exec("service wireguard restart > /dev/null 2>&1");
    echo "ok";
    exit;
}

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

$wg_bin = '';
foreach (['/sbin/wg', '/usr/bin/wg', '/usr/local/bin/wg'] as $path) {
    if (file_exists($path)) { $wg_bin = $path; break; }
}

$online_count = 0;
$activity_feed = [];
$transfers = [];

if (!empty($wg_bin) && $is_admin) {
    $raw_hs = shell_exec("{$wg_bin} show all latest-handshakes 2>/dev/null");
    if ($raw_hs) {
        foreach (explode("\n", trim($raw_hs)) as $line) {
            $parts = preg_split('/\s+/', $line);
            if (count($parts) >= 3 && (int)$parts[2] > 0) {
                $ts = (int)$parts[2];
                $pubkey = trim($parts[1]);
                if (time() - $ts < 180) { $online_count++; }
                $activity_feed[$pubkey] = $ts;
            }
        }
    }
    $raw_tx = shell_exec("{$wg_bin} show all transfer 2>/dev/null");
    if ($raw_tx) {
        foreach (explode("\n", trim($raw_tx)) as $line) {
            $parts = preg_split('/\s+/', $line);
            if (count($parts) >= 4) { $transfers[trim($parts[1])] = ['rx' => $parts[2], 'tx' => $parts[3]]; }
        }
    }
}
arsort($activity_feed);
$activity_feed = array_slice($activity_feed, 0, 3, true);
?>

<div class="content" style="padding: 10px;">
    <?php if(!$is_admin): ?>
        <div class="alert alert-danger text-center">Admin access required.</div>
    <?php else: ?>
        
        <div class="row text-center" style="margin-bottom: 10px;">
            <div class="col-xs-4">
                <h3 style="margin-top:0; margin-bottom:5px;">
                    <span class="text-success"><?=$online_count;?></span> 
                </h3>
                <small><i class="fa fa-circle text-success"></i> Active</small>
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
            <label>Export Existing Peer</label>
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
                    <button class="btn btn-sm btn-info" onclick="wgQuickProvision()">
                        <i class="fa fa-qrcode"></i> Export
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
                    
                    $diff = time() - $ts;
                    $status_icon = "fa-user " . ($diff < 180 ? "text-success" : "text-muted");
                    $mins = round($diff / 60);
                    $time_str = $mins < 1 ? "Just now" : "{$mins}m ago";

                    $data_str = "";
                    if (isset($transfers[$pk])) {
                        $rx = format_bytes($transfers[$pk]['rx']);
                        $tx = format_bytes($transfers[$pk]['tx']);
                        $data_str = "<br><span class='text-muted' style='font-size:10px;'><i class='fa fa-arrow-down'></i> {$rx} | <i class='fa fa-arrow-up'></i> {$tx}</span>";
                    }
                ?>
                <li style="margin-bottom: 5px; border-bottom: 1px solid #eee; padding-bottom: 3px;">
                    <small>
                        <i class="fa <?=$status_icon;?>"></i> <strong><?=htmlspecialchars($name);?></strong> 
                        <span class="pull-right text-muted"><?=$time_str;?></span>
                        <?=$data_str;?>
                    </small>
                </li>
                <?php endforeach; ?>
            <?php endif; ?>
        </ul>
        
        <div class="text-center" style="margin-top: 10px;">
            <button id="wg_restart_btn" class="btn btn-xs btn-danger" onclick="restartWireGuard()">
                <i class="fa fa-refresh"></i> Restart WG Service
            </button>
        </div>

        <script>
        function wgQuickProvision() {
            let idx = $('#wgQuickProvisionSelect').val();
            if(idx !== null) { window.location.href = '/vpn_wg_export.php?provision_idx=' + idx; }
        }

        function restartWireGuard() {
            if(confirm("Are you sure you want to restart the WireGuard service? All current connections will drop temporarily.")) {
                $('#wg_restart_btn').prop('disabled', true).html('<i class="fa fa-spinner fa-spin"></i> Restarting...');
                let csrfToken = $("input[name='__csrf_magic']").length ? $("input[name='__csrf_magic']").val() : (typeof csrfMagicToken !== 'undefined' ? csrfMagicToken : '');
                $.post('/widgets/widgets/wg_client_export.widget.php', {action: 'restart_wg', __csrf_magic: csrfToken}, function() {
                    setTimeout(function(){
                        $('#wg_restart_btn').prop('disabled', false).html('<i class="fa fa-check"></i> Service Restarted');
                        setTimeout(function(){ $('#wg_restart_btn').html('<i class="fa fa-refresh"></i> Restart WG Service'); }, 3000);
                    }, 1500);
                });
            }
        }
        </script>
        
    <?php endif; ?>
</div>
