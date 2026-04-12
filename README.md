pfSense WireGuard Peer Export
--
**One click to add a peer, get the `.conf` file, and generate a QR code. No more configuring both sides manually.**

Adding a WireGuard peer on pfSense normally means: create the peer in the GUI, manually generate keys, copy the public key back, hand-craft the client config, and figure out the endpoint/subnet yourself. This plugin turns all of that into a single step — click **Add New Peer**, fill in a name, and you get a ready-to-use config file and QR code while the peer is automatically registered on the firewall.

## ✨ Features

- **One-Click Peer Provisioning:** Instantly creates the peer on the firewall, generates keys, and delivers a ready-to-import `.conf` + QR code.
- **Auto-IP Discovery Engine:** Automatically calculates and suggests the next available IP address in the tunnel subnet.
- **Real-Time Config Preview:** Full `.conf` file and offline QR code generated instantly in the browser.
- **Bulk Export Support:** Download all peers at once as `.zip` or `.tar.gz` with one click.
- **Live Status Dashboard:** See tunnel, public key, Allowed IPs, and online/offline status for every peer.
- **Split Tunnel & DNS Options:** Easy toggles for full-tunnel vs split-tunnel and custom DNS.
- **100% Offline QR Code:** Uses a locally installed `qrcode.min.js` library — no external CDN calls.
- **Stateless Key Handling:** Private keys are generated on-the-fly and never stored in pfSense config or logs.

## 🚀 Quick Start

## 📦 Package Installation (Recommended)

install the tool as a native pfSense package (which allows for cleaner management and persistence), use the following commands. This will download the pre-compiled `.pkg` and install it using the system's package manager.

SSH into your pfSense (option 8 for shell), then download and run the installer:

**1. Download the package**
```bash
curl -LO https://raw.githubusercontent.com/3um3le3ee/pfSense-wireguard-peer-export/main/pfSense-pkg-wg-export-0.4.2.pkg
```
**2. Install the package**
```bash
pkg add pfSense-pkg-wg-export-0.4.2.pkg
```

### 🛠️ Manual Installation

SSH into your pfSense (option 8 for shell), then download and run the installer:

```bash
curl -LO https://raw.githubusercontent.com/3um3le3ee/pfSense-wireguard-peer-export/main/install_wg_export.sh
curl -LO https://raw.githubusercontent.com/3um3le3ee/pfSense-wireguard-peer-export/main/vpn_wg_export.php
curl -LO https://raw.githubusercontent.com/3um3le3ee/pfSense-wireguard-peer-export/main/wg_client_export.widget.php
chmod +x install_wg_export.sh && ./install_wg_export.sh
```
*Note: The installer will automatically download the offline QR code library to your firewall during setup.*

A new **Peer Export** tab will appear under **VPN > WireGuard**.

## 🗑️ Uninstall

```bash
curl -LO https://raw.githubusercontent.com/3um3le3ee/pfSense-wireguard-peer-export/main/uninstall.sh
chmod +x uninstall.sh && ./uninstall.sh
```

## 📖 Usage

### Add a New Peer (The Provisioning Workflow)

1. Go to **VPN > WireGuard > Peer Export**, click **Add New Peer**.
2. Pick a **Target Tunnel** — Endpoint, Public Key, and AllowedIPs are filled in automatically.
3. Enter a **Peer Description** (this will become the configuration filename).
4. **Auto-IP Discovery:** The **Assigned IP** box will automatically calculate and suggest the next available IP address in the tunnel's subnet!
5. Optionally set **DNS**, **Pre-Shared Key**, or switch to **Split Tunnel** mode.
6. **Download the .conf** or **scan the QR code** on your phone.
7. **Click Provision & Save to pfSense** — the peer is securely saved to the database and the WireGuard service is instantly synchronized in the background.

> ⚠️ **Download or scan before clicking Add** — the private key is generated statelessly and wiped from memory once saved.

### Export Existing Peers
The page also lists all configured peers with their tunnel, public key, allowed IPs, and live online status. Click **Export config** on any row to generate its config and QR code, or use **Download All** to grab a `.zip` or `.tar.gz` of every peer.

*Note: To prevent accidentally breaking existing tunnels, the "Generate Keys" button is safely hidden when exporting an already-provisioned peer.*

## ✨ What It Does For You

| Feature | How this plugin simplifies it |
| :--- | :--- |
| **Key Management** | Keys are auto-generated on page open; no manual `wg genkey` needed. |
| **Peer Registration** | Public keys are registered automatically on the firewall upon adding. |
| **Tunnel Details** | Endpoint IP, Port, and Server Public Key are auto-populated from the tunnel. |
| **IP Assignment** | **Auto-IP Engine** calculates and suggests the next available free IP. |
| **Client Config** | Real-time preview and one-click download of the `.conf` file. |
| **Mobile Setup** | QR code rendered instantly and **100% offline** for mobile scanning. |
| **Workflow** | One single form configures both the firewall and the client securely. |

## 📁 Files

- **`pfSense-pkg-wg-export-0.4.2.pkg`** Native pfSense Package — A pre-compiled binary that handles automated file placement, system registration, and clean uninstallation via the `pkg` manager.

- **`vpn_wg_export.php`** Main page — contains the peer table, Auto-IP engine, strict backend validation, and AJAX endpoints.

- **`wg_client_export.widget.php`** Dashboard widget — provides live telemetry, recent connections, and a quick-export dropdown.

- **`install_wg_export.sh`** Manual Installer — stages files, fetches the offline QR library, and patches native WireGuard tabs.

- **`uninstall.sh`** Uninstaller — removes all files, scrubs the XML database, and unpatches UI tabs cleanly.

## 🔒 Security & Architecture (v0.4.2 Updates)

This tool was designed with strict enterprise firewall security in mind:

- **100% Offline & Air-Gap Safe:** The Cloudflare CDN has been removed. The `qrcode.min.js` library is installed locally on the firewall, meaning no external requests are ever made by the WebGUI.

- **Strict CSRF Protection:** All background interactions utilize pfSense's native `__csrf_magic` tokens to prevent Cross-Site Request Forgery (CSRF) attacks.

- **Server-Side Validation:** Form inputs (like IPs and subnets) aren't just checked in the browser; the PHP backend heavily sanitizes and validates payloads using pfSense's native `is_ipaddr()` function before writing to `config.xml`.

- **Stateless Key Management:** Private keys are generated via the firewall's native `wg` binary, sent directly to the browser, and are **never** stored in the pfSense config or system logs.

- **Version-Aware:** Automatically detects and safely saves configurations whether you are running legacy pfSense 2.5.0 packages or modern pfSense 2.5.2/2.6/2.7+ native WireGuard integrations.

---

## ⚠️ Disclaimer

**Unofficial community plugin.** This project is not affiliated with or supported by Netgate or the pfSense project. Users should review the code before running it on production firewalls. Use at your own risk.

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
