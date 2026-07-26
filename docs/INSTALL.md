# Installing on an existing Frieren setup

This is a **third-party [Frieren](https://github.com/xchwarze/frieren) module**. Frieren
discovers any folder that contains a `manifest.json` under its modules root, so installing
is a drop-in: put the module folder on the device, install the tool dependencies, and reload
the panel.

The module is self-contained — three files (`manifest.json`, the PHP controller, and the
gzipped UMD frontend bundle) — and needs no build step on the device.

---

## Requirements

- A working **Frieren panel** on an OpenWrt device. Developed and tested on a **TP-Link
  Archer C7 v5** (OpenWrt 24.10). Two Wi-Fi radios are recommended (many features use one
  radio for the uplink and the other for testing).
- **Root access** to the device — either SSH, or the panel's built-in **Terminal**.
- A little free space for the module (~1 MB); captures/wordlists need more, so a USB/SD
  overlay is recommended on small-flash devices.

## 1. Install the tool dependencies (opkg)

The module shells out to standard OpenWrt wireless tooling. Install it once:

```sh
opkg update
opkg install aircrack-ng hcxdumptool hcxtools reaver pixiewps \
    hostapd-utils dnsmasq tcpdump nftables nmap iw kmod-tun
```

These mirror the `dependencies` array in `manifest.json`. `dnsmasq`, `nftables`, and `iw`
are usually already present — opkg will simply skip them. `wash` ships as part of `reaver`.

| Package(s) | Powers |
|------------|--------|
| `aircrack-ng` | Handshake capture (`airodump-ng`/`aireplay-ng`) and dictionary cracking |
| `hcxdumptool`, `hcxtools` | Clientless PMKID capture and `hcxpcapngtool` hash conversion |
| `reaver`, `pixiewps` | WPS online attack + pixie-dust; `wash` for discovery |
| `hostapd-utils`, `dnsmasq` | Evil-Portal / Rogue-AP twin AP + DHCP/DNS |
| `tcpdump`, `nftables` | Packet Intelligence sniffing and scoped MITM redirect rules |
| `nmap` | Network Recon (host/port/service scans) |
| `iw`, `kmod-tun` | Radio/monitor management; `kmod-tun` for the Rogue-AP path |

## 2. Install the module

The module folder must be named exactly **`wireless_assessment`** (it is Frieren's routing
key) and go in the modules root — **`/frieren/modules/`**. On most OpenWrt builds `/frieren`
is a symlink to `/usr/share/frieren`, so `/usr/share/frieren/modules/` is the same place.

Pick **one** method.

### Method A — copy from your computer (scp)

```sh
git clone https://github.com/Hmkz0x00/wireless-assessment-center
cd wireless-assessment-center
scp -r dist/wireless_assessment root@ROUTER_IP:/frieren/modules/
```

> The device runs **dropbear**, whose scp may reject the modern SFTP transfer. If scp fails
> with a subsystem/protocol error, add legacy mode: `scp -O -r dist/wireless_assessment
> root@ROUTER_IP:/frieren/modules/` — or use Method B.

### Method B — download on the device (no computer copy)

From the panel's **Terminal** (or an SSH session on the router):

```sh
mkdir -p /frieren/modules/wireless_assessment
cd /frieren/modules/wireless_assessment
BASE=https://raw.githubusercontent.com/Hmkz0x00/wireless-assessment-center/main/dist/wireless_assessment
wget -O manifest.json                     "$BASE/manifest.json"
wget -O Wireless_assessmentController.php  "$BASE/Wireless_assessmentController.php"
wget -O module.umd.js                      "$BASE/module.umd.js"
```

### Method C — tarball

Build the tarball on your computer, then extract it into the modules root on the device:

```sh
sh scripts/package.sh            # produces dist/wireless_assessment.tar.gz
scp dist/wireless_assessment.tar.gz root@ROUTER_IP:/tmp/
ssh root@ROUTER_IP 'tar -xzC /frieren/modules -f /tmp/wireless_assessment.tar.gz'
```

### Installing to SD/USB instead of internal flash

If internal flash is tight, install into `/sd/modules/` and symlink it back — this is exactly
what the panel's own installer does for its "SD" destination:

```sh
mkdir -p /sd/modules
mv /frieren/modules/wireless_assessment /sd/modules/
ln -s /sd/modules/wireless_assessment /frieren/modules/wireless_assessment
```

## 3. Open it

**Reload the Frieren panel** in your browser (a full refresh). Because the manifest sets
`forceSidebar: true`, **Wireless Assessment Center** appears in the left sidebar, and it also
shows up on the panel's **Modules** page. No service restart is needed — Frieren re-scans the
modules directory on each request.

Open the module and check its **System** tab first: it reports which tools are present, so you
can immediately spot any missing dependency from step 1.

## Uninstall

- In the panel: **Modules → Wireless Assessment Center → Remove**, or
- On the device: `rm -rf /frieren/modules/wireless_assessment` (plus the `/sd/modules/...`
  copy if you used SD).

Runtime data the module created (captures, wordlists, logs) lives under the module's own
`storage/` directory and is removed with it.

## Why isn't it in the panel's one-click "Available modules" list?

That list is fetched from the official Frieren release server (`frieren-modules-release`),
which serves only curated modules — so a third-party module like this one is installed
manually, as above. To get it into the official catalog it would need to be submitted to the
upstream [`frieren-modules`](https://github.com/xchwarze/frieren-modules) project.

## Troubleshooting

- **Module doesn't appear after install** — confirm the folder is exactly
  `/frieren/modules/wireless_assessment/` and contains a valid `manifest.json`, then do a full
  browser reload. Bad JSON in the manifest makes the panel skip the folder silently.
- **Tools show as "missing"** in the System tab — re-run step 1 (`opkg update` first).
- **A feature errors on a fresh device** — some paths need `kmod-tun` (Rogue AP) or a second
  free radio (switch to **Lab mode** in Radio Control). The in-UI notes call these out.
- **Panel shows a stale UI after an update** — the frontend is a gzip-served bundle;
  hard-refresh (Ctrl/Cmd-Shift-R) to bypass the browser cache.

## Compatibility & safety

- Built and tested on a TP-Link Archer C7 v5 (OpenWrt 24.10, single-core MIPS, ~121 MB RAM).
  Any OpenWrt device with two Wi-Fi radios should work; low-RAM devices will be slower.
- ⚠️ **Authorized use only.** See the [legal notice in the README](../README.md). Only run
  assessments against networks and devices you own or have explicit written permission to test.
