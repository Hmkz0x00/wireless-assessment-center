# Architecture

Wireless Assessment Center is a single [Frieren](https://github.com/xchwarze/frieren)
module: a PHP backend controller plus a self-contained React frontend bundle, running on
an OpenWrt router. This document explains how the pieces fit together.

## High-level shape

```
┌────────────────────────────────────────────────────────────┐
│ Browser (Frieren SPA — React 18 + Jotai + react-query)     │
│   module.umd.js  ── the module's own UI, mounted by Frieren │
└───────────────┬────────────────────────────────────────────┘
                │  JSON POST  /api/index.php
                │  { module, action, ...args }
┌───────────────▼────────────────────────────────────────────┐
│ Frieren core (PHP) → routes to the module controller        │
│   Wireless_assessmentController extends frieren\core\...     │
│   $endpointRoutes whitelists ~45 actions                    │
└───────────────┬────────────────────────────────────────────┘
                │  shells out to system tools, manages UCI/netifd
┌───────────────▼────────────────────────────────────────────┐
│ OpenWrt device                                              │
│   radios (STA uplink / AP / monitor) · nftables · dnsmasq   │
│   aircrack-ng · hcxtools · reaver/pixiewps · hostapd · …     │
└────────────────────────────────────────────────────────────┘
```

The frontend never talks to system tools directly. Every capability is an action on the
controller, and the controller is the only place that touches the radios, the packet
tools, or the firewall.

## Backend code organization

The controller owns everything stateful — the endpoint routes, the job lifecycle, and all
access to the radios/UCI/firewall. Everything that *doesn't* need that state is factored out
into small, stateless helper classes so the controller stays readable and the device parses
less code per request:

| Helper class       | Responsibility                                                        |
|--------------------|-----------------------------------------------------------------------|
| `WaParsers`        | Parse tool output — `iw`/`iwinfo`/`airodump` scans, reaver/WPS-IE, radiotap, tcpdump dissection |
| `WaValidators`     | Input-safety validators (BSSID/iface/job-id/RFC1918) + MAC/format utilities |
| `WaVendorLookup`   | OUI → vendor-name enrichment for every AP/client MAC                   |
| `WaWordlists`      | Wordlist generation and WPS default-PIN computation                   |
| `WaTemplates`      | Static HTML/CSS for captive-portal and MITM awareness pages           |
| `WaSystemInfo`     | System / hardware / wireless-interface introspection and static config |

Each helper is a class of `public static` methods under the module's namespace, so Frieren's
PSR-4 autoloader resolves `frieren\modules\wireless_assessment\WaParsers` straight to
`WaParsers.php` — no registration, and the file is only `require`d the first time an action
actually references it. A lightweight call like `moduleStatus` therefore never parses the
handshake/WPS/sniff parsers or the wordlist generators at all. On the single-core MIPS SoC this
project targets, that on-demand parsing is a deliberate, measurable win.

## Request / response model

Frieren dispatches a POST whose body names a `module` and an `action`. The controller
declares which actions are reachable:

```php
protected $endpointRoutes = [
    'scanNetworks'   => true,
    'startCapture'   => true,
    'startClientless'=> true,
    'startWpsAttack' => true,
    // ~45 total
];
```

Each action returns a normalized `setSuccess([...])` / `setError(...)` payload. Anything
not in the whitelist is unreachable, so the attack surface is explicit.

## Long-running jobs

Captures, cracks, WPS attacks, portals, and MITM all outlive a single HTTP request, so the
module uses a **background-job + polling** pattern rather than holding the connection open:

1. `startX` writes a self-contained shell script, launches it detached, and returns a
   `jobId`.
2. The script writes incremental log/state files and, on completion, a `done` marker with
   an exit code.
3. The UI polls `xStatus` on an interval, rendering live logs and progress.
4. `stopX` drops a stop-file the script watches, then signals the process group.

Because state lives in files keyed by `jobId`, `status`/`stop` are generic over the job
type and survive the PHP request that started them. Polling is deliberately tolerant of
transient unreachability (the device briefly drops off during radio retunes), so a single
missed poll never surfaces as a hard error.

## Radio mode management

The device has two radios and one job to keep straight: don't knock out your own
management link. The module models two explicit modes:

- **Internet / uplink** — one radio joins an upstream Wi-Fi as a station (STA) so the box
  has internet; the other is free for testing.
- **Lab** — both radios are freed for assessment work (monitor/AP), with no Wi-Fi uplink.
  Management continues over Ethernet.

Mode switches are scoped per-radio (`wifi up/down <radio>`) so reconfiguring the test
radio never tears down the uplink radio, and teardown always restores the saved interface
state.

## Tool integrations

| Capability            | Tools                                             |
|-----------------------|---------------------------------------------------|
| Scan / recon          | `iw`, `airodump-ng`                               |
| WPA handshake capture | `airodump-ng` + light `aireplay-ng` deauth        |
| Clientless / PMKID    | `hcxdumptool` (BPF-scoped) + `hcxpcapngtool`      |
| WPS                    | `wash`, `reaver`, `pixiewps`                       |
| Dictionary crack      | `aircrack-ng` (+ `hcxpcapngtool` for 22000 hashes) |
| Evil Portal            | `hostapd` + `dnsmasq` + `uhttpd` captive portal   |
| MITM / DNS            | `dnsmasq` (dedicated resolver) + `nftables`       |
| Packet sniff          | `tcpdump`                                          |

## Safety mechanics baked into the code

These are implementation details, not just documentation:

- **Single-target BPF scoping.** Clientless/PMKID capture compiles a Berkeley Packet
  Filter (`wlan addr3 <bssid>`) so both capture *and* any injection are limited to one
  authorized BSSID — neighbouring networks are never touched, and the radio is never
  flooded.
- **Authorization gating.** Targets carry an `authorized` flag in the recon database;
  attack actions are meant to run against targets you have marked as yours.
- **Credential redaction.** Config dumps run through a redaction pass
  (`.(key|password|sae_password)=<redacted>`) before they are returned to the UI.
- **Scoped firewall changes.** MITM/portal rules are added to a dedicated nftables table
  and interface, and torn down on stop, leaving the box's normal DNS and NAT intact.
- **No dangerous watchdog actions.** The packet tools are invoked with validated flags
  only; reboot/poweroff-on-error hooks are never set.

## Frontend

The UI is authored as a single UMD source (`module.umd.source.js`) using Frieren's
provided React runtime (no separate build toolchain required for the module), then gzipped
to `module.umd.js` for the device to serve with `Content-Encoding: gzip`:

```bash
node --check module.umd.source.js
gzip -9 -n -c module.umd.source.js > module.umd.js
```

Panels map one-to-one to backend capabilities (Recon, Capture, Clientless, WPS, Evil
Portal, MITM, Crack Lab, …), each driving the start/status/stop lifecycle of its job.
