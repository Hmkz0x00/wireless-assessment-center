(function (root, factory) {
  root.FrierenModuleWireless_assessment = factory(
    root.Frieren.React,
    root.Frieren.ReactBootstrap
  );
})(typeof globalThis !== "undefined" ? globalThis : window, function (React, RB) {
  "use strict";

  const h = React.createElement;
  const {
    Alert,
    Badge,
    Button,
    Card,
    Col,
    Form,
    Row,
    Spinner,
    Table,
  } = RB;

  const MODULE = "wireless_assessment";
  const CORE_TOOLS = ["iw", "iwinfo", "wifi", "ubus", "uci", "airodump-ng", "aireplay-ng", "hcxpcapngtool", "nmap", "curl"];

  function csrfToken() {
    const match = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]*)/);
    return match ? decodeURIComponent(match[1]) : "";
  }

  async function api(action, payload) {
    const response = await fetch(`${window.location.origin}/api/index.php`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-XSRF-TOKEN": csrfToken(),
      },
      body: JSON.stringify(Object.assign({ module: MODULE, action }, payload || {})),
    });
    const json = await response.json();
    if (!response.ok || json.error) {
      throw new Error(json.error || "Request failed");
    }
    return json;
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  // Read a File as a bare base64 string (no data: prefix) for the JSON upload API.
  // The backend caps payloads at ~1.8 MB (this router is memory_limit=8M).
  const UPLOAD_MAX_BYTES = 1887436;
  function readFileB64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const res = String(reader.result || "");
        const comma = res.indexOf("base64,");
        resolve(comma >= 0 ? res.slice(comma + 7) : res);
      };
      reader.onerror = () => reject(new Error("Could not read the file."));
      reader.readAsDataURL(file);
    });
  }

  function Icon({ name }) {
    return h("i", { className: `icon-${name}` });
  }

  function Panel({ title, icon, children, action }) {
    return h(
      Card,
      { className: "panel-card h-100" },
      h(
        Card.Body,
        null,
        h(
          "div",
          { className: "d-flex align-items-center justify-content-between mb-3" },
          h(Card.Title, { className: "panel-card-title mb-0" }, icon ? h("span", { className: "me-2" }, h(Icon, { name: icon })) : null, title),
          action || null
        ),
        children
      )
    );
  }

  function ToolBadge({ installed }) {
    return h(Badge, { bg: installed ? "success" : "secondary" }, installed ? "Installed" : "Missing");
  }

  function toolInstalled(status, name) {
    return Boolean((status.tools || []).find((tool) => tool.name === name && tool.installed));
  }

  function formatDate(value) {
    if (!value) {
      return "-";
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value;
    }
    return date.toLocaleString();
  }

  function StepIcon({ status }) {
    if (status === "active") {
      return h(Spinner, { size: "sm", animation: "border", variant: "primary" });
    }
    const map = {
      done: ["✓", "success"],
      failed: ["✕", "danger"],
      warn: ["!", "warning"],
      skipped: ["–", "secondary"],
      pending: ["○", "light"],
    };
    const [glyph, variant] = map[status] || map.pending;
    return h(
      "span",
      {
        className: `badge bg-${variant} ${variant === "light" ? "text-dark border" : ""}`,
        style: { width: "24px", height: "24px", display: "inline-flex", alignItems: "center", justifyContent: "center", borderRadius: "50%", fontSize: "13px" },
      },
      glyph
    );
  }

  function StepTimeline({ steps }) {
    if (!steps || !steps.length) {
      return null;
    }
    return h(
      "div",
      { className: "mb-2" },
      steps.map((step, index) =>
        h(
          "div",
          { key: step.key || index, className: "d-flex align-items-start gap-2 mb-2" },
          h("div", { style: { width: "26px", flex: "0 0 auto", textAlign: "center", paddingTop: "1px" } }, h(StepIcon, { status: step.status })),
          h(
            "div",
            null,
            h("div", { className: `fw-semibold ${step.status === "pending" || step.status === "skipped" ? "text-body-secondary" : ""}` }, step.label),
            step.detail ? h("small", { className: "text-body-secondary" }, step.detail) : null
          )
        )
      )
    );
  }

  function OutcomeBanner({ reason }) {
    if (!reason) {
      return null;
    }
    const variant = reason.level === "success" ? "success" : reason.level === "danger" ? "danger" : "warning";
    const prefix = reason.level === "success" ? "Success: " : reason.level === "danger" ? "Failed: " : "Ended: ";
    return h(Alert, { variant, className: "py-2 mb-2" }, h("strong", null, prefix), reason.text);
  }

  function RawLog({ log, error, open, label }) {
    const text = (log || "").trim();
    return h(
      "details",
      { className: "mb-0", open: !!open },
      h("summary", { className: "text-body-secondary small", style: { cursor: "pointer" } }, label || "Raw tool output"),
      h("pre", { className: "mb-0 small mt-2", style: { maxHeight: "260px", overflow: "auto", whiteSpace: "pre-wrap" } }, text || "Waiting for output…"),
      error ? h("pre", { className: "mb-0 small text-danger", style: { whiteSpace: "pre-wrap" } }, error) : null
    );
  }

  function StatusSummary({ status }) {
    const installedCore = (status.tools || []).filter((tool) => CORE_TOOLS.includes(tool.name) && tool.installed).length;
    const interfaceCount = (status.interfaces || []).length;
    const radioCount = (status.radios || []).length;
    const rootFs = (status.storage || []).find((row) => row.mountedOn === "/");

    return h(
      Row,
      { className: "g-3 mb-3" },
      h(Col, { md: 3 }, h(Panel, { title: "Core Tools", icon: "check-circle" }, h("div", { className: "fs-3" }, `${installedCore}/${CORE_TOOLS.length}`), h("small", { className: "text-body-secondary" }, "capture engine ready"))),
      h(Col, { md: 3 }, h(Panel, { title: "Radios", icon: "radio" }, h("div", { className: "fs-3" }, radioCount), h("small", { className: "text-body-secondary" }, "detected PHYs"))),
      h(Col, { md: 3 }, h(Panel, { title: "Interfaces", icon: "wifi" }, h("div", { className: "fs-3" }, interfaceCount), h("small", { className: "text-body-secondary" }, "active wireless interfaces"))),
      h(Col, { md: 3 }, h(Panel, { title: "Overlay", icon: "hard-drive" }, h("div", { className: "fs-3" }, rootFs ? rootFs.available : "-"), h("small", { className: "text-body-secondary" }, "available on /")))
    );
  }

  function ToolTable({ tools }) {
    return h(
      Table,
      { striped: true, hover: true, responsive: true, className: "mb-0" },
      h("thead", null, h("tr", null, h("th", null, "Tool"), h("th", null, "Status"), h("th", null, "Purpose"), h("th", null, "Path"))),
      h(
        "tbody",
        null,
        tools.map((tool) =>
          h("tr", { key: tool.name }, h("td", null, tool.name), h("td", null, h(ToolBadge, { installed: tool.installed })), h("td", null, tool.requiredFor), h("td", null, h("code", null, tool.path || "-")))
        )
      )
    );
  }

  function PackageTable({ packages }) {
    return h(
      Table,
      { striped: true, hover: true, responsive: true, className: "mb-0" },
      h("thead", null, h("tr", null, h("th", null, "Package"), h("th", null, "Installed"), h("th", null, "Available"))),
      h(
        "tbody",
        null,
        packages.map((pkg) =>
          h(
            "tr",
            { key: pkg.name },
            h("td", null, pkg.name),
            h("td", null, h(Badge, { bg: pkg.installed ? "success" : "secondary" }, pkg.installed ? "Yes" : "No")),
            h("td", null, h(Badge, { bg: pkg.available ? "info" : "secondary" }, pkg.available ? "Feed" : "No"))
          )
        )
      )
    );
  }

  function RadioTable({ radios }) {
    return h(
      Table,
      { striped: true, hover: true, responsive: true, className: "mb-0" },
      h("thead", null, h("tr", null, h("th", null, "PHY"), h("th", null, "Bands"), h("th", null, "Modes"), h("th", null, "Path"))),
      h(
        "tbody",
        null,
        radios.map((radio) =>
          h("tr", { key: radio.name }, h("td", null, radio.name), h("td", null, (radio.bands || []).join(", ") || "-"), h("td", null, (radio.modes || []).join(", ") || "-"), h("td", null, h("small", null, radio.path || "-")))
        )
      )
    );
  }

  function InterfaceTable({ interfaces }) {
    return h(
      Table,
      { striped: true, hover: true, responsive: true, className: "mb-0" },
      h("thead", null, h("tr", null, h("th", null, "Interface"), h("th", null, "PHY"), h("th", null, "Type"), h("th", null, "SSID"), h("th", null, "Channel"), h("th", null, "TX Power"))),
      h(
        "tbody",
        null,
        interfaces.length
          ? interfaces.map((iface) =>
              h("tr", { key: iface.name }, h("td", null, iface.name), h("td", null, iface.phy), h("td", null, iface.type || "-"), h("td", null, iface.ssid || "-"), h("td", null, iface.channel || "-"), h("td", null, iface.txpower || "-"))
            )
          : h("tr", null, h("td", { colSpan: 6 }, "No active wireless interfaces."))
      )
    );
  }

  function ReconResultsTable({ networks, authorized, onAuthorize, onUnauthorize }) {
    return h(
      Table,
      { striped: true, hover: true, responsive: true, size: "sm", className: "mb-0" },
      h("thead", null, h("tr", null, h("th", null, "SSID"), h("th", null, "BSSID"), h("th", null, "Ch"), h("th", null, "Security"), h("th", null, "Signal"), h("th", null, "Scope"))),
      h(
        "tbody",
        null,
        networks.length
          ? networks.map((net) => {
              const isAuth = Boolean(authorized[net.bssid]);
              return h(
                "tr",
                { key: `${net.bssid}-${net.ssid}`, className: isAuth ? "table-success" : "" },
                h("td", null, net.ssid || h("span", { className: "text-body-secondary" }, "<hidden>")),
                h("td", null, h("code", null, net.bssid), net.vendor ? h("div", null, h("small", { className: "text-body-secondary" }, net.vendor)) : null),
                h("td", null, net.channel || "-"),
                h("td", null, h("small", null, net.security || "-")),
                h("td", null, net.signal || "-"),
                h(
                  "td",
                  null,
                  isAuth
                    ? h(
                        "div",
                        { className: "d-flex gap-1 align-items-center" },
                        h(Badge, { bg: "success" }, "authorized"),
                        h(Button, { size: "sm", variant: "outline-secondary", title: "Remove authorization", onClick: () => onUnauthorize(net.bssid) }, h(Icon, { name: "x" }))
                      )
                    : h(Button, { size: "sm", variant: "outline-warning", onClick: () => onAuthorize(net) }, "Authorize")
                )
              );
            })
          : h("tr", null, h("td", { colSpan: 6 }, "No scan results yet."))
      )
    );
  }


  function ReconPanel({ status, authorized, authorizeTarget, unauthorizeTarget }) {
    const [band, setBand] = React.useState("both");
    const [scan, setScan] = React.useState({ networks: [] });
    const [loading, setLoading] = React.useState(false);
    const [error, setError] = React.useState("");
    const [continuous, setContinuous] = React.useState(false);
    const [rounds, setRounds] = React.useState(0);
    const continuousRef = React.useRef(false);
    React.useEffect(() => () => { continuousRef.current = false; }, []);

    const bandLabel = (b) => (b === "5g" ? "5 GHz" : b === "both" ? "2.4 + 5 GHz" : "2.4 GHz");

    async function waitForOne(job) {
      for (let attempt = 0; attempt < 35; attempt += 1) {
        await sleep(2000);
        const st = await api("scanStatus", { jobId: job.jobId });
        if (!st.pending) {
          return st;
        }
      }
      throw new Error("Scan is still running. Try again in a moment.");
    }

    async function runScan() {
      setLoading(true);
      setError("");
      try {
        const started = await api("scanNetworks", { band });
        const jobs = started.jobs || (started.jobId ? [{ jobId: started.jobId, band: started.band }] : []);
        setScan({ networks: [], message: `Scanning ${bandLabel(band)} on the router…` });
        // Both bands run on separate radios, so poll them in parallel and merge.
        const results = await Promise.all(jobs.map(waitForOne));
        const merged = {};
        const messages = [];
        results.forEach((r) => {
          (r.networks || []).forEach((n) => {
            merged[n.bssid] = n;
          });
          if (r.message) {
            messages.push(r.message);
          }
        });
        setScan({ networks: Object.values(merged), message: messages.length ? messages.join(" · ") : undefined });
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    // Continuous mode: keep re-scanning and ACCUMULATE results (union by BSSID) so a
    // long sweep catches APs/clients that only beacon intermittently. Runs until the
    // operator clicks Stop; a transient failed round is shown but doesn't end the loop.
    async function runContinuous() {
      continuousRef.current = true;
      setContinuous(true);
      setError("");
      setRounds(0);
      const merged = {};
      (scan.networks || []).forEach((n) => {
        merged[n.bssid] = n;
      });
      let round = 0;
      while (continuousRef.current) {
        try {
          const started = await api("scanNetworks", { band });
          const jobs = started.jobs || (started.jobId ? [{ jobId: started.jobId, band: started.band }] : []);
          const results = await Promise.all(jobs.map(waitForOne));
          results.forEach((r) => {
            (r.networks || []).forEach((n) => {
              merged[n.bssid] = n;
            });
          });
          round += 1;
          setRounds(round);
          setScan({ networks: Object.values(merged), message: `Continuous scan — round ${round}, ${Object.keys(merged).length} networks seen so far. Click Stop to finish.` });
        } catch (err) {
          setError(err.message);
        }
        if (!continuousRef.current) break;
        await sleep(1500);
      }
      setContinuous(false);
    }
    function stopContinuous() {
      continuousRef.current = false;
      setContinuous(false);
    }

    const networks = scan.networks || [];
    const authorizedList = Object.values(authorized || {});

    return h(
      Panel,
      {
        title: "Recon Scan",
        icon: "search",
        action: h(Button, { size: "sm", variant: "outline-secondary", onClick: runScan, disabled: loading }, h(Icon, { name: "refresh-cw" })),
      },
      h(
        Alert,
        { variant: "info", className: "py-2" },
        "Results are live only — nothing is saved to disk. Each scan replaces the previous list, and everything clears when you refresh or reopen the module. Mark the networks you own as ",
        h("strong", null, "Authorized"),
        " to unlock the Capture / WPS / Evil Portal tools for them."
      ),
      error ? h(Alert, { variant: "danger", className: "py-2" }, error) : null,
      scan.message ? h(Alert, { variant: "warning", className: "py-2" }, scan.message) : null,
      h(
        Row,
        { className: "g-2 align-items-end mb-3" },
        h(
          Col,
          { md: 3 },
          h(Form.Group, null, h(Form.Label, null, "Band"), h(Form.Select, { value: band, onChange: (event) => setBand(event.target.value), disabled: loading || continuous }, h("option", { value: "2g" }, "2.4 GHz (radio1)"), h("option", { value: "5g" }, "5 GHz (radio0)"), h("option", { value: "both" }, "Both (2.4 + 5 GHz)")))
        ),
        h(Col, { md: "auto" }, h(Button, { onClick: runScan, disabled: loading || continuous }, loading ? h(Spinner, { size: "sm", animation: "border", className: "me-2" }) : h("span", { className: "me-2" }, h(Icon, { name: "activity" })), "Scan once")),
        h(
          Col,
          { md: "auto" },
          continuous
            ? h(Button, { variant: "danger", onClick: stopContinuous }, h("span", { className: "me-2" }, h(Spinner, { size: "sm", animation: "border" })), `Stop (round ${rounds})`)
            : h(Button, { variant: "outline-primary", onClick: runContinuous, disabled: loading }, h("span", { className: "me-2" }, h(Icon, { name: "repeat" })), "Scan continuously")
        ),
        h(Col, { md: "auto", className: "text-body-secondary pb-2" }, `${networks.length} live · ${authorizedList.length} authorized`)
      ),
      h(ReconResultsTable, { networks, authorized: authorized || {}, onAuthorize: authorizeTarget, onUnauthorize: unauthorizeTarget }),
      authorizedList.length
        ? h(
            "div",
            { className: "mt-3" },
            h("div", { className: "fw-semibold mb-2" }, "Authorized targets (this session)"),
            h(
              "div",
              { className: "d-flex flex-wrap gap-2" },
              authorizedList.map((t) =>
                h(
                  Badge,
                  { key: t.bssid, bg: "success", className: "d-flex align-items-center gap-2 p-2" },
                  `${t.ssid || "<hidden>"} · ${t.bssid} · ch ${t.channel || "?"}`,
                  h("span", { role: "button", title: "Remove", style: { cursor: "pointer" }, onClick: () => unauthorizeTarget(t.bssid) }, "✕")
                )
              )
            )
          )
        : null
    );
  }

  function formatBytes(bytes) {
    const value = Number(bytes) || 0;
    if (value < 1024) {
      return `${value} B`;
    }
    if (value < 1024 * 1024) {
      return `${(value / 1024).toFixed(1)} KB`;
    }
    return `${(value / (1024 * 1024)).toFixed(1)} MB`;
  }

  async function downloadCaptureFile(jobId, kind, filename) {
    const response = await fetch(`${window.location.origin}/api/index.php`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json", "X-XSRF-TOKEN": csrfToken() },
      body: JSON.stringify({ module: MODULE, action: "downloadCapture", jobId, kind }),
    });
    if (!response.ok) {
      const json = await response.json().catch(() => ({}));
      throw new Error(json.error || "Download failed");
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  async function downloadFile(action, payload, filename) {
    const response = await fetch(`${window.location.origin}/api/index.php`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json", "X-XSRF-TOKEN": csrfToken() },
      body: JSON.stringify(Object.assign({ module: MODULE, action }, payload || {})),
    });
    if (!response.ok) {
      const json = await response.json().catch(() => ({}));
      throw new Error(json.error || "Download failed");
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  function CaptureResult({ result }) {
    if (!result) {
      return null;
    }
    return h(
      "div",
      { className: "d-flex flex-wrap align-items-center gap-2" },
      h(Badge, { bg: result.handshakeCaptured ? "success" : "secondary" }, result.handshakeCaptured ? `${result.hashCount} hash${result.hashCount === 1 ? "" : "es"} captured` : "No handshake yet"),
      result.pcapAvailable ? h(Badge, { bg: "info" }, `pcap ${formatBytes(result.pcapBytes)}`) : null,
      result.summaryLine ? h("small", { className: "text-body-secondary" }, result.summaryLine) : null
    );
  }

  function CaptureHistoryTable({ history, onDownload, onDelete, onSelect }) {
    return h(
      Table,
      { striped: true, hover: true, responsive: true, size: "sm", className: "mb-0" },
      h("thead", null, h("tr", null, h("th", null, "When"), h("th", null, "Target"), h("th", null, "Ch"), h("th", null, "Result"), h("th", null, "Files"))),
      h(
        "tbody",
        null,
        history.length
          ? history.map((item) => {
              const meta = item.meta || {};
              const target = meta.target || {};
              const result = item.result || {};
              return h(
                "tr",
                { key: item.jobId },
                h("td", null, h("small", null, formatDate(meta.createdAt))),
                h("td", null, h("div", null, target.ssid || "-"), h("small", { className: "text-body-secondary" }, h("code", null, target.bssid || "-"))),
                h("td", null, target.channel || "-"),
                h(
                  "td",
                  null,
                  item.pending
                    ? h(Badge, { bg: "warning" }, "running")
                    : h(Badge, { bg: result.handshakeCaptured ? "success" : "secondary" }, result.handshakeCaptured ? `${result.hashCount} hash` : "none")
                ),
                h(
                  "td",
                  null,
                  h(
                    "div",
                    { className: "d-flex gap-1 flex-wrap" },
                    result.hashAvailable ? h(Button, { size: "sm", variant: "outline-success", title: "Download hashcat 22000", onClick: () => onDownload(item.jobId, "hash", `${item.jobId}.22000`) }, "22000") : null,
                    result.pcapAvailable ? h(Button, { size: "sm", variant: "outline-info", title: "Download pcap", onClick: () => onDownload(item.jobId, "pcap", `${item.jobId}.cap`) }, "pcap") : null,
                    h(Button, { size: "sm", variant: "outline-secondary", title: "View log", onClick: () => onSelect(item.jobId) }, h(Icon, { name: "eye" })),
                    !item.pending ? h(Button, { size: "sm", variant: "outline-danger", title: "Delete", onClick: () => onDelete(item.jobId) }, h(Icon, { name: "trash-2" })) : null
                  )
                )
              );
            })
          : h("tr", null, h("td", { colSpan: 5 }, "No captures yet."))
      )
    );
  }

  function CapturePanel({ status, authorizedTargets, onActivity }) {
    const [targetBssid, setTargetBssid] = React.useState("");
    const [duration, setDuration] = React.useState(45);
    const [deauth, setDeauth] = React.useState(true);
    const [deauthRounds, setDeauthRounds] = React.useState(4);
    const [deauthInterval, setDeauthInterval] = React.useState(6);
    const [deauthDelay, setDeauthDelay] = React.useState(0);
    const [client, setClient] = React.useState("");
    const [running, setRunning] = React.useState(false);
    React.useEffect(() => {
      if (onActivity) onActivity(running);
    }, [running]);
    const [job, setJob] = React.useState(null);
    const [jobStatus, setJobStatus] = React.useState(null);
    const [history, setHistory] = React.useState([]);
    const [error, setError] = React.useState("");
    const cancelRef = React.useRef(false);

    const engineReady =
      toolInstalled(status, "airodump-ng") && toolInstalled(status, "aireplay-ng") && toolInstalled(status, "hcxpcapngtool");
    const selectedTarget = (authorizedTargets || []).find((target) => target.bssid === targetBssid) || null;

    async function loadHistory() {
      try {
        const result = await api("getCaptureHistory");
        setHistory(result.captures || []);
      } catch (err) {
        setError(err.message);
      }
    }

    React.useEffect(() => {
      loadHistory();
    }, []);

    React.useEffect(() => {
      if ((!targetBssid || !(authorizedTargets || []).some((t) => t.bssid === targetBssid)) && (authorizedTargets || [])[0]) {
        setTargetBssid(authorizedTargets[0].bssid);
      }
    }, [authorizedTargets]);

    async function pollUntilDone(jobId) {
      const maxAttempts = Math.ceil(duration / 2) + 40;
      let consecutiveErrors = 0;
      for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
        if (cancelRef.current) {
          break;
        }
        await sleep(2000);
        try {
          const result = await api("captureStatus", { jobId });
          consecutiveErrors = 0;
          setError("");
          setJobStatus(result);
          if (!result.pending) {
            return result;
          }
        } catch (err) {
          // Transient blips are expected while the radio cycles / deauth bursts fire
          // on this small box — keep polling and only surface a persistent outage.
          consecutiveErrors += 1;
          if (consecutiveErrors >= 8) {
            setError("Lost contact with the router while polling (" + err.message + "). The capture may still be running on the device — reopen this tab in a moment to see the result.");
            break;
          }
        }
      }
      return null;
    }

    async function startCapture() {
      if (!selectedTarget) {
        return;
      }
      setRunning(true);
      setError("");
      setJobStatus(null);
      cancelRef.current = false;
      try {
        const started = await api("startCapture", {
          bssid: selectedTarget.bssid,
          ssid: selectedTarget.ssid || "",
          channel: selectedTarget.channel || "",
          security: selectedTarget.security || "",
          authorized: true,
          duration,
          deauth,
          deauthRounds,
          deauthInterval,
          deauthDelay,
          client: client.trim(),
        });
        setJob(started);
        setJobStatus({ pending: true, meta: started.meta, log: "" });
        await pollUntilDone(started.jobId);
      } catch (err) {
        setError(err.message);
      } finally {
        setRunning(false);
        loadHistory();
      }
    }

    async function stopCapture() {
      if (!job) {
        return;
      }
      try {
        await api("stopCapture", { jobId: job.jobId });
      } catch (err) {
        setError(err.message);
      }
    }

    async function viewLog(jobId) {
      try {
        const result = await api("captureStatus", { jobId });
        setJobStatus(result);
      } catch (err) {
        setError(err.message);
      }
    }

    async function removeCapture(jobId) {
      try {
        await api("deleteCapture", { jobId });
        loadHistory();
      } catch (err) {
        setError(err.message);
      }
    }

    async function download(jobId, kind, filename) {
      setError("");
      try {
        await downloadCaptureFile(jobId, kind, filename);
      } catch (err) {
        setError(err.message);
      }
    }

    return h(
      Panel,
      {
        title: "PMKID / Handshake Capture",
        icon: "target",
        action: h(Button, { size: "sm", variant: "outline-secondary", onClick: loadHistory, disabled: running }, h(Icon, { name: "refresh-cw" })),
      },
      h(
        Alert,
        { variant: "warning", className: "py-2" },
        h("strong", null, "Authorized use only. "),
        "Capture switches the matching radio into monitor mode for the run and sends deauth frames to the selected BSSID. If that radio is this router's WiFi uplink, internet drops until the capture finishes and the radio is restored (management stays up over LAN)."
      ),
      error ? h(Alert, { variant: "danger", className: "py-2" }, error) : null,
      !engineReady
        ? h(Alert, { variant: "secondary", className: "py-2" }, "Capture engine incomplete. Needs airodump-ng, aireplay-ng and hcxpcapngtool installed.")
        : authorizedTargets.length === 0
        ? h(Alert, { variant: "info", className: "py-2" }, "No authorized targets. Select a target in the Recon panel and mark it as an ", h("em", null, "Authorized lab target"), " to enable capture.")
        : h(
            React.Fragment,
            null,
            h(
              Row,
              { className: "g-2 align-items-end mb-3" },
              h(
                Col,
                { md: 4 },
                h(Form.Group, null, h(Form.Label, null, "Authorized target"), h(Form.Select, { value: targetBssid, onChange: (event) => setTargetBssid(event.target.value), disabled: running }, authorizedTargets.map((target) => h("option", { key: target.bssid, value: target.bssid }, `${target.ssid || "<hidden>"} — ${target.bssid} (ch ${target.channel || "?"})`))))
              ),
              h(
                Col,
                { md: 3 },
                h(Form.Group, null, h(Form.Label, null, `Duration: ${duration}s`), h(Form.Range, { min: 15, max: 120, step: 5, value: duration, onChange: (event) => setDuration(Number(event.target.value)), disabled: running }))
              ),
              h(
                Col,
                { md: 3 },
                h(Form.Group, null, h(Form.Label, null, "Client MAC (optional)"), h(Form.Control, { placeholder: "aa:bb:cc:dd:ee:ff", value: client, maxLength: 17, onChange: (event) => setClient(event.target.value), disabled: running }))
              ),
              h(
                Col,
                { md: 2 },
                h(Form.Check, { type: "switch", id: "capture-deauth", label: "Send deauth", checked: deauth, onChange: (event) => setDeauth(event.target.checked), disabled: running })
              )
            ),
            deauth
              ? h(
                  "div",
                  { className: "border rounded p-2 mb-3 bg-body-tertiary" },
                  h(
                    "div",
                    { className: "d-flex align-items-center justify-content-between mb-2" },
                    h("small", { className: "fw-semibold text-body-secondary" }, h(Icon, { name: "zap" }), " Deauth cadence"),
                    h(
                      Button,
                      {
                        size: "sm",
                        variant: "outline-secondary",
                        disabled: running,
                        onClick: () => { setDeauthRounds(3); setDeauthInterval(15); setDeauthDelay(10); },
                        title: "Small bursts with long listen gaps — avoids the flood that zeroes the handshake/PMKID",
                      },
                      "Gentle preset"
                    )
                  ),
                  h(
                    Row,
                    { className: "g-2" },
                    h(
                      Col,
                      { md: 4 },
                      h(Form.Group, null, h(Form.Label, null, h("small", null, `Burst size: ${deauthRounds} rounds`)), h(Form.Range, { min: 1, max: 32, step: 1, value: deauthRounds, onChange: (e) => setDeauthRounds(Number(e.target.value)), disabled: running }))
                    ),
                    h(
                      Col,
                      { md: 4 },
                      h(Form.Group, null, h(Form.Label, null, h("small", null, `Interval: every ${deauthInterval}s`)), h(Form.Range, { min: 3, max: 60, step: 1, value: deauthInterval, onChange: (e) => setDeauthInterval(Number(e.target.value)), disabled: running }))
                    ),
                    h(
                      Col,
                      { md: 4 },
                      h(Form.Group, null, h(Form.Label, null, h("small", null, `Listen first: ${deauthDelay}s`)), h(Form.Range, { min: 0, max: Math.max(0, duration - 5), step: 1, value: deauthDelay, onChange: (e) => setDeauthDelay(Number(e.target.value)), disabled: running }))
                    )
                  ),
                  h(
                    "small",
                    { className: "text-body-secondary" },
                    `Sends --deauth ${deauthRounds} ${client.trim() ? "at the target client" : "(broadcast — set a client MAC for reliable, quieter deauth)"} every ${deauthInterval}s${deauthDelay > 0 ? `, after listening ${deauthDelay}s first` : ""}. Big bursts on a short interval flood the AP and can zero the handshake — keep it small unless a client refuses to reconnect.`
                  )
                )
              : null,
            h(
              "div",
              { className: "d-flex align-items-center gap-2 mb-3" },
              running
                ? h(Button, { variant: "danger", onClick: stopCapture }, h("span", { className: "me-2" }, h(Spinner, { size: "sm", animation: "border" })), "Stop Capture")
                : h(Button, { variant: "primary", onClick: startCapture, disabled: !selectedTarget }, h("span", { className: "me-2" }, h(Icon, { name: "target" })), "Start Capture"),
              selectedTarget ? h("small", { className: "text-body-secondary" }, `Target locked to ${selectedTarget.bssid} on channel ${selectedTarget.channel || "?"}`) : null
            ),
            jobStatus
              ? h(
                  "div",
                  { className: "border rounded p-2 mb-3" },
                  h(
                    "div",
                    { className: "d-flex align-items-center justify-content-between mb-2" },
                    h("div", { className: "fw-semibold" }, jobStatus.pending ? "Capture in progress…" : "Capture finished"),
                    h(CaptureResult, { result: jobStatus.result })
                  ),
                  h(OutcomeBanner, { reason: jobStatus.stopReason }),
                  h(StepTimeline, { steps: jobStatus.steps }),
                  !jobStatus.pending && jobStatus.result && jobStatus.result.handshakeCaptured
                    ? h(
                        "div",
                        { className: "d-flex gap-2 mb-2" },
                        jobStatus.result.hashAvailable ? h(Button, { size: "sm", variant: "outline-success", onClick: () => download(job ? job.jobId : jobStatus.jobId, "hash", `${(job && job.jobId) || jobStatus.jobId}.22000`) }, "Download 22000") : null,
                        jobStatus.result.pcapAvailable ? h(Button, { size: "sm", variant: "outline-info", onClick: () => download(job ? job.jobId : jobStatus.jobId, "pcap", `${(job && job.jobId) || jobStatus.jobId}.cap`) }, "Download pcap") : null
                      )
                    : null,
                  h(RawLog, { log: jobStatus.log, error: jobStatus.error })
                )
              : null
          ),
      h("div", { className: "fw-semibold mt-2 mb-2" }, "Capture History"),
      h(CaptureHistoryTable, { history, onDownload: download, onDelete: removeCapture, onSelect: viewLog })
    );
  }

  function ClientlessPanel({ status, authorizedTargets, onActivity }) {
    const [targetBssid, setTargetBssid] = React.useState("");
    const [mode, setMode] = React.useState("pmkid");
    const [duration, setDuration] = React.useState(60);
    const [running, setRunning] = React.useState(false);
    const [job, setJob] = React.useState(null);
    const [jobStatus, setJobStatus] = React.useState(null);
    const [error, setError] = React.useState("");
    const cancelRef = React.useRef(false);
    React.useEffect(() => {
      if (onActivity) onActivity(running);
    }, [running]);

    // 2.4 GHz = true clientless PMKID via hcxdumptool, scoped to the one target by a
    // compiled BPF filter (the scoping is what keeps it safe/stable on this radio).
    // 5 GHz = passive aircrack fallback (ath10k can't inject in monitor mode).
    const targets = authorizedTargets || [];
    const selectedTarget = targets.find((t) => t.bssid === targetBssid) || null;
    const is5g = selectedTarget && Number(selectedTarget.channel) > 14;
    const engineReady = is5g
      ? toolInstalled(status, "airodump-ng") && toolInstalled(status, "aireplay-ng") && toolInstalled(status, "hcxpcapngtool")
      : toolInstalled(status, "hcxdumptool") && toolInstalled(status, "hcxpcapngtool");

    React.useEffect(() => {
      if ((!targetBssid || !targets.some((t) => t.bssid === targetBssid)) && targets[0]) {
        setTargetBssid(targets[0].bssid);
      }
    }, [authorizedTargets]);

    async function pollUntilDone(jobId) {
      const maxAttempts = Math.ceil(duration / 2) + 40;
      let consecutiveErrors = 0;
      for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
        if (cancelRef.current) break;
        await sleep(2500);
        try {
          const st = await api("clientlessStatus", { jobId });
          consecutiveErrors = 0;
          setError("");
          setJobStatus(st);
          if (!st.pending) break;
        } catch (err) {
          // A running capture briefly cycles the radio (5 GHz does a wifi down/up,
          // and deauth bursts can stall this small box for a beat), so an occasional
          // status poll misses the router. Tolerate transient blips and keep polling
          // — the capture runs on the router regardless of what the UI can reach.
          consecutiveErrors += 1;
          if (consecutiveErrors >= 8) {
            setError("Lost contact with the router while polling (" + err.message + "). The capture may still be running on the device — reopen this tab in a moment to see the result.");
            break;
          }
        }
      }
    }

    async function start() {
      if (!selectedTarget) return;
      setRunning(true);
      setError("");
      setJobStatus(null);
      cancelRef.current = false;
      try {
        const started = await api("startClientless", {
          bssid: selectedTarget.bssid,
          ssid: selectedTarget.ssid || "",
          channel: selectedTarget.channel || "",
          security: selectedTarget.security || "",
          authorized: true,
          duration,
          mode,
        });
        setJob(started);
        setJobStatus({ pending: true, meta: started.meta, counts: { pmkid: 0, eapol: 0 }, result: {} });
        await pollUntilDone(started.jobId);
      } catch (err) {
        setError(err.message);
      } finally {
        setRunning(false);
      }
    }

    async function stop() {
      cancelRef.current = true;
      if (job) {
        try {
          await api("stopClientless", { jobId: job.jobId });
        } catch (err) {
          setError(err.message);
        }
      }
    }

    async function download(kind) {
      if (!job) return;
      try {
        await downloadFile("downloadCapture", { jobId: job.jobId, kind }, kind === "pcap" ? `${job.jobId}.cap` : `${job.jobId}.22000`);
      } catch (err) {
        setError(err.message);
      }
    }

    const counts = (jobStatus && jobStatus.counts) || { pmkid: 0, eapol: 0 };
    const result = (jobStatus && jobStatus.result) || {};
    const got = result.handshakeCaptured || counts.pmkid > 0 || counts.eapol > 0;

    return h(
      Panel,
      { title: "Clientless Assault", icon: "crosshair" },
      h(
        Alert,
        { variant: "warning", className: "py-2" },
        h("strong", null, "Authorized targets only. "),
        is5g
          ? h(React.Fragment, null,
              "5 GHz target: uses the passive aircrack engine (this radio can't inject), so it grabs a ",
              h("strong", null, "PMKID or handshake"),
              " when a client (re)associates. ",
              h("strong", null, "PMKID + handshake"),
              " nudges a reconnect with a light deauth.")
          : h(React.Fragment, null,
              "2.4 GHz target: ",
              h("strong", null, "true clientless PMKID"),
              " — hcxdumptool associates to the AP itself and grabs the PMKID with no client needed, ",
              h("strong", null, "scoped to this one BSSID by a compiled BPF filter"),
              " so neighbours are never touched. ",
              h("strong", null, "PMKID only"),
              " sends no deauth (gentle); ",
              h("strong", null, "PMKID + handshake"),
              " also runs the client-side EAPOL attack for a 4-way handshake."),
        " Results drop straight into ",
        h("strong", null, "Crack Lab"),
        ". The run briefly puts the 2.4 GHz radio into monitor mode (its other Wi-Fi networks pause, then restore); it does not touch the 5 GHz internet uplink."
      ),
      error ? h(Alert, { variant: "danger", className: "py-2" }, error) : null,
      !engineReady ? h(Alert, { variant: "secondary", className: "py-2" }, is5g ? "airodump-ng / aireplay-ng / hcxpcapngtool not installed — 5 GHz capture unavailable." : "hcxdumptool / hcxpcapngtool not installed — clientless attack unavailable.") : null,
      is5g
        ? h(Alert, { variant: "info", className: "py-2" }, h(Icon, { name: "info" }), " 5 GHz target: the 5 GHz radio is your internet uplink, so ", h("strong", null, "switch to Lab mode first"), " (Radio Control) — it drops internet for the run.")
        : null,
      targets.length === 0
        ? h(Alert, { variant: "info", className: "py-2" }, "No authorized targets. Mark a network you own as authorized in Recon or WPS first.")
        : h(
            React.Fragment,
            null,
            h(
              Row,
              { className: "g-2 align-items-end mb-3" },
              h(Col, { md: 4 }, h(Form.Group, null, h(Form.Label, null, "Authorized target"), h(Form.Select, { value: targetBssid, onChange: (e) => setTargetBssid(e.target.value), disabled: running }, targets.map((t) => h("option", { key: t.bssid, value: t.bssid }, `${t.ssid || "<hidden>"} — ${t.bssid} (ch ${t.channel || "?"})`))))),
              h(Col, { md: 4 }, h(Form.Group, null, h(Form.Label, null, "Mode"), h(Form.Select, { value: mode, onChange: (e) => setMode(e.target.value), disabled: running }, h("option", { value: "pmkid" }, "PMKID only (no deauth, gentle)"), h("option", { value: "full" }, "PMKID + handshake (deauths target's clients)")))),
              h(Col, { md: 4 }, h(Form.Group, null, h(Form.Label, null, `Duration: ${duration}s`), h(Form.Range, { min: 15, max: 180, step: 5, value: duration, onChange: (e) => setDuration(Number(e.target.value)), disabled: running })))
            ),
            h(
              "div",
              { className: "d-flex align-items-center gap-2 mb-3" },
              running
                ? h(Button, { variant: "danger", onClick: stop }, h("span", { className: "me-2" }, h(Spinner, { size: "sm", animation: "border" })), "Stop")
                : h(Button, { variant: "primary", onClick: start, disabled: !selectedTarget || !engineReady }, h("span", { className: "me-2" }, h(Icon, { name: "crosshair" })), "Start Clientless Attack"),
              selectedTarget ? h("small", { className: "text-body-secondary" }, `${is5g ? "airodump-ng" : "hcxdumptool"} ${mode} on ${selectedTarget.bssid} ch ${selectedTarget.channel || "?"}`) : null
            ),
            jobStatus
              ? h(
                  "div",
                  { className: "border rounded p-2 mb-2" },
                  h(
                    "div",
                    { className: "d-flex align-items-center justify-content-between mb-2" },
                    h("div", { className: "fw-semibold" }, jobStatus.pending ? "Attacking…" : got ? "Captured" : "Finished — nothing captured"),
                    h(
                      "div",
                      { className: "d-flex gap-1" },
                      h(Badge, { bg: counts.pmkid > 0 ? "success" : "secondary" }, `PMKID: ${counts.pmkid}`),
                      h(Badge, { bg: counts.eapol > 0 ? "success" : "secondary" }, `EAPOL: ${counts.eapol}`),
                      h(Badge, { bg: result.hashCount > 0 ? "success" : "secondary" }, `hashes: ${result.hashCount || 0}`)
                    )
                  ),
                  got
                    ? h(Alert, { variant: "success", className: "py-2 mb-2" }, h(Icon, { name: "check-circle" }), " Hash captured. It's now a source in ", h("strong", null, "Crack Lab"), " — run a dictionary attack there, or download the 22000 hash for offline cracking.")
                    : jobStatus.pending
                    ? null
                    : h(Alert, { variant: "warning", className: "py-2 mb-2" }, "No PMKID/EAPOL captured. This AP may not expose a PMKID — try ", h("strong", null, "PMKID + handshake"), " mode (needs a client to reconnect), a longer duration, or move closer."),
                  jobStatus.hashline ? h("div", { className: "mb-2" }, h("small", { className: "text-body-secondary" }, "hashline (22000):"), h("pre", { className: "mb-0 p-2 bg-body-tertiary rounded", style: { overflowX: "auto", fontSize: "0.72rem" } }, jobStatus.hashline)) : null,
                  !jobStatus.pending && (result.hashAvailable || result.pcapAvailable)
                    ? h(
                        "div",
                        { className: "d-flex gap-2 mb-2" },
                        result.hashAvailable ? h(Button, { size: "sm", variant: "outline-primary", onClick: () => download("hash") }, h(Icon, { name: "download" }), " .22000 hash") : null,
                        result.pcapAvailable ? h(Button, { size: "sm", variant: "outline-secondary", onClick: () => download("pcap") }, h(Icon, { name: "download" }), " .cap") : null
                      )
                    : null,
                  h(RawLog, { log: jobStatus.log, error: jobStatus.error })
                )
              : null
          )
    );
  }

  function signalVariant(sig) {
    const v = parseInt(sig, 10);
    if (isNaN(v)) return "secondary";
    if (v >= -60) return "success";
    if (v >= -75) return "warning";
    return "danger";
  }

  function WpsDiscoveredTable({ networks, authorizedMap, onAuthorize, onUnauthorize }) {
    return h(
      Table,
      { striped: true, hover: true, responsive: true, size: "sm", className: "mb-0" },
      h("thead", null, h("tr", null, h("th", null, "SSID"), h("th", null, "BSSID"), h("th", null, "Ch"), h("th", null, "Signal"), h("th", null, "WPS"), h("th", null, "Locked"), h("th", null, "Scope"))),
      h(
        "tbody",
        null,
        networks.length
          ? networks.map((net) => {
              const authorized = Boolean(authorizedMap[net.bssid]);
              return h(
                "tr",
                { key: net.bssid },
                h("td", null, net.ssid || "<hidden>"),
                h("td", null, h("code", null, net.bssid), net.vendor ? h("div", null, h("small", { className: "text-body-secondary" }, net.vendor)) : null),
                h("td", null, net.channel || "-"),
                h("td", null, net.signal ? h(Badge, { bg: signalVariant(net.signal) }, net.signal) : h("small", { className: "text-body-secondary" }, "—")),
                h("td", null, h(Badge, { bg: "info" }, `v${net.wpsVersion || "?"}`)),
                h("td", null, net.wpsLocked ? h(Badge, { bg: "danger" }, "locked") : h(Badge, { bg: "success" }, "open")),
                h(
                  "td",
                  null,
                  authorized
                    ? h(
                        "div",
                        { className: "d-flex gap-1 align-items-center" },
                        h(Badge, { bg: "success" }, "authorized"),
                        h(Button, { size: "sm", variant: "outline-secondary", title: "Remove authorization", onClick: () => onUnauthorize(net.bssid) }, h(Icon, { name: "x" }))
                      )
                    : h(Button, { size: "sm", variant: "outline-warning", onClick: () => onAuthorize(net) }, "Mark mine")
                )
              );
            })
          : h("tr", null, h("td", { colSpan: 7 }, "No WPS-enabled APs discovered yet."))
      )
    );
  }

  function WpsResult({ result }) {
    if (!result) {
      return null;
    }
    return h(
      "div",
      { className: "d-flex flex-wrap align-items-center gap-2" },
      h(Badge, { bg: result.success ? "success" : "secondary" }, result.success ? "recovered" : "no result yet"),
      result.pin ? h(Badge, { bg: "success" }, `PIN: ${result.pin}`) : null,
      result.psk ? h(Badge, { bg: "success" }, `PSK: ${result.psk}`) : null,
      result.locked ? h(Badge, { bg: "danger" }, "AP locked / rate-limited") : null
    );
  }

  function WpsPanel({ status, authorized, authorizeTarget, unauthorizeTarget, onActivity }) {
    const [band, setBand] = React.useState("2g");
    const [scanDuration, setScanDuration] = React.useState(30);
    const [scanning, setScanning] = React.useState(false);
    const [discovered, setDiscovered] = React.useState([]);
    const [attackBssid, setAttackBssid] = React.useState("");
    const [mode, setMode] = React.useState("pixie");
    const [pin, setPin] = React.useState("");
    const [timeout, setTimeoutVal] = React.useState(120);
    const [running, setRunning] = React.useState(false);
    const [attackJob, setAttackJob] = React.useState(null);
    const [attackStatus, setAttackStatus] = React.useState(null);
    const [history, setHistory] = React.useState([]);
    const [error, setError] = React.useState("");
    const cancelRef = React.useRef(false);
    React.useEffect(() => {
      if (onActivity) onActivity(running || scanning);
    }, [running, scanning]);

    const authorizedMap = authorized || {};
    const reaverReady = toolInstalled(status, "reaver");
    const authorizedWpsTargets = Object.values(authorizedMap).filter((target) => target.wps);
    const selected = authorizedWpsTargets.find((t) => t.bssid === attackBssid) || null;

    async function loadHistory() {
      try {
        setHistory((await api("getWpsHistory")).attacks || []);
      } catch (err) {
        setError(err.message);
      }
    }
    React.useEffect(() => {
      loadHistory();
    }, []);
    React.useEffect(() => {
      if ((!attackBssid || !authorizedWpsTargets.some((t) => t.bssid === attackBssid)) && authorizedWpsTargets[0]) {
        setAttackBssid(authorizedWpsTargets[0].bssid);
      }
    }, [authorizedMap]);

    async function runScan() {
      setScanning(true);
      setError("");
      setDiscovered([]);
      try {
        const started = await api("wpsScan", { band, duration: scanDuration });
        const maxAttempts = Math.ceil(scanDuration / 3) + 20;
        for (let i = 0; i < maxAttempts; i += 1) {
          await sleep(3000);
          const st = await api("wpsScanStatus", { jobId: started.jobId });
          if (!st.pending) {
            setDiscovered(st.networks || []);
            break;
          }
        }
      } catch (err) {
        setError(err.message);
      } finally {
        setScanning(false);
      }
    }

    function authorize(net) {
      authorizeTarget({
        bssid: net.bssid,
        ssid: net.ssid || "",
        channel: net.channel || "",
        band: Number(net.channel) > 14 ? "5g" : "2g",
        wps: { enabled: true, version: net.wpsVersion, locked: net.wpsLocked },
      });
    }

    async function startAttack() {
      if (!selected) {
        return;
      }
      setRunning(true);
      setError("");
      setAttackStatus(null);
      cancelRef.current = false;
      try {
        const started = await api("startWpsAttack", { bssid: selected.bssid, ssid: selected.ssid || "", channel: selected.channel || "", authorized: true, mode, pin: pin.trim(), timeout });
        setAttackJob(started);
        setAttackStatus({ pending: true, meta: started.meta, log: "" });
        const maxAttempts = Math.ceil(timeout / 2) + 30;
        for (let i = 0; i < maxAttempts; i += 1) {
          if (cancelRef.current) break;
          await sleep(2000);
          const st = await api("wpsAttackStatus", { jobId: started.jobId });
          setAttackStatus(st);
          if (!st.pending) break;
        }
      } catch (err) {
        setError(err.message);
      } finally {
        setRunning(false);
        loadHistory();
      }
    }

    async function stopAttack() {
      if (!attackJob) return;
      try {
        await api("stopWpsAttack", { jobId: attackJob.jobId });
      } catch (err) {
        setError(err.message);
      }
    }
    async function removeResult(jobId) {
      try {
        await api("deleteWpsResult", { jobId });
        loadHistory();
      } catch (err) {
        setError(err.message);
      }
    }

    return h(
      Panel,
      {
        title: "WPS Assessment",
        icon: "key",
        action: h(Button, { size: "sm", variant: "outline-secondary", onClick: loadHistory, disabled: scanning || running }, h(Icon, { name: "refresh-cw" })),
      },
      h(
        Alert,
        { variant: "warning", className: "py-2" },
        h("strong", null, "Authorized targets only. "),
        "WPS discovery is passive (beacon parsing). A WPS attack (reaver) actively probes one AP and only runs on a target you have marked as owned/authorized. Discovery uses radio1 (2.4GHz) with no uplink impact; a 5GHz attack briefly uses the uplink radio."
      ),
      error ? h(Alert, { variant: "danger", className: "py-2" }, error) : null,
      !reaverReady ? h(Alert, { variant: "secondary", className: "py-2" }, "reaver is not installed; attacks are unavailable (discovery still works).") : null,
      h("div", { className: "fw-semibold mb-2" }, "1. Discover WPS APs"),
      h(
        Row,
        { className: "g-2 align-items-end mb-2" },
        h(Col, { md: 3 }, h(Form.Group, null, h(Form.Label, null, "Band"), h(Form.Select, { value: band, onChange: (e) => setBand(e.target.value), disabled: scanning }, h("option", { value: "2g" }, "2.4 GHz (radio1)"), h("option", { value: "5g" }, "5 GHz (uplink radio)"), h("option", { value: "both" }, "Both (2.4 + 5 GHz)")))),
        h(Col, { md: 3 }, h(Form.Group, null, h(Form.Label, null, `Scan: ${scanDuration}s`), h(Form.Range, { min: 10, max: 90, step: 5, value: scanDuration, onChange: (e) => setScanDuration(Number(e.target.value)), disabled: scanning }))),
        h(Col, { md: "auto" }, h(Button, { onClick: runScan, disabled: scanning }, scanning ? h(Spinner, { size: "sm", animation: "border", className: "me-2" }) : h("span", { className: "me-2" }, h(Icon, { name: "search" })), "Scan WPS"))
      ),
      h(WpsDiscoveredTable, { networks: discovered, authorizedMap, onAuthorize: authorize, onUnauthorize: unauthorizeTarget }),
      h("div", { className: "fw-semibold mt-3 mb-2" }, "2. Attack an authorized WPS target"),
      authorizedWpsTargets.length === 0
        ? h(Alert, { variant: "info", className: "py-2" }, "No authorized WPS targets. Scan, then use ", h("em", null, "Mark mine"), " on an AP you own to enable the attack.")
        : h(
            React.Fragment,
            null,
            h(
              Row,
              { className: "g-2 align-items-end mb-3" },
              h(Col, { md: 4 }, h(Form.Group, null, h(Form.Label, null, "Target"), h(Form.Select, { value: attackBssid, onChange: (e) => setAttackBssid(e.target.value), disabled: running }, authorizedWpsTargets.map((t) => h("option", { key: t.bssid, value: t.bssid }, `${t.ssid || "<hidden>"} — ${t.bssid} (ch ${t.channel || "?"})`))))),
              h(Col, { md: 3 }, h(Form.Group, null, h(Form.Label, null, "Mode"), h(Form.Select, { value: mode, onChange: (e) => setMode(e.target.value), disabled: running }, h("option", { value: "pixie" }, "Pixie-Dust (offline)"), h("option", { value: "pin" }, "PIN (online)")))),
              mode === "pin" ? h(Col, { md: 2 }, h(Form.Group, null, h(Form.Label, null, "PIN (optional)"), h(Form.Control, { placeholder: "8 digits", value: pin, maxLength: 8, onChange: (e) => setPin(e.target.value), disabled: running }))) : null,
              h(Col, { md: 2 }, h(Form.Group, null, h(Form.Label, null, `Timeout: ${timeout}s`), h(Form.Range, { min: 30, max: 600, step: 30, value: timeout, onChange: (e) => setTimeoutVal(Number(e.target.value)), disabled: running })))
            ),
            h(
              "div",
              { className: "d-flex align-items-center gap-2 mb-3" },
              running
                ? h(Button, { variant: "danger", onClick: stopAttack }, h("span", { className: "me-2" }, h(Spinner, { size: "sm", animation: "border" })), "Stop Attack")
                : h(Button, { variant: "primary", onClick: startAttack, disabled: !selected }, h("span", { className: "me-2" }, h(Icon, { name: "key" })), "Start WPS Attack"),
              selected ? h("small", { className: "text-body-secondary" }, `reaver ${mode} on ${selected.bssid} ch ${selected.channel || "?"}`) : null
            ),
            attackStatus
              ? h(
                  "div",
                  { className: "border rounded p-2 mb-3" },
                  h(
                    "div",
                    { className: "d-flex align-items-center justify-content-between mb-2" },
                    h(
                      "div",
                      { className: "fw-semibold" },
                      attackStatus.pending ? "Attack running…" : "Attack finished",
                      attackStatus.pending && attackStatus.timeoutSec
                        ? h("span", { className: "ms-2 text-body-secondary fw-normal small" }, `auto-stops in ${Math.max(0, (attackStatus.timeoutSec || 0) - (attackStatus.elapsedSec || 0))}s (${attackStatus.elapsedSec || 0}/${attackStatus.timeoutSec}s)`)
                        : null,
                      !attackStatus.pending && attackStatus.timedOut ? h(Badge, { bg: "secondary", className: "ms-2" }, "timed out") : null
                    ),
                    h(WpsResult, { result: attackStatus.result })
                  ),
                  attackStatus.pending && attackStatus.timeoutSec
                    ? h(
                        "div",
                        { className: "progress mb-2", style: { height: "4px" } },
                        h("div", {
                          className: "progress-bar",
                          role: "progressbar",
                          style: { width: `${Math.min(100, Math.round(((attackStatus.elapsedSec || 0) / attackStatus.timeoutSec) * 100))}%` },
                        })
                      )
                    : null,
                  h(OutcomeBanner, { reason: attackStatus.stopReason }),
                  h(StepTimeline, { steps: attackStatus.steps }),
                  h(RawLog, { log: attackStatus.log, error: attackStatus.error, open: true, label: "Live reaver output" })
                )
              : null
          ),
      h("div", { className: "fw-semibold mt-2 mb-2" }, "WPS Attack History"),
      h(
        Table,
        { striped: true, hover: true, responsive: true, size: "sm", className: "mb-0" },
        h("thead", null, h("tr", null, h("th", null, "When"), h("th", null, "Target"), h("th", null, "Mode"), h("th", null, "Result"), h("th", null, ""))),
        h(
          "tbody",
          null,
          history.length
            ? history.map((item) => {
                const meta = item.meta || {};
                const t = meta.target || {};
                const r = item.result || {};
                return h(
                  "tr",
                  { key: item.jobId },
                  h("td", null, h("small", null, formatDate(meta.createdAt))),
                  h("td", null, h("div", null, t.ssid || "-"), h("small", { className: "text-body-secondary" }, h("code", null, t.bssid || "-"))),
                  h("td", null, meta.mode || "-"),
                  h("td", null, item.pending ? h(Badge, { bg: "warning" }, "running") : r.success ? h(Badge, { bg: "success" }, r.pin ? `PIN ${r.pin}` : "recovered") : h(Badge, { bg: "secondary" }, "none")),
                  h("td", null, !item.pending ? h(Button, { size: "sm", variant: "outline-danger", onClick: () => removeResult(item.jobId) }, h(Icon, { name: "trash-2" })) : null)
                );
              })
            : h("tr", null, h("td", { colSpan: 5 }, "No WPS attacks yet."))
        )
      )
    );
  }

  function BeaconPanel({ status, onActivity }) {
    const [band, setBand] = React.useState("2g");
    const [duration, setDuration] = React.useState(45);
    const [running, setRunning] = React.useState(false);
    const [job, setJob] = React.useState(null);
    const [result, setResult] = React.useState(null);
    const [error, setError] = React.useState("");
    const cancelRef = React.useRef(false);
    React.useEffect(() => {
      if (onActivity) onActivity(running);
    }, [running]);

    const ready = toolInstalled(status, "airodump-ng");
    const aps = (result && result.aps) || [];
    const clients = (result && result.clients) || [];

    function clientCountFor(bssid) {
      return clients.filter((c) => c.bssid === bssid).length;
    }

    async function startHarvest() {
      setRunning(true);
      setError("");
      setResult(null);
      cancelRef.current = false;
      try {
        const started = await api("startBeaconHarvest", { band, duration });
        setJob(started);
        const maxAttempts = Math.ceil(duration / 3) + 25;
        for (let i = 0; i < maxAttempts; i += 1) {
          if (cancelRef.current) break;
          await sleep(3000);
          const st = await api("beaconHarvestStatus", { jobId: started.jobId });
          setResult(st);
          if (!st.pending) break;
        }
      } catch (err) {
        setError(err.message);
      } finally {
        setRunning(false);
      }
    }

    async function stopHarvest() {
      if (!job) return;
      try {
        await api("stopBeaconHarvest", { jobId: job.jobId });
      } catch (err) {
        setError(err.message);
      }
    }

    return h(
      Panel,
      { title: "Beacon Harvesting", icon: "rss" },
      h(
        Alert,
        { variant: "info", className: "py-2" },
        "Passive channel-hopping capture of nearby APs and clients (no deauth, no injection). 2.4GHz uses radio1 with no uplink impact; 5GHz uses the uplink radio and briefly drops internet."
      ),
      error ? h(Alert, { variant: "danger", className: "py-2" }, error) : null,
      !ready ? h(Alert, { variant: "secondary", className: "py-2" }, "airodump-ng is not installed; harvesting is unavailable.") : null,
      h(
        Row,
        { className: "g-2 align-items-end mb-3" },
        h(Col, { md: 3 }, h(Form.Group, null, h(Form.Label, null, "Band"), h(Form.Select, { value: band, onChange: (e) => setBand(e.target.value), disabled: running }, h("option", { value: "2g" }, "2.4 GHz (radio1)"), h("option", { value: "5g" }, "5 GHz (uplink radio)"), h("option", { value: "both" }, "Both (2.4 + 5 GHz)")))),
        h(Col, { md: 3 }, h(Form.Group, null, h(Form.Label, null, `Duration: ${duration}s`), h(Form.Range, { min: 15, max: 180, step: 15, value: duration, onChange: (e) => setDuration(Number(e.target.value)), disabled: running }))),
        h(
          Col,
          { md: "auto" },
          running
            ? h(Button, { variant: "danger", onClick: stopHarvest }, h("span", { className: "me-2" }, h(Spinner, { size: "sm", animation: "border" })), "Stop")
            : h(Button, { onClick: startHarvest, disabled: !ready }, h("span", { className: "me-2" }, h(Icon, { name: "rss" })), "Harvest")
        ),
        result ? h(Col, { md: "auto", className: "text-body-secondary pb-2" }, `${result.apCount || aps.length} APs · ${result.clientCount || clients.length} clients${result.pending ? " (running…)" : ""}`) : null
      ),
      h(
        Row,
        { className: "g-3" },
        h(
          Col,
          { lg: 7 },
          h("div", { className: "fw-semibold mb-2" }, "Access Points"),
          h(
            Table,
            { striped: true, hover: true, responsive: true, size: "sm", className: "mb-0" },
            h("thead", null, h("tr", null, h("th", null, "SSID"), h("th", null, "BSSID"), h("th", null, "Ch"), h("th", null, "Security"), h("th", null, "Signal"), h("th", null, "WPS"), h("th", null, "Clients"))),
            h(
              "tbody",
              null,
              aps.length
                ? aps
                    .slice()
                    .sort((a, b) => clientCountFor(b.bssid) - clientCountFor(a.bssid))
                    .slice(0, 60)
                    .map((ap) =>
                      h(
                        "tr",
                        { key: ap.bssid },
                        h("td", null, ap.ssid || "<hidden>"),
                        h("td", null, h("code", null, ap.bssid), ap.vendor ? h("div", null, h("small", { className: "text-body-secondary" }, ap.vendor)) : null),
                        h("td", null, ap.channel || "-"),
                        h("td", null, h("small", null, ap.security || "-")),
                        h("td", null, ap.signal || "-"),
                        h("td", null, ap.wps ? h(Badge, { bg: ap.wps.locked ? "danger" : "info" }, ap.wps.locked ? "locked" : `v${ap.wps.version || "?"}`) : h("span", { className: "text-body-secondary" }, "-")),
                        h("td", null, clientCountFor(ap.bssid) || "-")
                      )
                    )
                : h("tr", null, h("td", { colSpan: 7 }, running ? "Harvesting…" : "No APs harvested yet."))
            )
          )
        ),
        h(
          Col,
          { lg: 5 },
          h("div", { className: "fw-semibold mb-2" }, "Clients"),
          h(
            Table,
            { striped: true, hover: true, responsive: true, size: "sm", className: "mb-0" },
            h("thead", null, h("tr", null, h("th", null, "Client MAC"), h("th", null, "Associated AP"), h("th", null, "Probes"))),
            h(
              "tbody",
              null,
              clients.length
                ? clients.slice(0, 60).map((c) =>
                    h(
                      "tr",
                      { key: c.mac },
                      h("td", null, h("code", null, c.mac), c.vendor ? h("div", null, h("small", { className: "text-body-secondary" }, c.vendor)) : null),
                      h("td", null, c.bssid ? h("code", null, c.bssid) : h("span", { className: "text-body-secondary" }, "(unassociated)")),
                      h("td", null, h("small", null, (c.probes || []).join(", ") || "-"))
                    )
                  )
                : h("tr", null, h("td", { colSpan: 3 }, running ? "Listening…" : "No clients seen yet."))
            )
          )
        )
      )
    );
  }

  function EvilPortalClientsTable({ clients }) {
    return h(
      Table,
      { striped: true, hover: true, responsive: true, size: "sm", className: "mb-0" },
      h("thead", null, h("tr", null, h("th", null, "Client MAC"), h("th", null, "IP"), h("th", null, "Hostname"))),
      h(
        "tbody",
        null,
        clients.length
          ? clients.map((c) =>
              h(
                "tr",
                { key: c.mac },
                h("td", null, h("code", null, c.mac), c.vendor ? h("div", null, h("small", { className: "text-body-secondary" }, c.vendor)) : null),
                h("td", null, c.ip),
                h("td", null, c.hostname || h("span", { className: "text-body-secondary" }, "-"))
              )
            )
          : h("tr", null, h("td", { colSpan: 3 }, "No devices connected to the twin yet."))
      )
    );
  }

  function EvilPortalCredsTable({ credentials }) {
    return h(
      Table,
      { striped: true, hover: true, responsive: true, size: "sm", className: "mb-0" },
      h("thead", null, h("tr", null, h("th", null, "When"), h("th", null, "From"), h("th", null, "Passphrase"), h("th", null, "Verified"))),
      h(
        "tbody",
        null,
        credentials.length
          ? credentials
              .slice()
              .reverse()
              .map((c, idx) =>
                h(
                  "tr",
                  { key: `${c.time}-${idx}`, className: c.verified ? "table-success" : "" },
                  h("td", null, h("small", null, c.time)),
                  h("td", null, h("code", null, c.ip)),
                  h("td", null, h("code", null, c.password)),
                  h(
                    "td",
                    null,
                    c.verified
                      ? h(Badge, { bg: "success" }, "verified")
                      : c.status === "unverified"
                      ? h(Badge, { bg: "secondary" }, "not checked")
                      : h(Badge, { bg: "warning" }, "wrong")
                  )
                )
              )
          : h("tr", null, h("td", { colSpan: 4 }, "No passphrases submitted yet."))
      )
    );
  }

  // One connected client in the passthrough traffic view: DNS activity plus an
  // on-demand nmap port scan of that device (reuses the LAN-scan endpoints).
  function ClientTrafficRow({ client }) {
    const [scanning, setScanning] = React.useState(false);
    const [ports, setPorts] = React.useState(null);
    const [scanErr, setScanErr] = React.useState("");

    async function scanPorts() {
      setScanning(true);
      setScanErr("");
      setPorts(null);
      try {
        const started = await api("startLanScan", { target: client.ip, profile: "ports" });
        for (let i = 0; i < 80; i += 1) {
          await sleep(2500);
          const st = await api("lanScanStatus", { jobId: started.jobId });
          if (!st.pending) {
            const host = (st.hosts || []).find((hh) => hh.ip === client.ip) || (st.hosts || [])[0];
            setPorts((host && host.ports) || []);
            break;
          }
        }
      } catch (err) {
        setScanErr(err.message);
      } finally {
        setScanning(false);
      }
    }

    const top = client.topDomains || [];
    return h(
      "div",
      { className: "border rounded p-2 mb-2" },
      h(
        "div",
        { className: "d-flex flex-wrap align-items-center justify-content-between gap-2 mb-2" },
        h(
          "div",
          null,
          h("code", null, client.ip),
          client.hostname ? h("span", { className: "ms-2" }, client.hostname) : null,
          client.mac ? h("span", { className: "text-body-secondary ms-2" }, client.mac) : null,
          client.vendor ? h("div", null, h("small", { className: "text-body-secondary" }, client.vendor)) : null
        ),
        h(
          "div",
          { className: "d-flex align-items-center gap-2" },
          h(Badge, { bg: "info" }, `${client.queryCount} queries`),
          h(Badge, { bg: "secondary" }, `${client.uniqueDomains} domains`),
          h(Button, { size: "sm", variant: "outline-primary", onClick: scanPorts, disabled: scanning }, scanning ? h(Spinner, { size: "sm", animation: "border" }) : h(Icon, { name: "search" }), h("span", { className: "ms-1" }, "Scan ports"))
        )
      ),
      top.length
        ? h(
            "div",
            { className: "d-flex flex-wrap gap-1" },
            top.map((d, i) => h(Badge, { key: i, bg: "light", text: "dark", title: `${d.count} queries` }, d.domain))
          )
        : h("small", { className: "text-body-secondary" }, "No DNS queries seen yet."),
      scanErr ? h("div", { className: "text-danger mt-2" }, h("small", null, scanErr)) : null,
      ports ? h("div", { className: "mt-2" }, h(LanPortsCell, { ports })) : null
    );
  }

  function EvilPortalTrafficPanel({ traffic }) {
    const clients = (traffic && traffic.clients) || [];
    return h(
      React.Fragment,
      null,
      h(
        "div",
        { className: "d-flex align-items-center gap-2 mb-2" },
        h("span", { className: "fw-semibold" }, "Live Traffic Intel"),
        h(Badge, { bg: "primary" }, `${clients.length} active`),
        traffic ? h("small", { className: "text-body-secondary" }, `pcap ${formatBytes(traffic.pcapBytes || 0)}${traffic.uplinkDev ? " · via " + traffic.uplinkDev : ""}`) : null
      ),
      clients.length
        ? clients.map((c) => h(ClientTrafficRow, { key: c.ip, client: c }))
        : h(Alert, { variant: "secondary", className: "py-2 mb-0" }, "No client DNS activity captured yet. Connect a device to the twin and browse.")
    );
  }

  function LanPortsCell({ ports }) {
    if (!ports || !ports.length) {
      return h("span", { className: "text-body-secondary" }, "-");
    }
    return h(
      "div",
      { className: "d-flex flex-wrap gap-1" },
      ports.map((p, i) =>
        h(Badge, { key: i, bg: p.state === "open" ? "primary" : "secondary", title: p.version || "" }, `${p.port}/${p.proto} ${p.service}${p.version ? " · " + p.version : ""}`)
      )
    );
  }

  function InventoryChanges({ changes }) {
    if (!changes) {
      return null;
    }
    const nh = changes.newHosts || [];
    const np = changes.newPorts || [];
    if (!nh.length && !np.length) {
      return h(Alert, { variant: "secondary", className: "py-2 mt-3 mb-0" }, h(Icon, { name: "check-circle" }), " No changes since the last scan — network baseline is stable.");
    }
    return h(
      Alert,
      { variant: "warning", className: "py-2 mt-3 mb-0" },
      h("div", { className: "fw-semibold mb-1" }, h(Icon, { name: "alert-triangle" }), " Changes detected this scan"),
      nh.length ? h("div", null, h("strong", null, `${nh.length} new host${nh.length === 1 ? "" : "s"}: `), nh.slice(0, 12).join(", "), nh.length > 12 ? " …" : "") : null,
      np.length ? h("div", null, h("strong", null, `${np.length} newly-open port${np.length === 1 ? "" : "s"}: `), np.slice(0, 12).join(", "), np.length > 12 ? " …" : "") : null
    );
  }

  function InventorySection({ inventory, onClear }) {
    const hosts = (inventory && inventory.hosts) || [];
    if (!hosts.length) {
      return null;
    }
    const withPorts = hosts.filter((hst) => hst.ports && hst.ports.length).length;
    const vendors = {};
    hosts.forEach((hst) => {
      if (hst.vendor) vendors[hst.vendor] = (vendors[hst.vendor] || 0) + 1;
    });
    const vendorCount = Object.keys(vendors).length;
    return h(
      "div",
      { className: "mt-4" },
      h(
        "div",
        { className: "d-flex align-items-center justify-content-between mb-2 flex-wrap gap-2" },
        h(
          "div",
          { className: "d-flex align-items-center flex-wrap gap-2" },
          h("span", { className: "fw-semibold" }, h(Icon, { name: "server" }), " Network Inventory"),
          h(Badge, { bg: "primary" }, `${hosts.length} hosts`),
          h(Badge, { bg: "info" }, `${withPorts} with open ports`),
          h(Badge, { bg: "secondary" }, `${vendorCount} vendors`),
          inventory.updatedAt ? h("span", { className: "text-body-secondary small" }, `updated ${formatDate(inventory.updatedAt)}`) : null
        ),
        h(Button, { size: "sm", variant: "outline-danger", onClick: onClear }, h(Icon, { name: "trash-2" }), " Clear")
      ),
      h(
        Table,
        { striped: true, hover: true, responsive: true, size: "sm", className: "mb-0" },
        h("thead", null, h("tr", null, h("th", null, "Host"), h("th", null, "MAC / Vendor"), h("th", null, "Open ports"), h("th", null, "First seen"), h("th", null, "Last seen"))),
        h(
          "tbody",
          null,
          hosts.map((hst) =>
            h(
              "tr",
              { key: (hst.mac || "") + hst.ip },
              h("td", null, h("code", null, hst.ip), hst.isNew ? h(Badge, { bg: "warning", text: "dark", className: "ms-1" }, "NEW") : null, hst.hostname ? h("div", null, h("small", { className: "text-body-secondary" }, hst.hostname)) : null),
              h("td", null, hst.mac ? h("code", null, hst.mac) : h("span", { className: "text-body-secondary" }, "-"), hst.vendor ? h("div", null, h("small", { className: "text-body-secondary" }, hst.vendor)) : null),
              h("td", null, h(LanPortsCell, { ports: hst.ports })),
              h("td", null, h("small", { className: "text-body-secondary" }, formatDate(hst.firstSeen))),
              h("td", null, h("small", { className: "text-body-secondary" }, formatDate(hst.lastSeen)))
            )
          )
        )
      )
    );
  }

  function LanReconPanel({ status, onActivity }) {
    const [targetKind, setTargetKind] = React.useState("uplink");
    const [custom, setCustom] = React.useState("");
    const [profile, setProfile] = React.useState("discovery");
    const [running, setRunning] = React.useState(false);
    const [job, setJob] = React.useState(null);
    const [result, setResult] = React.useState(null);
    const [error, setError] = React.useState("");
    const [inventory, setInventory] = React.useState(null);
    const [changes, setChanges] = React.useState(null);
    const cancelRef = React.useRef(false);
    React.useEffect(() => {
      if (onActivity) onActivity(running);
    }, [running]);

    async function loadInventory() {
      try {
        setInventory(await api("getNetworkInventory"));
      } catch (err) {
        /* inventory is best-effort; the live scan still works */
      }
    }
    React.useEffect(() => {
      loadInventory();
    }, []);

    async function clearInventory() {
      try {
        await api("clearNetworkInventory");
        setChanges(null);
        await loadInventory();
      } catch (err) {
        setError(err.message);
      }
    }

    const ready = toolInstalled(status, "nmap");

    async function startScan() {
      setRunning(true);
      setError("");
      setResult(null);
      setChanges(null);
      cancelRef.current = false;
      try {
        const target = targetKind === "custom" ? custom.trim() : targetKind;
        const started = await api("startLanScan", { target, profile });
        setJob(started);
        // Service scans can take a few minutes on this CPU; poll generously.
        let final = null;
        for (let i = 0; i < 140; i += 1) {
          if (cancelRef.current) break;
          await sleep(2500);
          const st = await api("lanScanStatus", { jobId: started.jobId });
          setResult(st);
          final = st;
          if (!st.pending) break;
        }
        // Fold the completed scan into the rolling inventory + report changes.
        if (final && !final.pending && final.hosts && final.hosts.length) {
          try {
            const merged = await api("updateNetworkInventory", { hosts: final.hosts });
            setInventory(merged);
            setChanges(merged.changes || null);
          } catch (err) {
            /* keep the live scan result even if the merge fails */
          }
        }
      } catch (err) {
        setError(err.message);
      } finally {
        setRunning(false);
      }
    }

    async function stopScan() {
      if (!job) return;
      cancelRef.current = true;
      try {
        await api("stopLanScan", { jobId: job.jobId });
      } catch (err) {
        setError(err.message);
      }
    }

    const hosts = (result && result.hosts) || [];
    return h(
      Panel,
      { title: "Network Recon Command Center", icon: "globe" },
      h(
        Alert,
        { variant: "info", className: "py-2" },
        "Scan a private network you're attached to for live hosts, open ports, and services. ",
        h("strong", null, "Uplink LAN"),
        " scans your internet network (needs Internet mode); ",
        h("strong", null, "Twin clients"),
        " scans devices connected to a running Evil Portal. Completed scans fold into a persistent ",
        h("strong", null, "inventory"),
        " below, and each rescan flags new hosts and newly-open ports. Only scan networks you own."
      ),
      error ? h(Alert, { variant: "danger", className: "py-2" }, error) : null,
      !ready ? h(Alert, { variant: "secondary", className: "py-2" }, "nmap is not installed.") : null,
      h(
        Row,
        { className: "g-2 align-items-end mb-3" },
        h(Col, { md: 3 }, h(Form.Group, null, h(Form.Label, null, "Target"), h(Form.Select, { value: targetKind, onChange: (e) => setTargetKind(e.target.value), disabled: running }, h("option", { value: "uplink" }, "Uplink LAN"), h("option", { value: "twin" }, "Twin clients (10.0.0.0/24)"), h("option", { value: "custom" }, "Custom IP / CIDR")))),
        targetKind === "custom" ? h(Col, { md: 3 }, h(Form.Group, null, h(Form.Label, null, "IP or CIDR"), h(Form.Control, { placeholder: "192.168.1.0/24", value: custom, onChange: (e) => setCustom(e.target.value), disabled: running }))) : null,
        h(Col, { md: 3 }, h(Form.Group, null, h(Form.Label, null, "Profile"), h(Form.Select, { value: profile, onChange: (e) => setProfile(e.target.value), disabled: running }, h("option", { value: "discovery" }, "Host discovery (fast)"), h("option", { value: "ports" }, "Top-100 ports"), h("option", { value: "services" }, "Services + versions")))),
        h(Col, { md: "auto" }, running ? h(Button, { variant: "danger", onClick: stopScan }, h("span", { className: "me-2" }, h(Spinner, { size: "sm", animation: "border" })), "Stop") : h(Button, { onClick: startScan, disabled: !ready }, h("span", { className: "me-2" }, h(Icon, { name: "globe" })), "Scan")),
        result ? h(Col, { md: "auto", className: "text-body-secondary pb-2" }, `${result.hostCount || hosts.length} hosts${result.pending ? " (scanning…)" : ""}${result.meta && result.meta.label ? " · " + result.meta.label : ""}`) : null
      ),
      result && result.error ? h(Alert, { variant: "warning", className: "py-2" }, result.error) : null,
      h(
        Table,
        { striped: true, hover: true, responsive: true, size: "sm", className: "mb-0" },
        h("thead", null, h("tr", null, h("th", null, "Host"), h("th", null, "MAC / Vendor"), h("th", null, "Open ports / services"))),
        h(
          "tbody",
          null,
          hosts.length
            ? hosts.map((hst) =>
                h(
                  "tr",
                  { key: hst.ip },
                  h("td", null, h("code", null, hst.ip), hst.hostname ? h("div", null, h("small", { className: "text-body-secondary" }, hst.hostname)) : null),
                  h("td", null, hst.mac ? h("code", null, hst.mac) : h("span", { className: "text-body-secondary" }, "-"), hst.vendor ? h("div", null, h("small", { className: "text-body-secondary" }, hst.vendor)) : null),
                  h("td", null, h(LanPortsCell, { ports: hst.ports }))
                )
              )
            : h("tr", null, h("td", { colSpan: 3 }, running ? "Scanning…" : "No hosts found yet."))
        )
      ),
      h(InventoryChanges, { changes }),
      h(InventorySection, { inventory, onClear: clearInventory })
    );
  }

  function SniffPanel({ status, onActivity }) {
    const [iface, setIface] = React.useState("uplink");
    const [preset, setPreset] = React.useState("web");
    const [duration, setDuration] = React.useState(120);
    const [running, setRunning] = React.useState(false);
    const [job, setJob] = React.useState(null);
    const [result, setResult] = React.useState(null);
    const [error, setError] = React.useState("");
    const cancelRef = React.useRef(false);
    React.useEffect(() => {
      if (onActivity) onActivity(running);
    }, [running]);

    const ready = toolInstalled(status, "tcpdump");
    const findings = (result && result.findings) || null;

    async function start() {
      setRunning(true);
      setError("");
      setResult(null);
      cancelRef.current = false;
      try {
        const started = await api("startSniff", { iface, preset, duration: Number(duration) });
        setJob(started);
        // Poll for the whole duration (+slack); findings stream in live.
        const loops = Math.ceil(Number(duration) / 3) + 6;
        for (let i = 0; i < loops; i += 1) {
          if (cancelRef.current) break;
          await sleep(3000);
          const st = await api("sniffStatus", { jobId: started.jobId });
          setResult(st);
          if (!st.pending) break;
        }
      } catch (err) {
        setError(err.message);
      } finally {
        setRunning(false);
      }
    }

    async function stop() {
      if (!job) return;
      cancelRef.current = true;
      try {
        await api("stopSniff", { jobId: job.jobId });
      } catch (err) {
        setError(err.message);
      }
    }

    async function download() {
      if (!job) return;
      try {
        await downloadFile("downloadSniff", { jobId: job.jobId }, `${job.jobId}.pcap`);
      } catch (err) {
        setError(err.message);
      }
    }

    async function discard() {
      if (!job) return;
      try {
        await api("deleteSniff", { jobId: job.jobId });
        setResult(null);
        setJob(null);
      } catch (err) {
        setError(err.message);
      }
    }

    const counts = (findings && findings.counts) || { dns: 0, http: 0, creds: 0, cookies: 0 };
    return h(
      Panel,
      { title: "Packet Intelligence", icon: "eye" },
      h(
        Alert,
        { variant: "info", className: "py-2" },
        "Passively capture traffic on an interface and dissect the cleartext: DNS lookups, HTTP requests, cookies, and any credentials sent in the clear. ",
        h("strong", null, "HTTPS stays encrypted"),
        " — you'll see the domains devices resolve, but not the contents of TLS. Sniff ",
        h("strong", null, "Uplink"),
        " (your WAN, needs Internet mode), ",
        h("strong", null, "LAN bridge"),
        ", or a running ",
        h("strong", null, "Evil Portal twin"),
        ". Only capture on networks you own."
      ),
      error ? h(Alert, { variant: "danger", className: "py-2" }, error) : null,
      !ready ? h(Alert, { variant: "secondary", className: "py-2" }, "tcpdump is not installed.") : null,
      h(
        Row,
        { className: "g-2 align-items-end mb-3" },
        h(Col, { md: 3 }, h(Form.Group, null, h(Form.Label, null, "Interface"), h(Form.Select, { value: iface, onChange: (e) => setIface(e.target.value), disabled: running }, h("option", { value: "uplink" }, "Uplink (WAN)"), h("option", { value: "lan" }, "LAN bridge (br-lan)"), h("option", { value: "twin" }, "Evil Portal twin")))),
        h(Col, { md: 3 }, h(Form.Group, null, h(Form.Label, null, "Capture filter"), h(Form.Select, { value: preset, onChange: (e) => setPreset(e.target.value), disabled: running }, h("option", { value: "web" }, "Web + DNS (80 + 53)"), h("option", { value: "dns" }, "DNS only (53)"), h("option", { value: "cleartext" }, "Cleartext protocols")))),
        h(Col, { md: 2 }, h(Form.Group, null, h(Form.Label, null, "Duration (s)"), h(Form.Control, { type: "number", min: 15, max: 600, value: duration, onChange: (e) => setDuration(e.target.value), disabled: running }))),
        h(Col, { md: "auto" }, running ? h(Button, { variant: "danger", onClick: stop }, h("span", { className: "me-2" }, h(Spinner, { size: "sm", animation: "border" })), "Stop") : h(Button, { onClick: start, disabled: !ready }, h("span", { className: "me-2" }, h(Icon, { name: "eye" })), "Capture")),
        result && result.findings ? h(Col, { md: "auto", className: "text-body-secondary pb-2" }, `pcap ${formatBytes(result.findings.pcapBytes)}${result.pending ? " · capturing…" : ""}`) : null
      ),
      result && result.error ? h(Alert, { variant: "warning", className: "py-2" }, result.error) : null,
      findings
        ? h(
            "div",
            null,
            h(
              "div",
              { className: "d-flex flex-wrap gap-2 mb-3" },
              h(Badge, { bg: "primary" }, `${counts.dns} DNS`),
              h(Badge, { bg: "info" }, `${counts.http} HTTP`),
              h(Badge, { bg: counts.creds ? "danger" : "secondary" }, `${counts.creds} creds`),
              h(Badge, { bg: "secondary" }, `${counts.cookies} cookies`),
              job ? h(Button, { size: "sm", variant: "outline-info", onClick: download }, h(Icon, { name: "download" }), " pcap") : null,
              job && !result.pending ? h(Button, { size: "sm", variant: "outline-danger", onClick: discard }, h(Icon, { name: "trash-2" }), " Discard") : null
            ),
            counts.creds
              ? h(
                  "div",
                  { className: "mb-3" },
                  h("div", { className: "fw-semibold mb-1 text-danger" }, h(Icon, { name: "alert-octagon" }), " Cleartext credentials"),
                  h(
                    Table,
                    { size: "sm", responsive: true, className: "mb-0" },
                    h("thead", null, h("tr", null, h("th", null, "Client"), h("th", null, "Host"), h("th", null, "Type"), h("th", null, "Captured"))),
                    h("tbody", null, findings.creds.map((c, i) => h("tr", { key: i }, h("td", null, h("code", null, c.client || "-")), h("td", null, c.host || "-"), h("td", null, h(Badge, { bg: "danger" }, c.type)), h("td", null, h("code", null, c.detail)))))
                  )
                )
              : null,
            h(
              Row,
              { className: "g-3" },
              h(
                Col,
                { lg: 6 },
                h("div", { className: "fw-semibold mb-1" }, h(Icon, { name: "globe" }), " DNS queries"),
                h(
                  Table,
                  { size: "sm", hover: true, responsive: true, className: "mb-0" },
                  h("thead", null, h("tr", null, h("th", null, "Client"), h("th", null, "Domain"), h("th", null, "#"))),
                  h("tbody", null, findings.dns.length ? findings.dns.map((d, i) => h("tr", { key: i }, h("td", null, h("code", null, d.client || "-")), h("td", null, d.domain), h("td", null, d.count))) : h("tr", null, h("td", { colSpan: 3 }, "No DNS seen yet.")))
                )
              ),
              h(
                Col,
                { lg: 6 },
                h("div", { className: "fw-semibold mb-1" }, h(Icon, { name: "activity" }), " HTTP requests"),
                h(
                  Table,
                  { size: "sm", hover: true, responsive: true, className: "mb-0" },
                  h("thead", null, h("tr", null, h("th", null, "Client"), h("th", null, "Request"))),
                  h("tbody", null, findings.http.length ? findings.http.map((r, i) => h("tr", { key: i }, h("td", null, h("code", null, r.client || "-")), h("td", null, h("div", null, h(Badge, { bg: "secondary", className: "me-1" }, r.method), h("span", null, (r.host || "") + r.url)), r.ua ? h("small", { className: "text-body-secondary" }, r.ua) : null))) : h("tr", null, h("td", { colSpan: 2 }, "No cleartext HTTP seen (most sites use HTTPS).")))
                )
              )
            ),
            findings.cookies.length
              ? h(
                  "div",
                  { className: "mt-3" },
                  h("div", { className: "fw-semibold mb-1" }, h(Icon, { name: "database" }), " Cookies"),
                  h(
                    Table,
                    { size: "sm", responsive: true, className: "mb-0" },
                    h("thead", null, h("tr", null, h("th", null, "Client"), h("th", null, "Host"), h("th", null, "Cookie"))),
                    h("tbody", null, findings.cookies.map((c, i) => h("tr", { key: i }, h("td", null, h("code", null, c.client || "-")), h("td", null, c.host || "-"), h("td", null, h("code", { className: "small" }, c.cookie)))))
                  )
                )
              : null
          )
        : h("p", { className: "text-body-secondary mb-0" }, running ? "Capturing…" : "Start a capture to see traffic intelligence.")
    );
  }

  function CrackPanel({ status, authorizedTargets, onActivity }) {
    const [sources, setSources] = React.useState([]);
    const [captureId, setCaptureId] = React.useState("");
    const [wordlists, setWordlists] = React.useState([]);
    const [wordlist, setWordlist] = React.useState("");
    const [genType, setGenType] = React.useState("common");
    const [genSsid, setGenSsid] = React.useState("");
    const [genBusy, setGenBusy] = React.useState(false);
    const [running, setRunning] = React.useState(false);
    const [job, setJob] = React.useState(null);
    const [result, setResult] = React.useState(null);
    const [error, setError] = React.useState("");
    const [pinBssid, setPinBssid] = React.useState("");
    const [pins, setPins] = React.useState(null);
    const [pinBusy, setPinBusy] = React.useState(false);
    const [wlUploading, setWlUploading] = React.useState(false);
    const [capUploading, setCapUploading] = React.useState(false);
    const [capBssid, setCapBssid] = React.useState("");
    const [notice, setNotice] = React.useState("");
    const wlFileRef = React.useRef(null);
    const capFileRef = React.useRef(null);
    const cancelRef = React.useRef(false);
    React.useEffect(() => {
      if (onActivity) onActivity(running);
    }, [running]);

    const ready = toolInstalled(status, "aircrack-ng");

    async function loadSources() {
      try {
        const r = await api("listCrackSources");
        setSources(r.sources || []);
      } catch (err) {
        /* best effort */
      }
    }
    async function loadWordlists() {
      try {
        const r = await api("listWordlists");
        setWordlists(r.wordlists || []);
      } catch (err) {
        /* best effort */
      }
    }
    React.useEffect(() => {
      loadSources();
      loadWordlists();
    }, []);

    async function generate() {
      setGenBusy(true);
      setError("");
      try {
        const r = await api("generateWordlist", { type: genType, ssid: genSsid.trim() });
        await loadWordlists();
        setWordlist(r.name);
      } catch (err) {
        setError(err.message);
      } finally {
        setGenBusy(false);
      }
    }

    async function removeWordlist(name) {
      try {
        await api("deleteWordlist", { name });
        if (wordlist === name) setWordlist("");
        await loadWordlists();
      } catch (err) {
        setError(err.message);
      }
    }

    async function uploadWordlistFile() {
      const f = wlFileRef.current && wlFileRef.current.files && wlFileRef.current.files[0];
      if (!f) {
        setError("Choose a .txt wordlist file first.");
        return;
      }
      if (f.size > UPLOAD_MAX_BYTES) {
        setError("Wordlist is too large (max 1.8 MB on this router). Generate large lists on-device instead.");
        return;
      }
      setWlUploading(true);
      setError("");
      setNotice("");
      try {
        const b64 = await readFileB64(f);
        const r = await api("uploadWordlist", { name: f.name, contentB64: b64 });
        await loadWordlists();
        setWordlist(r.name);
        setNotice(`Uploaded ${r.name} — ${r.count.toLocaleString()} usable keys.`);
        if (wlFileRef.current) wlFileRef.current.value = "";
      } catch (err) {
        setError(err.message);
      } finally {
        setWlUploading(false);
      }
    }

    async function uploadCaptureFile() {
      const f = capFileRef.current && capFileRef.current.files && capFileRef.current.files[0];
      if (!f) {
        setError("Choose a .cap / .pcap / .pcapng file first.");
        return;
      }
      if (f.size > UPLOAD_MAX_BYTES) {
        setError("Capture is too large (max 1.8 MB). A handshake file is normally only a few KB.");
        return;
      }
      setCapUploading(true);
      setError("");
      setNotice("");
      try {
        const b64 = await readFileB64(f);
        const r = await api("uploadCapture", { name: f.name, contentB64: b64, bssid: capBssid.trim() });
        await loadSources();
        setCaptureId(r.jobId);
        if (capFileRef.current) capFileRef.current.value = "";
        setCapBssid("");
        setNotice(
          r.handshake
            ? `Added capture for ${r.ssid || r.bssid} — handshake/PMKID detected (${r.hashCount}).`
            : `Added capture for ${r.ssid || r.bssid}, but no handshake/PMKID was auto-detected — cracking may fail.`
        );
      } catch (err) {
        setError(err.message);
      } finally {
        setCapUploading(false);
      }
    }

    async function start() {
      if (!captureId || !wordlist) {
        setError("Pick a captured handshake and a wordlist first.");
        return;
      }
      setRunning(true);
      setError("");
      setResult(null);
      cancelRef.current = false;
      try {
        const started = await api("startCrack", { captureId, wordlist });
        setJob(started);
        for (let i = 0; i < 700; i += 1) {
          if (cancelRef.current) break;
          await sleep(2500);
          const st = await api("crackStatus", { jobId: started.jobId });
          setResult(st);
          if (!st.pending || st.cracked) break;
        }
      } catch (err) {
        setError(err.message);
      } finally {
        setRunning(false);
      }
    }

    async function stop() {
      if (!job) return;
      cancelRef.current = true;
      try {
        await api("stopCrack", { jobId: job.jobId });
      } catch (err) {
        setError(err.message);
      }
    }

    async function computePins() {
      setPinBusy(true);
      setError("");
      try {
        const r = await api("computeWpsPins", { bssid: pinBssid.trim().toLowerCase() });
        setPins(r.pins || []);
      } catch (err) {
        setPins(null);
        setError(err.message);
      } finally {
        setPinBusy(false);
      }
    }

    const targets = authorizedTargets || [];
    const pct = result && result.total ? Math.min(100, Math.round((result.tested / result.total) * 100)) : 0;

    return h(
      Panel,
      { title: "Crack Lab", icon: "unlock" },
      h(
        Alert,
        { variant: "info", className: "py-2" },
        "Run a dictionary attack against a captured WPA/WPA2 handshake, and compute likely WPS default PINs from a BSSID. ",
        h("strong", null, "This is a single-core router"),
        " — it tests roughly a few hundred keys/sec, so it only realistically recovers weak or default passwords, not strong ones. Only attack handshakes from networks you own."
      ),
      error ? h(Alert, { variant: "danger", className: "py-2" }, error) : null,
      notice ? h(Alert, { variant: "success", className: "py-2" }, notice) : null,
      !ready ? h(Alert, { variant: "secondary", className: "py-2" }, "aircrack-ng is not installed.") : null,
      h(
        Row,
        { className: "g-3" },
        h(
          Col,
          { lg: 5 },
          h(
            Card,
            { className: "h-100", body: true },
            h("div", { className: "fw-semibold mb-2" }, h(Icon, { name: "list" }), " Wordlists"),
            h(
              Row,
              { className: "g-2 align-items-end mb-2" },
              h(Col, { xs: genType === "ssid" ? 5 : 8 }, h(Form.Group, null, h(Form.Label, { className: "small mb-1" }, "Generate"), h(Form.Select, { size: "sm", value: genType, onChange: (e) => setGenType(e.target.value), disabled: genBusy }, h("option", { value: "common" }, "Common PSKs"), h("option", { value: "digits" }, "Digit / date patterns"), h("option", { value: "ssid" }, "SSID-derived")))),
              genType === "ssid" ? h(Col, { xs: 4 }, h(Form.Group, null, h(Form.Label, { className: "small mb-1" }, "SSID"), h(Form.Control, { size: "sm", value: genSsid, onChange: (e) => setGenSsid(e.target.value), placeholder: "Home_WiFi", disabled: genBusy }))) : null,
              h(Col, { xs: "auto" }, h(Button, { size: "sm", onClick: generate, disabled: genBusy }, genBusy ? h(Spinner, { size: "sm", animation: "border" }) : "Generate"))
            ),
            h(
              Form.Group,
              { className: "mb-2" },
              h(Form.Label, { className: "small mb-1" }, "Or upload your own (.txt, ≤ 1.8 MB)"),
              h(
                "div",
                { className: "d-flex gap-2" },
                h(Form.Control, { size: "sm", type: "file", accept: ".txt,text/plain", ref: wlFileRef, disabled: wlUploading }),
                h(Button, { size: "sm", variant: "outline-primary", onClick: uploadWordlistFile, disabled: wlUploading }, wlUploading ? h(Spinner, { size: "sm", animation: "border" }) : "Upload")
              )
            ),
            wordlists.length
              ? h(
                  Table,
                  { size: "sm", hover: true, responsive: true, className: "mb-0" },
                  h("thead", null, h("tr", null, h("th", null, "Name"), h("th", null, "Keys"), h("th", null, "Size"), h("th", null, ""))),
                  h(
                    "tbody",
                    null,
                    wordlists.map((wl) =>
                      h(
                        "tr",
                        { key: wl.name, className: wordlist === wl.name ? "table-active" : "", style: { cursor: "pointer" }, onClick: () => setWordlist(wl.name) },
                        h("td", null, wordlist === wl.name ? h(Icon, { name: "check" }) : null, " ", h("code", null, wl.name)),
                        h("td", null, wl.lines),
                        h("td", null, formatBytes(wl.bytes)),
                        h("td", null, h("span", { className: "text-danger", role: "button", onClick: (e) => { e.stopPropagation(); removeWordlist(wl.name); } }, h(Icon, { name: "trash-2" })))
                      )
                    )
                  )
                )
              : h("p", { className: "text-body-secondary small mb-0" }, "No wordlists yet — generate one above.")
          )
        ),
        h(
          Col,
          { lg: 7 },
          h(
            Card,
            { className: "h-100", body: true },
            h("div", { className: "fw-semibold mb-2" }, h(Icon, { name: "unlock" }), " Dictionary attack"),
            h(
              Row,
              { className: "g-2 align-items-end mb-2" },
              h(Col, { md: 6 }, h(Form.Group, null, h(Form.Label, { className: "small mb-1" }, "Captured handshake"), h(Form.Select, { size: "sm", value: captureId, onChange: (e) => setCaptureId(e.target.value), disabled: running }, h("option", { value: "" }, sources.length ? "Select a capture…" : "No captures — capture or upload one"), sources.filter((s) => s.handshake || s.source === "uploaded").map((s) => h("option", { key: s.jobId, value: s.jobId }, `${s.ssid || s.bssid} · ${s.bssid}${s.source === "uploaded" ? " (uploaded)" : ""}${s.handshake ? "" : " — no handshake"}`))))),
              h(Col, { md: 4 }, h(Form.Group, null, h(Form.Label, { className: "small mb-1" }, "Wordlist"), h(Form.Select, { size: "sm", value: wordlist, onChange: (e) => setWordlist(e.target.value), disabled: running }, h("option", { value: "" }, "Select…"), wordlists.map((wl) => h("option", { key: wl.name, value: wl.name }, `${wl.name} (${wl.lines})`))))),
              h(Col, { md: "auto" }, running ? h(Button, { size: "sm", variant: "danger", onClick: stop }, h(Spinner, { size: "sm", animation: "border", className: "me-1" }), "Stop") : h(Button, { size: "sm", onClick: start, disabled: !ready }, h(Icon, { name: "play" }), " Crack"))
            ),
            h(
              "div",
              { className: "border rounded p-2 mb-3 bg-body-tertiary" },
              h("div", { className: "small fw-semibold mb-1" }, h(Icon, { name: "upload" }), " Add a capture from a file (.cap / .pcap / .pcapng)"),
              h(
                Row,
                { className: "g-2 align-items-end" },
                h(Col, { md: 5 }, h(Form.Control, { size: "sm", type: "file", accept: ".cap,.pcap,.pcapng", ref: capFileRef, disabled: capUploading })),
                h(Col, { md: 4 }, h(Form.Control, { size: "sm", value: capBssid, onChange: (e) => setCapBssid(e.target.value), placeholder: "BSSID (only if not in file)", disabled: capUploading })),
                h(Col, { md: "auto" }, h(Button, { size: "sm", variant: "outline-primary", onClick: uploadCaptureFile, disabled: capUploading }, capUploading ? h(Spinner, { size: "sm", animation: "border" }) : "Add"))
              ),
              h("div", { className: "text-body-secondary small mt-1" }, "Bring a handshake captured elsewhere (Wireshark, another tool). BSSID + SSID are read from the file when present; pcapng is converted automatically.")
            ),
            result && result.cracked
              ? h(Alert, { variant: "success", className: "py-2" }, h("div", { className: "fw-semibold" }, h(Icon, { name: "unlock" }), " KEY FOUND"), h("code", { style: { fontSize: "1.1rem" } }, result.found))
              : null,
            result && result.noHandshake ? h(Alert, { variant: "warning", className: "py-2" }, "aircrack-ng found no valid handshake in that capture. Re-capture the target with a forced deauth.") : null,
            result && !result.cracked
              ? h(
                  "div",
                  null,
                  h(
                    "div",
                    { className: "d-flex flex-wrap gap-2 mb-1" },
                    h(Badge, { bg: result.pending ? "primary" : "secondary" }, result.pending ? "Running…" : "Finished"),
                    result.total ? h(Badge, { bg: "info" }, `${result.tested.toLocaleString()} / ${result.total.toLocaleString()} keys`) : null,
                    result.speed ? h(Badge, { bg: "secondary" }, `${result.speed} k/s`) : null,
                    result.current ? h(Badge, { bg: "secondary" }, `trying: ${result.current}`) : null
                  ),
                  result.total ? h("div", { className: "progress", style: { height: "6px" } }, h("div", { className: "progress-bar", style: { width: `${pct}%` } })) : null,
                  !result.pending && !result.cracked && !result.noHandshake ? h("div", { className: "text-body-secondary small mt-1" }, "Wordlist exhausted — password not in this list.") : null
                )
              : null
          )
        )
      ),
      h(
        Card,
        { className: "mt-3", body: true },
        h("div", { className: "fw-semibold mb-2" }, h(Icon, { name: "key" }), " WPS default-PIN calculator"),
        h(
          "p",
          { className: "text-body-secondary small" },
          "Compute likely WPS PINs from a BSSID using known vendor algorithms (ComputePIN family, D-Link) plus common static defaults. Paste a promising PIN into the ",
          h("strong", null, "WPS"),
          " tab's attack field to try it against a WPS-enabled AP you own."
        ),
        h(
          Row,
          { className: "g-2 align-items-end mb-2" },
          h(Col, { md: 4 }, h(Form.Group, null, h(Form.Label, { className: "small mb-1" }, "BSSID"), h(Form.Control, { size: "sm", value: pinBssid, onChange: (e) => setPinBssid(e.target.value), placeholder: "AA:BB:CC:DD:EE:FF" }))),
          targets.length ? h(Col, { md: 4 }, h(Form.Group, null, h(Form.Label, { className: "small mb-1" }, "or pick authorized"), h(Form.Select, { size: "sm", value: "", onChange: (e) => setPinBssid(e.target.value) }, h("option", { value: "" }, "Select…"), targets.map((t) => h("option", { key: t.bssid, value: t.bssid }, `${t.ssid || t.bssid}`))))) : null,
          h(Col, { md: "auto" }, h(Button, { size: "sm", onClick: computePins, disabled: pinBusy }, pinBusy ? h(Spinner, { size: "sm", animation: "border" }) : h(Icon, { name: "cpu" }), " Compute"))
        ),
        pins
          ? pins.length
            ? h(
                "div",
                { className: "d-flex flex-wrap gap-2" },
                pins.map((p, i) => h("span", { key: i, className: "wa-pill", title: p.algo }, h("code", null, p.pin), h("small", { className: "text-body-secondary" }, p.algo)))
              )
            : h("span", { className: "text-body-secondary" }, "No candidates.")
          : null
      )
    );
  }

  const EVIL_5G_CHANNELS = [36, 40, 44, 48, 149, 153, 157, 161, 165];

  // MITM add-ons for a running passthrough twin. We already sit inline as the
  // clients' gateway + resolver, so these are turn-key: DNS spoofing (scoped to
  // twin clients) and cleartext HTTP session/credential sniffing.
  function emptyMitmRule() {
    return { domain: "", action: "notice", target: "", template: "instagram" };
  }

  function MitmPanel() {
    const [mitm, setMitm] = React.useState(null);
    const [httpSniff, setHttpSniff] = React.useState(false);
    const [rules, setRules] = React.useState([emptyMitmRule()]);
    const [landing, setLanding] = React.useState("");
    const [busy, setBusy] = React.useState(false);
    const [err, setErr] = React.useState("");
    const pollRef = React.useRef(null);
    const initRef = React.useRef(false);

    async function refresh() {
      try {
        setMitm(await api("mitmStatus"));
      } catch (e) {
        /* best effort */
      }
    }
    React.useEffect(() => {
      refresh();
      pollRef.current = setInterval(refresh, 5000);
      return () => pollRef.current && clearInterval(pollRef.current);
    }, []);
    React.useEffect(() => {
      if (!initRef.current && mitm && mitm.mitm) {
        initRef.current = true;
        setHttpSniff(!!mitm.mitm.httpSniff);
        const loaded = (mitm.mitm.rules || []).map((r) => ({
          domain: r.domain || "",
          action: r.action || "notice",
          target: r.target || "",
          template: r.template || "instagram",
        }));
        if (loaded.length) setRules(loaded);
        setLanding(mitm.mitm.landingText || "");
      }
    }, [mitm]);

    function updateRule(i, patch) {
      setRules((prev) => prev.map((r, idx) => (idx === i ? { ...r, ...patch } : r)));
    }
    function addRule() {
      setRules((prev) => [...prev, emptyMitmRule()]);
    }
    function removeRule(i) {
      setRules((prev) => prev.filter((_, idx) => idx !== i));
    }

    async function apply() {
      setBusy(true);
      setErr("");
      try {
        const payload = rules
          .map((r) => ({ ...r, domain: r.domain.trim().toLowerCase() }))
          .filter((r) => r.domain);
        await api("updateMitm", { authorized: true, httpSniff, rules: payload, landingText: landing });
        await refresh();
      } catch (e) {
        setErr(e.message);
      } finally {
        setBusy(false);
      }
    }
    async function stopAll() {
      setBusy(true);
      setErr("");
      try {
        await api("stopMitm");
        setHttpSniff(false);
        setRules([emptyMitmRule()]);
        setLanding("");
        await refresh();
      } catch (e) {
        setErr(e.message);
      } finally {
        setBusy(false);
      }
    }

    const cap = (mitm && mitm.captured) || { hosts: [], cookies: [], creds: [] };
    const cloneCreds = (mitm && mitm.cloneCreds) || [];
    const cloneTemplates = (mitm && mitm.cloneTemplates) || [];
    const sniffOn = mitm && mitm.httpSniffActive;
    const dnsOn = mitm && mitm.dnsSpoofActive;

    return h(
      Card,
      { className: "mt-3", body: true },
      h(
        "div",
        { className: "d-flex align-items-center justify-content-between mb-2" },
        h("div", { className: "fw-semibold" }, h(Icon, { name: "crosshair" }), " MITM toolkit"),
        h(
          "div",
          { className: "d-flex gap-2" },
          h(Badge, { bg: sniffOn ? "success" : "secondary" }, sniffOn ? "sniffer on" : "sniffer off"),
          h(Badge, { bg: dnsOn ? "success" : "secondary" }, dnsOn ? "dns spoof on" : "dns spoof off")
        )
      ),
      h(
        Alert,
        { variant: "secondary", className: "py-2 small mb-3" },
        "The twin is already the clients' gateway and resolver, so you have a full man-in-the-middle position. ",
        h("strong", null, "HTTP sniff"),
        " reads cleartext traffic for cookies (session hijacking) and login fields. Each ",
        h("strong", null, "domain rule"),
        " below spoofs one domain to the twin, then either shows a plain notice, sends an HTTP 302 ",
        h("strong", null, "redirect"),
        " to any URL you choose (\"type google.com, land anywhere\"), or serves a fake-login ",
        h("strong", null, "clone"),
        " page that captures whatever is typed (awareness/training demo). ",
        h("em", null, "Only works for plain HTTP. Real sites with HSTS preload (accounts.google.com, instagram.com, most modern HTTPS-only sites) will be refused by the browser before any request leaves the device — test with an HTTP-only or non-preloaded domain instead. ARP poisoning is not offered: no arp-spoof tool exists on this hardware and, as the gateway, you already have the position it would try to reach.")
      ),
      err ? h(Alert, { variant: "danger", className: "py-2" }, err) : null,
      h(
        Row,
        { className: "g-3" },
        h(
          Col,
          { md: 6 },
          h(Form.Check, {
            type: "switch",
            id: "mitm-http-sniff",
            className: "mb-2",
            label: "HTTP session / credential sniffer (tcpdump on evtwin0)",
            checked: httpSniff,
            disabled: busy,
            onChange: (e) => setHttpSniff(e.target.checked),
          }),
          h("div", { className: "small fw-semibold mb-1" }, "Domain rules"),
          rules.map((r, i) =>
            h(
              "div",
              { key: i, className: "border rounded p-2 mb-2" },
              h(
                Row,
                { className: "g-2 align-items-end" },
                h(Col, { xs: 12 }, h(Form.Group, null, h(Form.Label, { className: "small mb-1" }, "Domain to spoof"), h(Form.Control, { size: "sm", value: r.domain, onChange: (e) => updateRule(i, { domain: e.target.value }), placeholder: "google.com", disabled: busy }))),
                h(
                  Col,
                  { xs: 12 },
                  h(Form.Group, null, h(Form.Label, { className: "small mb-1" }, "Action"), h(Form.Select, { size: "sm", value: r.action, onChange: (e) => updateRule(i, { action: e.target.value }), disabled: busy }, h("option", { value: "notice" }, "Plain notice page"), h("option", { value: "redirect" }, "Redirect to any URL"), h("option", { value: "clone" }, "Fake login page (creds capture)")))
                ),
                r.action === "redirect"
                  ? h(Col, { xs: 12 }, h(Form.Group, null, h(Form.Label, { className: "small mb-1" }, "Send to URL"), h(Form.Control, { size: "sm", value: r.target, onChange: (e) => updateRule(i, { target: e.target.value }), placeholder: "https://example.com", disabled: busy })))
                  : null,
                r.action === "clone"
                  ? h(
                      Col,
                      { xs: 12 },
                      h(
                        Form.Group,
                        null,
                        h(Form.Label, { className: "small mb-1" }, "Clone template"),
                        h(
                          Form.Select,
                          { size: "sm", value: r.template, onChange: (e) => updateRule(i, { template: e.target.value }), disabled: busy },
                          (cloneTemplates.length ? cloneTemplates : [{ id: "instagram", label: "Instagram-style login" }, { id: "google", label: "Google-style sign-in" }]).map((t) => h("option", { key: t.id, value: t.id }, t.label))
                        )
                      )
                    )
                  : null,
                h(Col, { xs: 12 }, h(Button, { size: "sm", variant: "outline-danger", onClick: () => removeRule(i), disabled: busy }, h(Icon, { name: "trash-2" }), " Remove rule"))
              )
            )
          ),
          h(Button, { size: "sm", variant: "outline-secondary", onClick: addRule, disabled: busy, className: "mb-2" }, h(Icon, { name: "plus" }), " Add rule"),
          h(Form.Group, { className: "mb-2" }, h(Form.Label, { className: "small mb-1" }, "Notice text (used by \"Plain notice page\" rules)"), h(Form.Control, { size: "sm", value: landing, onChange: (e) => setLanding(e.target.value), placeholder: "Redirected for assessment", disabled: busy })),
          h(
            "div",
            { className: "d-flex gap-2 mt-3" },
            h(Button, { size: "sm", onClick: apply, disabled: busy }, busy ? h(Spinner, { size: "sm", animation: "border", className: "me-1" }) : h(Icon, { name: "check" }), " Apply"),
            h(Button, { size: "sm", variant: "outline-danger", onClick: stopAll, disabled: busy }, h(Icon, { name: "power" }), " Stop MITM")
          )
        ),
        h(
          Col,
          { md: 6 },
          cloneCreds.length
            ? h(
                "div",
                { className: "mb-3" },
                h("div", { className: "fw-semibold small mb-1 text-danger" }, h(Icon, { name: "key" }), ` Clone-page credentials (${cloneCreds.length})`),
                h(
                  Table,
                  { size: "sm", responsive: true, className: "mb-0" },
                  h("thead", null, h("tr", null, h("th", null, "Time"), h("th", null, "Spoofed domain"), h("th", null, "Captured fields"))),
                  h("tbody", null, cloneCreds.map((c, i) => h("tr", { key: i }, h("td", null, h("small", null, c.time)), h("td", null, h("code", { className: "small" }, String(c.template || "").replace(/^mitm-/, ""))), h("td", null, h("code", { className: "small" }, c.fields)))))
                )
              )
            : null,
          cap.creds && cap.creds.length
            ? h(
                "div",
                { className: "mb-3" },
                h("div", { className: "fw-semibold small mb-1 text-danger" }, h(Icon, { name: "key" }), ` Sniffed credentials (${cap.creds.length})`),
                h(
                  Table,
                  { size: "sm", responsive: true, className: "mb-0" },
                  h("thead", null, h("tr", null, h("th", null, "Host"), h("th", null, "Type"), h("th", null, "Value"))),
                  h("tbody", null, cap.creds.map((c, i) => h("tr", { key: i }, h("td", null, h("small", null, c.host || "-")), h("td", null, h(Badge, { bg: c.type === "http-basic" ? "warning" : "info" }, c.type)), h("td", null, h("code", { className: "small" }, c.value)))))
                )
              )
            : null,
          cap.cookies && cap.cookies.length
            ? h(
                "div",
                { className: "mb-3" },
                h("div", { className: "fw-semibold small mb-1" }, h(Icon, { name: "database" }), ` Session cookies (${cap.cookies.length})`),
                h(
                  Table,
                  { size: "sm", responsive: true, className: "mb-0" },
                  h("thead", null, h("tr", null, h("th", null, "Host"), h("th", null, "Cookie"))),
                  h("tbody", null, cap.cookies.map((c, i) => h("tr", { key: i }, h("td", null, h("small", null, c.host || "-")), h("td", null, h("code", { className: "small", style: { wordBreak: "break-all" } }, c.value)))))
                )
              )
            : null,
          cap.hosts && cap.hosts.length
            ? h(
                "div",
                null,
                h("div", { className: "fw-semibold small mb-1" }, h(Icon, { name: "globe" }), ` Hosts seen (${cap.hosts.length})`),
                h("div", { className: "d-flex flex-wrap gap-1" }, cap.hosts.map((hh, i) => h("span", { key: i, className: "badge bg-secondary" }, `${hh.host} ·${hh.hits}`)))
              )
            : !cloneCreds.length
            ? h("p", { className: "text-body-secondary small mb-0" }, sniffOn ? "Sniffer running — browse from a connected client to populate this." : "Enable the HTTP sniffer, or add a domain rule, then connect a client to see results here.")
            : null
        )
      )
    );
  }

  function EvilPortalPanel({ status, authorizedTargets, onActivity }) {
    const [targetBssid, setTargetBssid] = React.useState("");
    const [band, setBand] = React.useState("2g");
    const [channel, setChannel] = React.useState(6);
    const [internet, setInternet] = React.useState(false);
    const [template, setTemplate] = React.useState("router");
    const [customHtml, setCustomHtml] = React.useState("");
    const [starting, setStarting] = React.useState(false);
    const [live, setLive] = React.useState(null);
    const [traffic, setTraffic] = React.useState(null);
    const [note, setNote] = React.useState("");
    const [error, setError] = React.useState("");
    const pollRef = React.useRef(null);

    const targets = authorizedTargets || [];
    const toolsReady =
      toolInstalled(status, "hostapd") && toolInstalled(status, "dnsmasq") && toolInstalled(status, "nft") && toolInstalled(status, "uhttpd");
    const selected = targets.find((t) => t.bssid === targetBssid) || null;
    const running = Boolean(live && live.running);
    React.useEffect(() => {
      if (onActivity) onActivity(running);
    }, [running]);

    async function refreshStatus() {
      try {
        const st = await api("evilPortalStatus");
        setLive(st);
        // In passthrough mode, also pull per-client DNS/traffic intel each poll.
        if (st && st.running && st.state && st.state.internet) {
          try {
            setTraffic(await api("evilPortalTraffic"));
          } catch (e) {
            /* traffic view is best-effort; ignore transient errors */
          }
        } else {
          setTraffic(null);
        }
        return st;
      } catch (err) {
        setError(err.message);
        return null;
      }
    }

    React.useEffect(() => {
      refreshStatus();
      return () => {
        if (pollRef.current) {
          clearInterval(pollRef.current);
        }
      };
    }, []);

    React.useEffect(() => {
      if ((!targetBssid || !targets.some((t) => t.bssid === targetBssid)) && targets[0]) {
        setTargetBssid(targets[0].bssid);
      }
    }, [authorizedTargets]);

    function startPolling() {
      if (pollRef.current) {
        clearInterval(pollRef.current);
      }
      pollRef.current = setInterval(refreshStatus, 4000);
    }

    function stopPolling() {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    }

    function changeBand(next) {
      setBand(next);
      setChannel(next === "5g" ? EVIL_5G_CHANNELS[0] : 6);
    }

    function toggleInternet(on) {
      setInternet(on);
      // Passthrough needs radio0 for the uplink, so the twin must live on 2.4GHz.
      if (on && band !== "2g") {
        changeBand("2g");
      }
    }

    React.useEffect(() => {
      if (running) {
        startPolling();
      } else {
        stopPolling();
      }
      return stopPolling;
    }, [running]);

    async function startPortal() {
      if (!selected) {
        return;
      }
      if (!internet && template === "custom" && !customHtml.trim()) {
        setError("Custom template needs HTML with a form posting to /cgi-bin/submit.");
        return;
      }
      setStarting(true);
      setError("");
      setNote("");
      try {
        // Passthrough has no captive page, so send a safe template to satisfy validation.
        const result = await api("startEvilPortal", { bssid: selected.bssid, ssid: selected.ssid || "", authorized: true, band, channel: Number(channel), internet, template: internet ? "wifi" : template, customHtml });
        setNote(result.note || "");
        setLive({ running: true, state: result.state, clients: [], credentials: [] });
        await refreshStatus();
      } catch (err) {
        setError(err.message);
      } finally {
        setStarting(false);
      }
    }

    async function stopPortal() {
      setError("");
      try {
        await api("stopEvilPortal");
        stopPolling();
        setLive({ running: false });
        setNote("");
      } catch (err) {
        setError(err.message);
      }
    }

    async function clearCreds() {
      try {
        await api("clearPortalCreds");
        await refreshStatus();
      } catch (err) {
        setError(err.message);
      }
    }

    const state = (live && live.state) || {};
    const clients = (live && live.clients) || [];
    const credentials = (live && live.credentials) || [];
    const verifiedPassword = live && live.verifiedPassword;
    const passthrough = Boolean(state.internet);

    return h(
      Panel,
      {
        title: "Evil Portal (Twin AP)",
        icon: "wifi",
        action: h(Button, { size: "sm", variant: "outline-secondary", onClick: refreshStatus, disabled: starting }, h(Icon, { name: "refresh-cw" })),
      },
      h(
        Alert,
        { variant: "warning", className: "py-2" },
        h("strong", null, "Authorized targets only. "),
        "Stands up an OPEN twin AP cloning the target's SSID. ",
        h("em", null, "Captive"),
        " mode serves a login page — pick a template (Wi-Fi password with offline handshake-verify, Router admin, ISP sign-in, or your own HTML) and every submitted field is captured. ",
        h("em", null, "Internet passthrough"),
        " mode instead NATs clients out through the 5GHz uplink so they get real internet while their DNS + transit traffic are logged, and unlocks the ",
        h("strong", null, "MITM toolkit"),
        " (DNS spoofing + HTTP session/credential sniffing). 2.4GHz uses radio1; passthrough requires Internet (uplink) mode and runs on 2.4GHz. Only run this against a network you own."
      ),
      error ? h(Alert, { variant: "danger", className: "py-2" }, error) : null,
      note ? h(Alert, { variant: "info", className: "py-2" }, note) : null,
      !toolsReady
        ? h(Alert, { variant: "secondary", className: "py-2" }, "Evil Portal needs hostapd, dnsmasq, nft and uhttpd installed.")
        : running
        ? h(
            React.Fragment,
            null,
            h(
              "div",
              { className: "border rounded p-3 mb-3 bg-body-tertiary" },
              h(
                "div",
                { className: "d-flex align-items-center justify-content-between mb-2" },
                h(
                  "div",
                  null,
                  h(Badge, { bg: "success", className: "me-2" }, "LIVE"),
                  h(Badge, { bg: passthrough ? "danger" : "dark", className: "me-2" }, passthrough ? "PASSTHROUGH MITM" : `CAPTIVE · ${String(state.template || "?").toUpperCase()}`),
                  h("span", { className: "fw-semibold" }, `Twin "${state.ssid || "?"}"`),
                  h("span", { className: "text-body-secondary ms-2" }, `${state.band === "5g" ? "5GHz" : "2.4GHz"} ch ${state.channel || "?"} · ${state.portalIp || "10.0.0.1"} · ${state.iface || "evtwin0"}`)
                ),
                h(Button, { variant: "danger", onClick: stopPortal }, h("span", { className: "me-2" }, h(Icon, { name: "power" })), "Stop Twin")
              ),
              h(
                "div",
                { className: "d-flex flex-wrap gap-2 align-items-center" },
                passthrough
                  ? h(Badge, { bg: "danger" }, `NAT via ${state.uplinkDev || "uplink"}`)
                  : h(Badge, { bg: state.verify ? "success" : "secondary" }, state.verify ? "offline verify armed" : "no handshake — verify off"),
                h(Badge, { bg: "info" }, `${clients.length} connected`),
                passthrough
                  ? h(Badge, { bg: "primary" }, "DNS + pcap logging")
                  : h(Badge, { bg: credentials.length ? "primary" : "secondary" }, `${credentials.length} submission${credentials.length === 1 ? "" : "s"}`),
                h("small", { className: "text-body-secondary" }, "auto-refreshing every 4s")
              )
            ),
            verifiedPassword && !passthrough
              ? h(
                  Alert,
                  { variant: "success", className: "py-2" },
                  h("strong", null, "Passphrase confirmed: "),
                  h("code", null, verifiedPassword),
                  " — matches the captured handshake for this target."
                )
              : null,
            h(
              Row,
              { className: "g-3" },
              h(Col, { lg: 5 }, h("div", { className: "fw-semibold mb-2" }, "Connected Devices"), h(EvilPortalClientsTable, { clients })),
              passthrough
                ? h(Col, { lg: 7 }, h(EvilPortalTrafficPanel, { traffic }))
                : h(
                    Col,
                    { lg: 7 },
                    h(
                      "div",
                      { className: "d-flex justify-content-between align-items-center mb-2" },
                      h("div", { className: "fw-semibold" }, "Captured Submissions"),
                      credentials.length ? h(Button, { size: "sm", variant: "outline-danger", onClick: clearCreds }, h(Icon, { name: "trash-2" }), " Clear") : null
                    ),
                    h(PortalKitCredsTable, { credentials })
                  )
            ),
            passthrough ? h(MitmPanel, null) : null
          )
        : authorizedTargets.length === 0
        ? h(Alert, { variant: "info", className: "py-2" }, "No authorized targets. Select a target in the Recon panel and mark it as an ", h("em", null, "Authorized lab target"), " to clone it.")
        : h(
            React.Fragment,
            null,
            h(
              "div",
              { className: "border rounded p-2 mb-3 d-flex flex-wrap align-items-center gap-3 bg-body-tertiary" },
              h(Form.Check, {
                type: "switch",
                id: "evil-internet-switch",
                label: "Internet passthrough (MITM)",
                checked: internet,
                disabled: starting,
                onChange: (e) => toggleInternet(e.target.checked),
              }),
              h(
                "small",
                { className: "text-body-secondary" },
                internet
                  ? "Clients get real internet via the 5GHz uplink; DNS + transit traffic are logged. Twin runs on 2.4GHz. Requires Internet (uplink) mode."
                  : "Captive portal — serves a login template and captures every submitted field. No upstream internet for clients."
              )
            ),
            !internet
              ? h(
                  Row,
                  { className: "g-2 align-items-end mb-3" },
                  h(Col, { md: 5 }, h(Form.Group, null, h(Form.Label, null, "Captive login template"), h(Form.Select, { value: template, onChange: (e) => setTemplate(e.target.value), disabled: starting }, PK_TEMPLATES.map((t) => h("option", { key: t.id, value: t.id }, t.label))))),
                  h(Col, { md: 7 }, h("div", { className: "small text-body-secondary" }, (PK_TEMPLATES.find((t) => t.id === template) || {}).desc || ""))
                )
              : null,
            !internet && template === "custom"
              ? h(Form.Group, { className: "mb-3" }, h(Form.Label, null, "Custom HTML (must contain a form posting to /cgi-bin/submit)"), h(Form.Control, { as: "textarea", rows: 5, value: customHtml, onChange: (e) => setCustomHtml(e.target.value), placeholder: "<form method=post action=/cgi-bin/submit> ... </form>", disabled: starting, style: { fontFamily: "monospace", fontSize: "0.8rem" } }))
              : null,
            h(
              Row,
              { className: "g-2 align-items-end mb-3" },
              h(
                Col,
                { md: 4 },
                h(Form.Group, null, h(Form.Label, null, "Target to clone"), h(Form.Select, { value: targetBssid, onChange: (e) => setTargetBssid(e.target.value), disabled: starting }, authorizedTargets.map((t) => h("option", { key: t.bssid, value: t.bssid }, `${t.ssid || "<hidden>"} — ${t.bssid}`))))
              ),
              h(
                Col,
                { md: 3 },
                h(Form.Group, null, h(Form.Label, null, "Band"), h(Form.Select, { value: band, onChange: (e) => changeBand(e.target.value), disabled: starting || internet }, h("option", { value: "2g" }, "2.4 GHz (radio1)"), internet ? null : h("option", { value: "5g" }, "5 GHz (radio0, Lab mode)")))
              ),
              h(
                Col,
                { md: 3 },
                h(
                  Form.Group,
                  null,
                  h(Form.Label, null, band === "5g" ? "Twin channel (5GHz, non-DFS)" : "Twin channel (2.4GHz)"),
                  h(
                    Form.Select,
                    { value: channel, onChange: (e) => setChannel(Number(e.target.value)), disabled: starting },
                    (band === "5g" ? EVIL_5G_CHANNELS : Array.from({ length: 13 }, (_, i) => i + 1)).map((ch) => h("option", { key: ch, value: ch }, `ch ${ch}`))
                  )
                )
              ),
              h(
                Col,
                { md: "auto" },
                h(Button, { variant: "primary", onClick: startPortal, disabled: !selected || starting }, starting ? h(Spinner, { size: "sm", animation: "border", className: "me-2" }) : h("span", { className: "me-2" }, h(Icon, { name: "wifi" })), "Start Twin AP")
              )
            ),
            selected
              ? h(
                  "small",
                  { className: "text-body-secondary" },
                  `Will broadcast open SSID "${selected.ssid}" on ${band === "5g" ? "radio0 (5GHz — requires Lab mode)" : "radio1 (2.4GHz)"}. `,
                  findHandshakeHint(selected)
                )
              : null
          )
    );
  }

  function findHandshakeHint() {
    return "For offline passphrase verification, run a Capture on this target first so a handshake is available.";
  }

  const PK_TEMPLATES = [
    { id: "router", label: "Router admin login", desc: "Generic router admin sign-in (username + password)." },
    { id: "isp", label: "Internet sign-in", desc: "Generic ISP / Wi-Fi sign-in (email + password)." },
    { id: "wifi", label: "Wi-Fi password", desc: "Asks for the network password (verifies offline vs a captured handshake)." },
    { id: "custom", label: "Custom HTML", desc: "Your own page; it must post to /cgi-bin/submit." },
  ];

  function PortalKitCredsTable({ credentials }) {
    if (!credentials || !credentials.length) {
      return h("div", { className: "text-body-secondary small" }, "No submissions yet. When a device on the twin submits the login form, its captured fields appear here.");
    }
    return h(
      Table,
      { striped: true, hover: true, responsive: true, size: "sm", className: "mb-0" },
      h("thead", null, h("tr", null, h("th", null, "Time"), h("th", null, "IP"), h("th", null, "Template"), h("th", null, "Captured fields"))),
      h(
        "tbody",
        null,
        credentials
          .slice()
          .reverse()
          .map((c, i) =>
            h(
              "tr",
              { key: i },
              h("td", null, h("small", null, c.time || "-")),
              h("td", null, h("code", null, c.ip || "-")),
              h("td", null, h(Badge, { bg: "dark" }, c.template || "?")),
              h("td", null, h("code", { style: { whiteSpace: "pre-wrap", wordBreak: "break-all" } }, c.fields || "-"))
            )
          )
      )
    );
  }

  function PnlClientsTable({ clients, onPickSsid }) {
    const rows = (clients || []).filter((c) => c.probes && c.probes.length);
    if (!rows.length) {
      return h("div", { className: "text-body-secondary small" }, "No probe requests captured yet. Nearby devices reveal the names of networks they remember (their PNL) while searching for Wi-Fi — run a harvest with the target devices powered on and nearby.");
    }
    return h(
      Table,
      { striped: true, hover: true, responsive: true, size: "sm", className: "mb-0" },
      h("thead", null, h("tr", null, h("th", null, "Device"), h("th", null, "Signal"), h("th", null, "Probing for (saved networks)"), h("th", null, "Assoc"))),
      h(
        "tbody",
        null,
        rows.map((c, i) =>
          h(
            "tr",
            { key: c.mac || i },
            h("td", null, h("code", null, c.mac || "-"), c.vendor ? h("div", null, h("small", { className: "text-body-secondary" }, c.vendor)) : null),
            h("td", null, c.signal ? h(Badge, { bg: signalVariant(c.signal) }, c.signal) : h("small", { className: "text-body-secondary" }, "-")),
            h("td", null, h("div", { className: "d-flex flex-wrap gap-1" }, c.probes.map((p, j) => h(Button, { key: j, size: "sm", variant: "outline-secondary", className: "py-0 px-2", style: { fontSize: "0.72rem" }, title: "Use this SSID for the evil-twin test", onClick: () => onPickSsid && onPickSsid(p) }, p)))),
            h("td", null, c.bssid ? h("code", { className: "small" }, c.bssid) : h("small", { className: "text-body-secondary" }, "-"))
          )
        )
      )
    );
  }

  function KarmaPanel({ status, onActivity }) {
    const [harvestDuration, setHarvestDuration] = React.useState(45);
    const [harvesting, setHarvesting] = React.useState(false);
    const [clients, setClients] = React.useState([]);
    const [harvestErr, setHarvestErr] = React.useState("");
    const cancelRef = React.useRef(false);

    const [ssid, setSsid] = React.useState("");
    const [channel, setChannel] = React.useState(6);
    const [starting, setStarting] = React.useState(false);
    const [live, setLive] = React.useState(null);
    const [karmaErr, setKarmaErr] = React.useState("");
    const pollRef = React.useRef(null);

    const apReady = toolInstalled(status, "hostapd") && toolInstalled(status, "dnsmasq");
    const running = Boolean(live && live.running);
    React.useEffect(() => {
      if (onActivity) onActivity(running || harvesting);
    }, [running, harvesting]);

    async function refreshKarma() {
      try {
        const st = await api("karmaStatus");
        setLive(st);
        return st;
      } catch (err) {
        setKarmaErr(err.message);
        return null;
      }
    }
    React.useEffect(() => {
      refreshKarma();
      return () => {
        if (pollRef.current) clearInterval(pollRef.current);
      };
    }, []);
    function startPolling() {
      if (pollRef.current) clearInterval(pollRef.current);
      pollRef.current = setInterval(refreshKarma, 4000);
    }
    function stopPolling() {
      if (pollRef.current) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    }
    React.useEffect(() => {
      if (running) startPolling();
      else stopPolling();
      return stopPolling;
    }, [running]);

    async function harvest() {
      setHarvesting(true);
      setHarvestErr("");
      setClients([]);
      cancelRef.current = false;
      try {
        const started = await api("startBeaconHarvest", { band: "2g", duration: harvestDuration });
        const loops = Math.ceil(harvestDuration / 3) + 25;
        for (let i = 0; i < loops; i++) {
          if (cancelRef.current) break;
          await sleep(3000);
          const st = await api("beaconHarvestStatus", { jobId: started.jobId });
          if (st.clients) setClients(st.clients);
          if (!st.pending) {
            setClients(st.clients || []);
            break;
          }
        }
      } catch (err) {
        setHarvestErr(err.message);
      } finally {
        setHarvesting(false);
      }
    }

    async function startKarma() {
      if (!ssid.trim()) {
        setKarmaErr("Enter an SSID you own to broadcast.");
        return;
      }
      setStarting(true);
      setKarmaErr("");
      try {
        const result = await api("startKarma", { ssid: ssid.trim(), channel: Number(channel), authorized: true });
        setLive({ running: true, state: result.state, associated: [], leased: [] });
        await refreshKarma();
      } catch (err) {
        setKarmaErr(err.message);
      } finally {
        setStarting(false);
      }
    }
    async function stopKarma() {
      setKarmaErr("");
      try {
        await api("stopKarma");
        stopPolling();
        setLive({ running: false });
      } catch (err) {
        setKarmaErr(err.message);
      }
    }

    const state = (live && live.state) || {};
    // Backend returns the full cumulative "joined" list in `associated` (MAC,
    // vendor, signal, connected-now flag, and IP/hostname if it got a lease).
    const joined = (live && live.associated) || [];
    const exposed = live && live.exposed;

    return h(
      Panel,
      { title: "Rogue AP / KARMA", icon: "radio" },
      h(
        Alert,
        { variant: "warning", className: "py-2" },
        h("strong", null, "Authorized self-assessment only. "),
        "Part 1 passively logs which saved-network names nearby devices are searching for (their PNL). Part 2 broadcasts an OPEN evil-twin of an SSID ",
        h("strong", null, "you own"),
        " and shows which of ",
        h("strong", null, "your"),
        " devices auto-join. It does not respond to arbitrary probes and must not be used against devices you don't control."
      ),
      h("div", { className: "fw-semibold mb-2" }, h(Icon, { name: "search" }), " 1. Preferred-Network (PNL) harvest"),
      harvestErr ? h(Alert, { variant: "danger", className: "py-2" }, harvestErr) : null,
      h(
        Row,
        { className: "g-2 align-items-end mb-2" },
        h(Col, { md: 4 }, h(Form.Group, null, h(Form.Label, null, `Duration: ${harvestDuration}s`), h(Form.Range, { min: 15, max: 120, step: 5, value: harvestDuration, onChange: (e) => setHarvestDuration(Number(e.target.value)), disabled: harvesting }))),
        h(Col, { md: "auto" }, h(Button, { onClick: harvest, disabled: harvesting }, harvesting ? h(Spinner, { size: "sm", animation: "border", className: "me-2" }) : h("span", { className: "me-2" }, h(Icon, { name: "search" })), "Harvest PNLs"))
      ),
      h("div", { className: "small text-body-secondary mb-2" }, "Passive, 2.4 GHz (radio1), no uplink impact. Click a network name to load it into the evil-twin test below."),
      h(PnlClientsTable, { clients, onPickSsid: (s) => setSsid(s) }),
      h("hr", null),
      h("div", { className: "fw-semibold mb-2" }, h(Icon, { name: "radio" }), " 2. Evil-twin exposure test"),
      karmaErr ? h(Alert, { variant: "danger", className: "py-2" }, karmaErr) : null,
      !apReady
        ? h(Alert, { variant: "secondary", className: "py-2" }, "hostapd / dnsmasq not available.")
        : running
        ? h(
            React.Fragment,
            null,
            h(
              "div",
              { className: "border rounded p-3 mb-2 bg-body-tertiary" },
              h(
                "div",
                { className: "d-flex align-items-center justify-content-between mb-2" },
                h(
                  "div",
                  null,
                  h(Badge, { bg: "danger", className: "me-2" }, "BROADCASTING"),
                  h("span", { className: "fw-semibold" }, `Twin "${state.ssid || "?"}"`),
                  h("span", { className: "text-body-secondary ms-2" }, `2.4GHz ch ${state.channel || "?"} · ${state.apIp || "10.0.1.1"}`)
                ),
                h(Button, { variant: "danger", onClick: stopKarma }, h("span", { className: "me-2" }, h(Icon, { name: "power" })), "Stop")
              ),
              exposed
                ? h(Alert, { variant: "danger", className: "py-2 mb-0" }, h(Icon, { name: "alert-triangle" }), ` Exposure confirmed - ${joined.length} device${joined.length === 1 ? "" : "s"} auto-joined the spoofed "${state.ssid}".`)
                : h(Alert, { variant: "success", className: "py-2 mb-0" }, h(Icon, { name: "shield" }), " No device has joined yet. A device that remembers this SSID and auto-connects will appear below.")
            ),
            h("div", { className: "fw-semibold mb-2" }, "Devices that joined the twin"),
            joined.length
              ? h(
                  Table,
                  { striped: true, hover: true, responsive: true, size: "sm", className: "mb-0" },
                  h("thead", null, h("tr", null, h("th", null, "Device"), h("th", null, "Signal"), h("th", null, "IP"), h("th", null, "Status"))),
                  h(
                    "tbody",
                    null,
                    joined.map((d, i) =>
                      h(
                        "tr",
                        { key: d.mac || i },
                        h("td", null, h("code", null, d.mac || "-"), d.vendor ? h("div", null, h("small", { className: "text-body-secondary" }, d.vendor)) : null),
                        h("td", null, d.signal ? h(Badge, { bg: signalVariant(d.signal) }, d.signal) : h("small", { className: "text-body-secondary" }, "-")),
                        h("td", null, d.ip ? h("code", null, d.ip) : "-"),
                        h("td", null, d.connected ? h(Badge, { bg: "success" }, "connected") : h(Badge, { bg: "secondary" }, "seen"))
                      )
                    )
                  )
                )
              : h("div", { className: "text-body-secondary small" }, "None yet.")
          )
        : h(
            React.Fragment,
            null,
            h(
              Row,
              { className: "g-2 align-items-end mb-2" },
              h(Col, { md: 5 }, h(Form.Group, null, h(Form.Label, null, "SSID to broadcast (one you own)"), h(Form.Control, { value: ssid, maxLength: 32, placeholder: "e.g. your home network name", onChange: (e) => setSsid(e.target.value), disabled: starting }))),
              h(Col, { md: 3 }, h(Form.Group, null, h(Form.Label, null, "Channel"), h(Form.Select, { value: channel, onChange: (e) => setChannel(Number(e.target.value)), disabled: starting }, Array.from({ length: 13 }, (_, i) => i + 1).map((ch) => h("option", { key: ch, value: ch }, `ch ${ch}`))))),
              h(Col, { md: "auto" }, h(Button, { variant: "primary", onClick: startKarma, disabled: starting || !ssid.trim() }, starting ? h(Spinner, { size: "sm", animation: "border", className: "me-2" }) : h("span", { className: "me-2" }, h(Icon, { name: "radio" })), "Broadcast twin"))
            ),
            h("div", { className: "small text-body-secondary" }, "Runs hostapd on 2.4 GHz radio1 (needs the radio free - Lab mode). Broadcasts an OPEN AP with this name; a device that remembers the network and auto-connects shows up above via the AP's station table. Use your own SSID only.")
          )
    );
  }

  function RadioControlPanel({ onChanged }) {
    const [mode, setMode] = React.useState(null);
    const [switching, setSwitching] = React.useState("");
    const [error, setError] = React.useState("");

    async function load() {
      try {
        setMode(await api("getRadioMode"));
      } catch (err) {
        setError(err.message);
      }
    }

    React.useEffect(() => {
      load();
    }, []);

    async function switchTo(target) {
      setSwitching(target);
      setError("");
      try {
        const result = await api("setRadioMode", { mode: target });
        setMode(result);
        if (onChanged) {
          onChanged();
        }
      } catch (err) {
        setError(err.message);
      } finally {
        setSwitching("");
      }
    }

    const current = mode && mode.mode;
    const busy = Boolean(switching);

    return h(
      Panel,
      {
        title: "Radio Control",
        icon: "radio",
        action: h(Button, { size: "sm", variant: "outline-secondary", onClick: load, disabled: busy }, h(Icon, { name: "refresh-cw" })),
      },
      error ? h(Alert, { variant: "danger", className: "py-2" }, error) : null,
      h(
        "div",
        { className: "d-flex flex-wrap align-items-center gap-2 mb-3" },
        h("span", { className: "text-body-secondary" }, "Current mode:"),
        current === "uplink"
          ? h(Badge, { bg: "success" }, "Internet ON")
          : current === "lab"
          ? h(Badge, { bg: "warning", text: "dark" }, "Lab — both radios free")
          : current
          ? h(Badge, { bg: "secondary" }, "Custom config")
          : h(Spinner, { size: "sm", animation: "border" }),
        mode && mode.internet ? h(Badge, { bg: "info" }, `uplink: ${mode.uplinkSsid || "connected"}`) : mode && current === "uplink" ? h(Badge, { bg: "secondary" }, "uplink not associated") : null
      ),
      mode
        ? h(
            Table,
            { size: "sm", responsive: true, className: "mb-3" },
            h("thead", null, h("tr", null, h("th", null, "Radio"), h("th", null, "Band"), h("th", null, "Role"))),
            h(
              "tbody",
              null,
              ["radio0", "radio1"].map((key) => {
                const r = (mode.radios || {})[key] || {};
                return h(
                  "tr",
                  { key },
                  h("td", null, key),
                  h("td", null, r.band === "5g" ? "5 GHz" : r.band === "2g" ? "2.4 GHz" : "-"),
                  h("td", null, h(Badge, { bg: r.free ? "secondary" : "success" }, r.role || "-"))
                );
              })
            )
          )
        : null,
      h(
        Alert,
        { variant: "info", className: "py-2" },
        "Switching modes reconfigures the WiFi radios and takes a few seconds. ",
        h("strong", null, "Internet ON"),
        " joins your saved uplink network on 5GHz (internet up, 2.4GHz free). ",
        h("strong", null, "Lab"),
        " frees both radios for testing on 2.4GHz and 5GHz (no WiFi internet — this management UI stays up over Ethernet)."
      ),
      h(
        "div",
        { className: "d-flex flex-wrap gap-2" },
        h(
          Button,
          { variant: current === "uplink" ? "success" : "outline-success", onClick: () => switchTo("uplink"), disabled: busy || current === "uplink" },
          switching === "uplink" ? h(Spinner, { size: "sm", animation: "border", className: "me-2" }) : h("span", { className: "me-2" }, h(Icon, { name: "globe" })),
          "Internet ON"
        ),
        h(
          Button,
          { variant: current === "lab" ? "warning" : "outline-warning", onClick: () => switchTo("lab"), disabled: busy || current === "lab" },
          switching === "lab" ? h(Spinner, { size: "sm", animation: "border", className: "me-2" }) : h("span", { className: "me-2" }, h(Icon, { name: "zap" })),
          "Lab (both free)"
        )
      )
    );
  }

  // Scoped styling for the tabbed shell. Uses Bootstrap 5.3 CSS variables so it
  // tracks the host light/dark theme instead of hardcoding colors.
  const WA_CSS = `
.wa-root .wa-header{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;flex-wrap:wrap;margin-bottom:1.1rem}
.wa-root .wa-title{font-size:1.5rem;font-weight:650;letter-spacing:-0.01em;margin:0;line-height:1.2}
.wa-root .wa-sub{color:var(--bs-secondary-color);font-size:.9rem;margin-top:.15rem}
.wa-root .wa-state{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
.wa-root .wa-pill{display:inline-flex;align-items:center;gap:.4rem;font-size:.8rem;font-weight:500;padding:.32rem .6rem;border-radius:999px;border:1px solid var(--bs-border-color);background:var(--bs-body-bg);color:var(--bs-body-color);white-space:nowrap}
.wa-root .wa-dot{width:.5rem;height:.5rem;border-radius:50%;flex:0 0 auto;background:var(--bs-secondary-color)}
.wa-root .wa-dot.on{background:var(--bs-success);box-shadow:0 0 0 3px rgba(var(--bs-success-rgb),.18)}
.wa-root .wa-dot.lab{background:var(--bs-warning)}
.wa-root .wa-tabs{display:flex;align-items:stretch;gap:.15rem;overflow-x:auto;border-bottom:1px solid var(--bs-border-color);margin-bottom:1.25rem;scrollbar-width:thin}
.wa-root .wa-tab{appearance:none;border:0;background:transparent;color:var(--bs-secondary-color);font-size:.9rem;font-weight:500;padding:.6rem .85rem;border-bottom:2px solid transparent;margin-bottom:-1px;cursor:pointer;white-space:nowrap;display:inline-flex;align-items:center;gap:.45rem;border-radius:.375rem .375rem 0 0;transition:color .18s ease,background-color .18s ease,border-color .18s ease}
.wa-root .wa-tab:hover{color:var(--bs-body-color);background:var(--bs-secondary-bg)}
.wa-root .wa-tab:focus-visible{outline:2px solid var(--bs-primary);outline-offset:-2px}
.wa-root .wa-tab.active{color:var(--bs-primary);border-bottom-color:var(--bs-primary);font-weight:600}
.wa-root .wa-tab-count{font-size:.7rem;font-weight:600;padding:.05rem .4rem;border-radius:999px;background:var(--bs-secondary-bg);color:var(--bs-secondary-color)}
.wa-root .wa-tab.active .wa-tab-count{background:var(--bs-primary);color:var(--bs-white,#fff)}
.wa-root .wa-tab-live{width:.5rem;height:.5rem;border-radius:50%;background:var(--bs-success);flex:0 0 auto;animation:wa-pulse 1.6s ease-in-out infinite}
.wa-root .wa-sep{width:1px;align-self:center;height:1.3rem;background:var(--bs-border-color);margin:0 .3rem;flex:0 0 auto}
@keyframes wa-pulse{0%,100%{opacity:1}50%{opacity:.35}}
@media (prefers-reduced-motion:reduce){.wa-root .wa-tab{transition:none}.wa-root .wa-tab-live{animation:none}}
`;

  function WaStyles() {
    return h("style", { dangerouslySetInnerHTML: { __html: WA_CSS } });
  }

  const TABS = [
    { id: "overview", label: "Overview", icon: "activity", group: "state" },
    { id: "recon", label: "Recon", icon: "search", group: "recon" },
    { id: "capture", label: "Capture", icon: "target", group: "attack" },
    { id: "clientless", label: "Clientless", icon: "crosshair", group: "attack" },
    { id: "wps", label: "WPS", icon: "key", group: "attack" },
    { id: "beacon", label: "Beacon", icon: "rss", group: "attack" },
    { id: "evil", label: "Evil Portal", icon: "wifi", group: "attack" },
    { id: "karma", label: "Rogue AP", icon: "radio", group: "attack" },
    { id: "network", label: "Network", icon: "globe", group: "attack" },
    { id: "sniff", label: "Packet Intel", icon: "eye", group: "attack" },
    { id: "crack", label: "Crack Lab", icon: "unlock", group: "attack" },
    { id: "system", label: "System", icon: "tool", group: "state" },
  ];

  function TabBar({ active, onSelect, badges, live }) {
    const items = [];
    let prevGroup = null;
    TABS.forEach((tab) => {
      if (prevGroup && tab.group !== prevGroup) {
        items.push(h("span", { key: `sep-${tab.id}`, className: "wa-sep", "aria-hidden": "true" }));
      }
      prevGroup = tab.group;
      const count = badges && badges[tab.id];
      items.push(
        h(
          "button",
          {
            key: tab.id,
            type: "button",
            className: `wa-tab ${active === tab.id ? "active" : ""}`,
            "aria-current": active === tab.id ? "page" : null,
            onClick: () => onSelect(tab.id),
          },
          h(Icon, { name: tab.icon }),
          h("span", null, tab.label),
          live && live[tab.id] ? h("span", { className: "wa-tab-live", title: "Running" }) : null,
          count ? h("span", { className: "wa-tab-count" }, count) : null
        )
      );
    });
    return h("div", { className: "wa-tabs", role: "tablist" }, items);
  }

  function TabPane({ active, id, children }) {
    // Stay mounted so live polling (captures, WPS, Evil Portal) and in-progress
    // state survive tab switches; just hide when not active.
    return h("div", { className: "wa-pane", style: { display: active === id ? "block" : "none" } }, children);
  }

  function App() {
    const [status, setStatus] = React.useState(null);
    const [radioMode, setRadioMode] = React.useState(null);
    const [activeTab, setActiveTab] = React.useState("overview");
    const [loading, setLoading] = React.useState(true);
    const [error, setError] = React.useState("");
    // Ephemeral, browser-only authorization: which APs the operator has confirmed
    // they own. Nothing is persisted — this clears on refresh/reopen.
    const [authorized, setAuthorized] = React.useState({});
    // Which tabs have a live operation running (drives the pulsing tab indicator).
    const [liveTabs, setLiveTabs] = React.useState({});
    const reportActivity = React.useCallback(
      (id, on) => setLiveTabs((prev) => (prev[id] === on ? prev : Object.assign({}, prev, { [id]: on }))),
      []
    );

    function authorizeTarget(t) {
      if (!t || !t.bssid) {
        return;
      }
      setAuthorized((prev) =>
        Object.assign({}, prev, {
          [t.bssid]: {
            bssid: t.bssid,
            ssid: t.ssid || "",
            channel: t.channel || "",
            band: t.band || (Number(t.channel) > 14 ? "5g" : "2g"),
            security: t.security || "",
            wps: t.wps || (prev[t.bssid] && prev[t.bssid].wps) || null,
          },
        })
      );
    }

    function unauthorizeTarget(bssid) {
      setAuthorized((prev) => {
        const next = Object.assign({}, prev);
        delete next[bssid];
        return next;
      });
    }

    const authorizedList = Object.values(authorized);

    async function refresh() {
      setLoading(true);
      setError("");
      try {
        setStatus(await api("moduleStatus"));
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
      // Radio mode drives the header state pill; a failure here shouldn't block
      // the rest of the dashboard.
      try {
        setRadioMode(await api("getRadioMode"));
      } catch (err) {
        /* header pill just stays neutral */
      }
    }

    React.useEffect(() => {
      refresh();
    }, []);

    if (loading && !status) {
      return h(Alert, { variant: "info" }, h(Spinner, { size: "sm", animation: "border", className: "me-2" }), "Loading Wireless Assessment Center...");
    }

    if (error && !status) {
      return h(Alert, { variant: "danger" }, error);
    }

    const mode = radioMode && radioMode.mode;
    const modePill =
      mode === "uplink"
        ? h("span", { className: "wa-pill", title: radioMode.internet ? `Uplink: ${radioMode.uplinkSsid || "connected"}` : "Uplink not yet associated" }, h("span", { className: "wa-dot on" }), radioMode.internet ? `Internet · ${radioMode.uplinkSsid || "up"}` : "Internet (linking…)")
        : mode === "lab"
        ? h("span", { className: "wa-pill", title: "Both radios free for testing; no WiFi uplink" }, h("span", { className: "wa-dot lab" }), "Lab · both radios free")
        : mode
        ? h("span", { className: "wa-pill" }, h("span", { className: "wa-dot" }), "Custom radio config")
        : null;

    const badges = { recon: authorizedList.length || null };

    return h(
      "div",
      { className: "wa-root" },
      h(WaStyles),
      h(
        "header",
        { className: "wa-header" },
        h(
          "div",
          null,
          h("h1", { className: "wa-title" }, "Wireless Assessment Center"),
          h("div", { className: "wa-sub" }, "Authorized wireless lab assessment for your own networks.")
        ),
        h(
          "div",
          { className: "wa-state" },
          modePill,
          h("span", { className: "wa-pill", title: "Networks you have marked as authorized this session" }, h(Icon, { name: "target" }), `${authorizedList.length} authorized`),
          h(Button, { size: "sm", variant: "outline-primary", onClick: refresh, disabled: loading }, loading ? h(Spinner, { size: "sm", animation: "border", className: "me-2" }) : h("span", { className: "me-2" }, h(Icon, { name: "refresh-cw" })), "Refresh")
        )
      ),
      error ? h(Alert, { variant: "warning" }, error) : null,
      h(TabBar, { active: activeTab, onSelect: setActiveTab, badges, live: liveTabs }),
      h(
        TabPane,
        { active: activeTab, id: "overview" },
        h(StatusSummary, { status }),
        h(Row, { className: "g-3 mb-3" }, h(Col, null, h(RadioControlPanel, { onChanged: refresh }))),
        h(Row, { className: "g-3" }, h(Col, { lg: 6 }, h(Panel, { title: "Radios", icon: "radio" }, h(RadioTable, { radios: status.radios || [] }))), h(Col, { lg: 6 }, h(Panel, { title: "Interfaces", icon: "wifi" }, h(InterfaceTable, { interfaces: status.interfaces || [] }))))
      ),
      h(TabPane, { active: activeTab, id: "recon" }, h(ReconPanel, { status, authorized, authorizeTarget, unauthorizeTarget })),
      h(TabPane, { active: activeTab, id: "capture" }, h(CapturePanel, { status, authorizedTargets: authorizedList, onActivity: (on) => reportActivity("capture", on) })),
      h(TabPane, { active: activeTab, id: "clientless" }, h(ClientlessPanel, { status, authorizedTargets: authorizedList, onActivity: (on) => reportActivity("clientless", on) })),
      h(TabPane, { active: activeTab, id: "wps" }, h(WpsPanel, { status, authorized, authorizeTarget, unauthorizeTarget, onActivity: (on) => reportActivity("wps", on) })),
      h(TabPane, { active: activeTab, id: "beacon" }, h(BeaconPanel, { status, onActivity: (on) => reportActivity("beacon", on) })),
      h(TabPane, { active: activeTab, id: "evil" }, h(EvilPortalPanel, { status, authorizedTargets: authorizedList, onActivity: (on) => reportActivity("evil", on) })),
      h(TabPane, { active: activeTab, id: "karma" }, h(KarmaPanel, { status, onActivity: (on) => reportActivity("karma", on) })),
      h(TabPane, { active: activeTab, id: "network" }, h(LanReconPanel, { status, onActivity: (on) => reportActivity("network", on) })),
      h(TabPane, { active: activeTab, id: "sniff" }, h(SniffPanel, { status, onActivity: (on) => reportActivity("sniff", on) })),
      h(TabPane, { active: activeTab, id: "crack" }, h(CrackPanel, { status, authorizedTargets: authorizedList, onActivity: (on) => reportActivity("crack", on) })),
      h(
        TabPane,
        { active: activeTab, id: "system" },
        h(Row, { className: "g-3" }, h(Col, { lg: 7 }, h(Panel, { title: "Tool Readiness", icon: "tool" }, h(ToolTable, { tools: status.tools || [] }))), h(Col, { lg: 5 }, h(Panel, { title: "Install Candidates", icon: "package" }, h(PackageTable, { packages: status.packages || [] }))))
      )
    );
  }

  return function WirelessAssessmentModule() {
    return h(App);
  };
});