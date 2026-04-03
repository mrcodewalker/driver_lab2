/* app.js — AIC Semi USB Driver Web Monitor */

// ── Chart.js minimal (inline, không cần CDN) ──────────────────
// Dùng canvas 2D tự vẽ, không phụ thuộc thư viện ngoài

const PROTO_COLORS = {
    TCP: "#58a6ff",
    UDP: "#d29922",
    ICMP: "#bc8cff",
    ARP: "#3fb950",
    IPv6: "#ffa657",
    Other: "#8b949e",
};

let _chartData = { TCP: 0, UDP: 0, ICMP: 0, ARP: 0, IPv6: 0, Other: 0 };

function drawChart(data) {
    const canvas = document.getElementById("proto-chart");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const W = canvas.width = canvas.offsetWidth;
    const H = canvas.height = 160;
    ctx.clearRect(0, 0, W, H);

    const keys = Object.keys(data);
    const vals = keys.map(k => data[k]);
    const total = vals.reduce((a, b) => a + b, 0) || 1;
    const cx = W / 2, cy = H / 2, r = Math.min(cx, cy) - 16;

    // Donut
    let angle = -Math.PI / 2;
    keys.forEach((k, i) => {
        const slice = (vals[i] / total) * Math.PI * 2;
        ctx.beginPath();
        ctx.moveTo(cx, cy);
        ctx.arc(cx, cy, r, angle, angle + slice);
        ctx.closePath();
        ctx.fillStyle = PROTO_COLORS[k] || "#8b949e";
        ctx.fill();
        angle += slice;
    });

    // Inner hole
    ctx.beginPath();
    ctx.arc(cx, cy, r * 0.55, 0, Math.PI * 2);
    ctx.fillStyle = "#161b22";
    ctx.fill();

    // Center text
    ctx.fillStyle = "#e6edf3";
    ctx.font = "bold 18px monospace";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText(total, cx, cy - 6);
    ctx.font = "10px sans-serif";
    ctx.fillStyle = "#8b949e";
    ctx.fillText("total TX", cx, cy + 10);

    // Legend (right side)
    const lx = cx + r + 12;
    let ly = cy - (keys.length * 14) / 2;
    keys.forEach((k, i) => {
        const pct = Math.round(vals[i] * 100 / total);
        ctx.fillStyle = PROTO_COLORS[k] || "#8b949e";
        ctx.fillRect(lx, ly + i * 16, 8, 8);
        ctx.fillStyle = "#8b949e";
        ctx.font = "10px sans-serif";
        ctx.textAlign = "left";
        ctx.fillText(`${k} ${pct}%`, lx + 12, ly + i * 16 + 7);
    });
}

// ── Utilities ─────────────────────────────────────────────────

function fmtBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " K";
    if (n < 1073741824) return (n / 1048576).toFixed(2) + " M";
    return (n / 1073741824).toFixed(2) + " G";
}

function fmtNum(n) {
    n = Number(n) || 0;
    if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
    if (n >= 1e3) return (n / 1e3).toFixed(1) + "K";
    return String(n);
}

function toast(msg, color = "#58a6ff") {
    const el = document.getElementById("toast");
    el.textContent = msg;
    el.style.borderColor = color;
    el.style.color = color;
    el.classList.remove("hidden");
    el.classList.add("show");
    clearTimeout(el._t);
    el._t = setTimeout(() => { el.classList.remove("show"); el.classList.add("hidden"); }, 3000);
}

function setDot(id, state) {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = "dot dot-" + state;
}

function setBadge(id, text, cls) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = text;
    el.className = "badge badge-" + cls;
}

function classifyLog(msg) {
    if (/✓|OK|thành công|WIFI|UP|success/i.test(msg)) return "log-ok";
    if (/✗|error|thất bại|FAIL|failed/i.test(msg)) return "log-err";
    if (/⚠|warn|WARNING|STORAGE|modeswitch/i.test(msg)) return "log-warn";
    if (/\[ℹ\]|info|→/i.test(msg)) return "log-info";
    return "log-dim";
}

function appendLog(boxId, lines, withTime = false) {
    const box = document.getElementById(boxId);
    if (!box) return;
    lines.forEach(item => {
        const div = document.createElement("div");
        div.className = "log-line";
        const msg = typeof item === "string" ? item : item.msg;
        const t = typeof item === "object" && item.t ? item.t : "";
        const cls = classifyLog(msg);
        div.innerHTML = withTime
            ? `<span class="log-time">${t}</span><span class="${cls}">${escHtml(msg)}</span>`
            : `<span class="${cls}">${escHtml(msg)}</span>`;
        box.appendChild(div);
    });
    box.scrollTop = box.scrollHeight;
}

function escHtml(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function setEl(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

// ── Status polling ─────────────────────────────────────────────

async function refreshStatus() {
    try {
        const r = await fetch("/api/status");
        const d = await r.json();

        // USB
        const usb = d.usb;
        if (usb.found) {
            setEl("usb-line", usb.line.replace(/^Bus.*ID\s+[a-f0-9:]+\s+/i, "").trim());
            setEl("usb-pid", "0x" + usb.pid);
            if (usb.mode === "wifi") {
                setBadge("usb-mode-badge", "WiFi 8d80", "wifi");
                setDot("dot-usb", "green");
            } else if (usb.mode === "storage") {
                setBadge("usb-mode-badge", "Storage 5721", "storage");
                setDot("dot-usb", "yellow");
            } else {
                setBadge("usb-mode-badge", "Unknown", "none");
                setDot("dot-usb", "gray");
            }
        } else {
            setEl("usb-line", "Not found");
            setBadge("usb-mode-badge", "None", "none");
            setDot("dot-usb", "red");
        }

        // Module
        setDot("dot-mod", d.loaded ? "green" : "red");
        setEl("lbl-mod", d.loaded ? "Module ✓" : "Module ✗");

        // Interface
        const iface = d.iface;
        if (iface.exists) {
            setEl("if-mac", iface.mac || "—");
            setEl("if-ip", iface.ip || "—");
            if (iface.up) {
                setBadge("if-status-badge", "UP", "up");
                setDot("dot-iface", "green");
            } else {
                setBadge("if-status-badge", "DOWN", "down");
                setDot("dot-iface", "yellow");
            }
        } else {
            setBadge("if-status-badge", "Not found", "none");
            setDot("dot-iface", "red");
            setEl("if-mac", "—");
            setEl("if-ip", "—");
        }

        // Stats from /proc
        const p = d.proc;
        if (d.has_proc && Object.keys(p).length) {
            setEl("s-tx", fmtNum(p["TX tổng"] || p["TX total"] || 0));
            setEl("s-rx", fmtNum(p["RX tổng"] || p["RX total"] || 0));
            setEl("s-txb", fmtBytes(p["TX bytes"] || 0));
            setEl("s-drop", fmtNum(p["TX bị rớt"] || p["TX dropped"] || 0));
            setEl("s-tcp", fmtNum(p["TCP"] || 0));
            setEl("s-udp", fmtNum(p["UDP"] || 0));
            setEl("s-icmp", fmtNum(p["ICMP"] || 0));
            setEl("s-arp", fmtNum(p["ARP"] || 0));

            _chartData = {
                TCP: Number(p["TCP"] || 0),
                UDP: Number(p["UDP"] || 0),
                ICMP: Number(p["ICMP"] || 0),
                ARP: Number(p["ARP"] || 0),
                IPv6: Number(p["IPv6"] || 0),
                Other: Number(p["Khác"] || p["Other"] || 0),
            };
            drawChart(_chartData);
            drawProtoBars(_chartData);
        }

        // /proc raw
        if (d.has_proc) {
            const raw = Object.entries(p).map(([k, v]) => `  ${k.padEnd(14)}: ${v}`).join("\n");
            document.getElementById("proc-box").textContent = raw || "—";
        } else {
            document.getElementById("proc-box").textContent = "Driver chưa load hoặc chưa ở WiFi mode";
        }

    } catch (e) {
        console.error("status error", e);
    }
}

function drawProtoBars(data) {
    const box = document.getElementById("proto-bars");
    if (!box) return;
    const total = Object.values(data).reduce((a, b) => a + b, 0) || 1;
    box.innerHTML = Object.entries(data).map(([k, v]) => {
        const pct = Math.round(v * 100 / total);
        const col = PROTO_COLORS[k] || "#8b949e";
        return `<div class="proto-bar-row">
      <div class="proto-bar-lbl">${k}</div>
      <div class="proto-bar-track">
        <div class="proto-bar-fill" style="width:${pct}%;background:${col}"></div>
      </div>
      <div class="proto-bar-cnt">${fmtNum(v)}</div>
    </div>`;
    }).join("");
}

// ── dmesg ──────────────────────────────────────────────────────

async function loadDmesg() {
    const box = document.getElementById("dmesg-box");
    box.innerHTML = "";
    try {
        const r = await fetch("/api/dmesg?n=50");
        const d = await r.json();
        appendLog("dmesg-box", d.lines);
    } catch (e) { box.textContent = "Error loading dmesg"; }
}

// ── Action log polling ─────────────────────────────────────────

let _lastLogLen = 0;
async function pollLog() {
    try {
        const r = await fetch("/api/log");
        const d = await r.json();
        if (d.lines.length > _lastLogLen) {
            const newLines = d.lines.slice(_lastLogLen);
            appendLog("action-log", newLines, true);
            _lastLogLen = d.lines.length;
        }
    } catch (e) { }
}

async function clearLog() {
    await fetch("/api/log/clear", { method: "POST" });
    document.getElementById("action-log").innerHTML = "";
    _lastLogLen = 0;
}

// ── Driver Actions ─────────────────────────────────────────────

const ACTION_LABELS = {
    compile: "Compiling...",
    setup: "Running setup.bash...",
    restart: "Restarting driver...",
    modeswitch: "Forcing modeswitch...",
    demo: "Running demo...",
    unload: "Unloading module...",
    clear_ring: "Clearing ring buffer...",
};

async function doAction(name) {
    const btn = event.currentTarget;
    const orig = btn.textContent;
    btn.disabled = true;
    btn.innerHTML = `<span class="spin">⟳</span> ${ACTION_LABELS[name] || name}`;
    toast(ACTION_LABELS[name] || name, "#58a6ff");

    try {
        const r = await fetch(`/api/action/${name}`, { method: "POST" });
        const d = await r.json();
        if (d.ok) {
            toast(`✓ ${name} OK`, "#3fb950");
        } else {
            toast(`✗ ${name} failed: ${d.stderr || ""}`, "#f85149");
        }
        await refreshStatus();
        await loadDmesg();
    } catch (e) {
        toast(`✗ Network error`, "#f85149");
    } finally {
        btn.disabled = false;
        btn.textContent = orig;
    }
}

// ── Interface UP/DOWN ──────────────────────────────────────────

async function ifUp() {
    const iface = document.getElementById("if-name").textContent.trim() || "aic0";
    const ip = document.getElementById("inp-ip").value.trim() || "192.168.99.1/24";
    toast(`Setting ${iface} UP...`, "#58a6ff");
    const r = await fetch("/api/action/ifup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ iface, ip }),
    });
    const d = await r.json();
    toast(d.ok ? `✓ ${iface} UP — ${ip}` : `✗ ${d.link?.stderr || "failed"}`,
        d.ok ? "#3fb950" : "#f85149");
    await refreshStatus();
}

async function ifDown() {
    const iface = document.getElementById("if-name").textContent.trim() || "aic0";
    toast(`Setting ${iface} DOWN...`, "#d29922");
    const r = await fetch("/api/action/ifdown", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ iface }),
    });
    const d = await r.json();
    toast(d.ok ? `✓ ${iface} DOWN` : `✗ failed`, d.ok ? "#3fb950" : "#f85149");
    await refreshStatus();
}

// ── Ping ──────────────────────────────────────────────────────

async function doPing() {
    const ip = document.getElementById("ping-ip").value.trim();
    const iface = document.getElementById("ping-iface").value.trim() || "aic0";
    const count = document.getElementById("ping-count").value;
    const box = document.getElementById("ping-result");

    if (!ip) { toast("Nhập IP trước", "#f85149"); return; }

    box.className = "ping-result";
    box.textContent = `Pinging ${ip} via ${iface} (${count} packets)...`;
    box.classList.remove("hidden");

    const r = await fetch("/api/action/ping", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, iface, count: Number(count) }),
    });
    const d = await r.json();

    box.className = "ping-result " + (d.ok ? "ping-ok" : "ping-fail");
    box.textContent = d.ok
        ? `✓ ${ip} reachable\n  Loss: ${d.loss}  RTT avg: ${d.rtt_avg}\n\n${d.stdout}`
        : `✗ ${ip} unreachable\n  Loss: ${d.loss}\n\n${d.stdout || d.stderr || ""}`;
}

// ── Clock ─────────────────────────────────────────────────────

function updateClock() {
    const el = document.getElementById("hdr-time");
    if (el) el.textContent = new Date().toLocaleString("vi-VN");
}

// ── Resize chart on window resize ─────────────────────────────

window.addEventListener("resize", () => drawChart(_chartData));

// ── Init ──────────────────────────────────────────────────────

async function refreshAll() {
    await refreshStatus();
    await loadDmesg();
}

(async function init() {
    updateClock();
    setInterval(updateClock, 1000);
    await refreshAll();
    setInterval(refreshStatus, 3000);
    setInterval(pollLog, 1500);
    setInterval(loadDmesg, 10000);
})();
