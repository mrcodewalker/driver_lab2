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
    const W = canvas.width = canvas.offsetWidth || 400;
    const keys = Object.keys(data);
    const vals = keys.map(k => data[k]);
    const total = Math.max(vals.reduce((a, b) => a + b, 0), 1);
    const max = Math.max(...vals, 1);

    // Layout
    const ROW_H = 36;   // chiều cao mỗi row (bar + gap)
    const BAR_H = 20;   // chiều cao thanh bar
    const PAD_L = 52;   // cột label bên trái
    const PAD_R = 64;   // cột số bên phải
    const PAD_T = 14;   // padding top
    const PAD_B = 10;
    const H = PAD_T + keys.length * ROW_H + PAD_B;
    canvas.height = H;

    ctx.clearRect(0, 0, W, H);

    const TRACK_W = W - PAD_L - PAD_R;  // chiều rộng vùng bar

    keys.forEach((k, i) => {
        const v = vals[i];
        const pct = v / max;                        // tỉ lệ so với max (không phải total)
        const fillW = Math.round(pct * TRACK_W);
        const y = PAD_T + i * ROW_H;
        const barY = y + (ROW_H - BAR_H) / 2;
        const col = PROTO_COLORS[k] || "#8b949e";
        const pctTot = Math.round(v * 100 / total);

        // ── Track (nền xám) ──
        ctx.beginPath();
        roundRect(ctx, PAD_L, barY, TRACK_W, BAR_H, 4);
        ctx.fillStyle = "#1e2a3a";
        ctx.fill();

        // ── Fill bar ──
        if (fillW > 0) {
            // Gradient: màu solid → sáng hơn ở đầu
            const grad = ctx.createLinearGradient(PAD_L, 0, PAD_L + fillW, 0);
            grad.addColorStop(0, col + "99");   // mờ ở gốc
            grad.addColorStop(1, col);           // đậm ở đầu
            ctx.beginPath();
            roundRect(ctx, PAD_L, barY, fillW, BAR_H, 4);
            ctx.fillStyle = grad;
            ctx.fill();

            // Glow effect — vẽ lại với shadow
            ctx.save();
            ctx.shadowColor = col;
            ctx.shadowBlur = 8;
            ctx.beginPath();
            roundRect(ctx, PAD_L + fillW - 3, barY + 2, 3, BAR_H - 4, 2);
            ctx.fillStyle = col;
            ctx.fill();
            ctx.restore();
        }

        // ── Label trái (tên giao thức) ──
        ctx.fillStyle = "#64748b";
        ctx.font = "500 11px 'JetBrains Mono', monospace";
        ctx.textAlign = "right";
        ctx.textBaseline = "middle";
        ctx.fillText(k, PAD_L - 8, barY + BAR_H / 2);

        // ── Số gói + % bên phải ──
        ctx.fillStyle = col;
        ctx.font = "600 11px 'JetBrains Mono', monospace";
        ctx.textAlign = "left";
        ctx.fillText(fmtNum(v), PAD_L + TRACK_W + 8, barY + BAR_H / 2 - 5);
        ctx.fillStyle = "#334155";
        ctx.font = "400 10px 'JetBrains Mono', monospace";
        ctx.fillText(pctTot + "%", PAD_L + TRACK_W + 8, barY + BAR_H / 2 + 7);
    });

    // ── Đường kẻ dọc grid (mờ) ──
    ctx.strokeStyle = "#162030";
    ctx.lineWidth = 1;
    [0.25, 0.5, 0.75, 1].forEach(t => {
        const x = PAD_L + Math.round(t * TRACK_W);
        ctx.beginPath();
        ctx.moveTo(x, PAD_T);
        ctx.lineTo(x, H - PAD_B);
        ctx.stroke();
    });
}

// Helper: vẽ rect bo góc (polyfill cho ctx.roundRect cũ)
function roundRect(ctx, x, y, w, h, r) {
    if (w < 2 * r) r = w / 2;
    if (h < 2 * r) r = h / 2;
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.quadraticCurveTo(x + w, y, x + w, y + r);
    ctx.lineTo(x + w, y + h - r);
    ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    ctx.lineTo(x + r, y + h);
    ctx.quadraticCurveTo(x, y + h, x, y + h - r);
    ctx.lineTo(x, y + r);
    ctx.quadraticCurveTo(x, y, x + r, y);
    ctx.closePath();
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

            // Security counters từ /proc
            const enc = Number(p["Encrypted"] || 0);
            const tamp = Number(p["Tampered"] || 0);
            const plain = Number(p["Plain"] || 0);
            setEl("ss-enc", enc);
            setEl("ss-tamp", tamp);
            setEl("ss-plain", plain);
            setEl("sec-enc-badge", "ENC: " + enc);
            setEl("sec-tamp-badge", "TAMPER: " + tamp);
            setEl("sec-plain-badge", "PLAIN: " + plain);
            // Cập nhật security events từ dmesg
            updateSecEvents(tamp);

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

function drawProtoBars(_data) {
    // Đã được thay thế bởi drawChart (horizontal bar canvas)
}

// ── Security Events ────────────────────────────────────────────

let _lastTamperCount = 0;

async function updateSecEvents(tampCount) {
    const grid = document.getElementById("sec-grid");
    if (!grid) return;

    // Chỉ refresh khi có thay đổi
    try {
        const r = await fetch("/api/dmesg?n=80");
        const d = await r.json();

        // Lọc các dòng liên quan crypto/security
        const secLines = d.lines.filter(l =>
            /HMAC|CRYPTO|SECURITY|tamper|TAMPER|encrypt|PLAIN/i.test(l)
        );

        if (secLines.length === 0) {
            grid.innerHTML = '<div class="sec-empty">Chưa có sự kiện — chạy demo để xem</div>';
            return;
        }

        grid.innerHTML = secLines.slice(-20).reverse().map(line => {
            const isOk = /HMAC OK|OK.*hợp lệ/i.test(line);
            const isFail = /HMAC FAIL|TAMPER|tamper/i.test(line);
            const isPlain = /PLAIN|plain/i.test(line);
            const isCipher = /plaintext|ciphertext/i.test(line);

            // Extract hex nếu có
            const hexMatch = line.match(/([0-9a-f]{2}(?:\s[0-9a-f]{2})+)/i);
            const hexStr = hexMatch ? hexMatch[0] : "";

            // Timestamp từ dmesg [xxx.xxx]
            const tsMatch = line.match(/\[\s*(\d+\.\d+)\]/);
            const ts = tsMatch ? tsMatch[1] + "s" : "";

            // Clean message
            const msg = line.replace(/^\[.*?\]\s*/, "").replace(/\[aicsemi\]\s*/i, "");

            if (isFail) return `
                <div class="sec-event sec-event-fail">
                    <div class="sec-icon">🚨</div>
                    <div class="sec-body">
                        <div class="sec-title sec-title-fail">HMAC FAIL — Gói bị TAMPER</div>
                        <div class="sec-hex">${escHtml(msg)}</div>
                        ${hexStr ? `<div class="sec-hex" style="color:#f87171">${hexStr}</div>` : ""}
                    </div>
                    <div class="sec-meta">${ts}</div>
                </div>`;
            if (isOk) return `
                <div class="sec-event sec-event-ok">
                    <div class="sec-icon">🔐</div>
                    <div class="sec-body">
                        <div class="sec-title sec-title-ok">HMAC OK — Gói hợp lệ</div>
                        <div class="sec-hex">${escHtml(msg)}</div>
                        ${hexStr ? `<div class="sec-hex" style="color:#34d399">${hexStr}</div>` : ""}
                    </div>
                    <div class="sec-meta">${ts}</div>
                </div>`;
            return `
                <div class="sec-event sec-event-plain">
                    <div class="sec-icon">📦</div>
                    <div class="sec-body">
                        <div class="sec-title sec-title-plain">Crypto info</div>
                        <div class="sec-hex">${escHtml(msg)}</div>
                    </div>
                    <div class="sec-meta">${ts}</div>
                </div>`;
        }).join("");

    } catch (e) { /* ignore */ }
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
    // Vẽ chart placeholder ngay khi load
    drawChart(_chartData);
    await refreshAll();
    setInterval(refreshStatus, 3000);
    setInterval(pollLog, 1500);
    setInterval(loadDmesg, 10000);
})();
