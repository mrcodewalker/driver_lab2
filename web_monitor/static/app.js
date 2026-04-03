/* app.js - AIC Semi USB Driver Web Monitor v5.0 */
"use strict";

const PROTO_COLORS = {
    TCP: "#58a6ff", UDP: "#d29922", ICMP: "#bc8cff",
    ARP: "#3fb950", IPv6: "#ffa657", Other: "#8b949e",
};
let _chartData = { TCP: 0, UDP: 0, ICMP: 0, ARP: 0, IPv6: 0, Other: 0 };
let _secEvents = [];

// ── Canvas horizontal bar chart ──────────────────────────────
function drawChart(data) {
    const canvas = document.getElementById("proto-chart");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const W = canvas.width = canvas.offsetWidth || 400;
    const keys = Object.keys(data);
    const vals = keys.map(k => data[k]);
    const total = Math.max(vals.reduce((a, b) => a + b, 0), 1);
    const max = Math.max(...vals, 1);
    const ROW_H = 36, BAR_H = 20, PAD_L = 52, PAD_R = 64, PAD_T = 14, PAD_B = 10;
    const H = PAD_T + keys.length * ROW_H + PAD_B;
    canvas.height = H;
    ctx.clearRect(0, 0, W, H);
    const TRACK_W = W - PAD_L - PAD_R;
    keys.forEach((k, i) => {
        const v = vals[i], pct = v / max, fillW = Math.round(pct * TRACK_W);
        const y = PAD_T + i * ROW_H, barY = y + (ROW_H - BAR_H) / 2;
        const col = PROTO_COLORS[k] || "#8b949e";
        const pctTot = Math.round(v * 100 / total);
        ctx.beginPath(); roundRect(ctx, PAD_L, barY, TRACK_W, BAR_H, 4);
        ctx.fillStyle = "#1e2a3a"; ctx.fill();
        if (fillW > 0) {
            const g = ctx.createLinearGradient(PAD_L, 0, PAD_L + fillW, 0);
            g.addColorStop(0, col + "99"); g.addColorStop(1, col);
            ctx.beginPath(); roundRect(ctx, PAD_L, barY, fillW, BAR_H, 4);
            ctx.fillStyle = g; ctx.fill();
            ctx.save(); ctx.shadowColor = col; ctx.shadowBlur = 8;
            ctx.beginPath(); roundRect(ctx, PAD_L + fillW - 3, barY + 2, 3, BAR_H - 4, 2);
            ctx.fillStyle = col; ctx.fill(); ctx.restore();
        }
        ctx.fillStyle = "#64748b"; ctx.font = "500 11px 'JetBrains Mono',monospace";
        ctx.textAlign = "right"; ctx.textBaseline = "middle";
        ctx.fillText(k, PAD_L - 8, barY + BAR_H / 2);
        ctx.fillStyle = col; ctx.font = "600 11px 'JetBrains Mono',monospace";
        ctx.textAlign = "left";
        ctx.fillText(fmtNum(v), PAD_L + TRACK_W + 8, barY + BAR_H / 2 - 5);
        ctx.fillStyle = "#334155"; ctx.font = "400 10px 'JetBrains Mono',monospace";
        ctx.fillText(pctTot + "%", PAD_L + TRACK_W + 8, barY + BAR_H / 2 + 7);
    });
    ctx.strokeStyle = "#162030"; ctx.lineWidth = 1;
    [0.25, 0.5, 0.75, 1].forEach(t => {
        const x = PAD_L + Math.round(t * TRACK_W);
        ctx.beginPath(); ctx.moveTo(x, PAD_T); ctx.lineTo(x, H - PAD_B); ctx.stroke();
    });
}
function roundRect(ctx, x, y, w, h, r) {
    if (w < 2 * r) r = w / 2; if (h < 2 * r) r = h / 2;
    ctx.moveTo(x + r, y); ctx.lineTo(x + w - r, y); ctx.quadraticCurveTo(x + w, y, x + w, y + r);
    ctx.lineTo(x + w, y + h - r); ctx.quadraticCurveTo(x + w, y + h, x + w - r, y + h);
    ctx.lineTo(x + r, y + h); ctx.quadraticCurveTo(x, y + h, x, y + h - r);
    ctx.lineTo(x, y + r); ctx.quadraticCurveTo(x, y, x + r, y); ctx.closePath();
}
function drawProtoBars(_d) { }

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
function escHtml(s) {
    return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
function setEl(id, val) { const e = document.getElementById(id); if (e) e.textContent = val; }
function setDot(id, state) { const e = document.getElementById(id); if (e) e.className = "dot dot-" + state; }
function setBadge(id, text, cls) {
    const e = document.getElementById(id); if (!e) return;
    e.textContent = text; e.className = "badge badge-" + cls;
}
function classifyLog(m) {
    if (/OK|thanh cong|WIFI|UP|success/i.test(m)) return "log-ok";
    if (/error|that bai|FAIL|failed/i.test(m)) return "log-err";
    if (/warn|WARNING|STORAGE|modeswitch/i.test(m)) return "log-warn";
    if (/info/i.test(m)) return "log-info";
    return "log-dim";
}
function appendLog(boxId, lines, withTime = false) {
    const box = document.getElementById(boxId); if (!box) return;
    lines.forEach(item => {
        const div = document.createElement("div"); div.className = "log-line";
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
function toast(msg, color = "#58a6ff") {
    const el = document.getElementById("toast");
    el.textContent = msg; el.style.borderColor = color; el.style.color = color;
    el.classList.remove("hidden"); el.classList.add("show");
    clearTimeout(el._t);
    el._t = setTimeout(() => { el.classList.remove("show"); el.classList.add("hidden"); }, 3000);
}
function updateClock() {
    const e = document.getElementById("hdr-time");
    if (e) e.textContent = new Date().toLocaleString("vi-VN");
}

// ── Status polling ────────────────────────────────────────────
async function refreshStatus() {
    try {
        const r = await fetch("/api/status"); const d = await r.json();
        const usb = d.usb;
        if (usb.found) {
            setEl("usb-line", usb.line.replace(/^Bus.*ID\s+[a-f0-9:]+\s+/i, "").trim());
            setEl("usb-pid", "0x" + usb.pid);
            if (usb.mode === "wifi") { setBadge("usb-mode-badge", "WiFi 8d80", "wifi"); setDot("dot-usb", "green"); }
            else if (usb.mode === "storage") { setBadge("usb-mode-badge", "Storage 5721", "storage"); setDot("dot-usb", "yellow"); }
            else { setBadge("usb-mode-badge", "Unknown", "none"); setDot("dot-usb", "gray"); }
        } else {
            setEl("usb-line", "Not found"); setBadge("usb-mode-badge", "None", "none"); setDot("dot-usb", "red");
        }
        setDot("dot-mod", d.loaded ? "green" : "red");
        setEl("lbl-mod", d.loaded ? "Module OK" : "Module --");
        const iface = d.iface;
        if (iface.exists) {
            setEl("if-mac", iface.mac || "--"); setEl("if-ip", iface.ip || "--");
            if (iface.up) { setBadge("if-status-badge", "UP", "up"); setDot("dot-iface", "green"); }
            else { setBadge("if-status-badge", "DOWN", "down"); setDot("dot-iface", "yellow"); }
        } else {
            setBadge("if-status-badge", "Not found", "none"); setDot("dot-iface", "red");
            setEl("if-mac", "--"); setEl("if-ip", "--");
        }
        const p = d.proc;
        if (d.has_proc && Object.keys(p).length) {
            setEl("s-tx", fmtNum(p["TX tong"] || p["TX total"] || 0));
            setEl("s-rx", fmtNum(p["RX tong"] || p["RX total"] || 0));
            setEl("s-txb", fmtBytes(p["TX bytes"] || 0));
            setEl("s-drop", fmtNum(p["TX bi rot"] || p["TX dropped"] || 0));
            setEl("s-tcp", fmtNum(p["TCP"] || 0));
            setEl("s-udp", fmtNum(p["UDP"] || 0));
            setEl("s-icmp", fmtNum(p["ICMP"] || 0));
            setEl("s-arp", fmtNum(p["ARP"] || 0));
            setEl("ss-enc", Number(p["Encrypted"] || 0));
            setEl("ss-tamp", Number(p["Tampered"] || 0));
            setEl("ss-plain", Number(p["Plain"] || 0));
            _chartData = {
                TCP: Number(p["TCP"] || 0),
                UDP: Number(p["UDP"] || 0),
                ICMP: Number(p["ICMP"] || 0),
                ARP: Number(p["ARP"] || 0),
                IPv6: Number(p["IPv6"] || 0),
                Other: Number(p["Khac"] || p["Other"] || 0),
            };
            drawChart(_chartData);
        }
        if (d.has_proc) {
            const raw = Object.entries(p).map(([k, v]) => `  ${k.padEnd(14)}: ${v}`).join("\n");
            document.getElementById("proc-box").textContent = raw || "--";
        } else {
            document.getElementById("proc-box").textContent = "Driver chua load hoac chua o WiFi mode";
        }
    } catch (e) { console.error("status error", e); }
}

// ── Security Events ───────────────────────────────────────────
async function loadSecEvents() {
    try {
        const r = await fetch("/api/security"); const d = await r.json();
        _secEvents = d.events || [];
        renderSecEvents(_secEvents, d.counts || {});
    } catch (e) { console.error("sec events", e); }
}

function renderSecEvents(events, counts) {
    const okCnt = counts.ok || 0;
    const tampCnt = counts.tamper || 0;
    const arpCnt = counts.plain || 0;
    const infoCnt = (counts.info || 0) + (counts.detail || 0);
    const isFallback = events.length > 0 && events[0].fallback;

    if (isFallback) {
        setEl("sec-enc-badge", "TX: " + events.length);
        setEl("sec-tamp-badge", "TAMPER: 0");
        setEl("sec-plain-badge", "Driver cu");
        setEl("ss-enc", 0); setEl("ss-tamp", 0); setEl("ss-plain", events.length);
    } else {
        setEl("sec-enc-badge", "OK: " + okCnt);
        setEl("sec-tamp-badge", "TAMPER: " + tampCnt);
        setEl("sec-plain-badge", "ARP: " + arpCnt);
        setEl("ss-enc", okCnt); setEl("ss-tamp", tampCnt); setEl("ss-plain", arpCnt + infoCnt);
    }

    const grid = document.getElementById("sec-grid");
    if (!grid) return;
    if (events.length === 0) {
        grid.innerHTML = '<div class="sec-empty">Chua co su kien -- chay Run Demo de xem</div>';
        return;
    }

    const banner = isFallback
        ? `<div class="sec-event sec-event-plain" style="cursor:default;margin-bottom:6px">
               <div class="sec-icon">&#9888;</div>
               <div class="sec-body">
                   <div class="sec-title sec-title-plain">Driver chua co crypto -- hien thi TX log</div>
                   <div class="sec-hex">Chay Compile -&gt; Restart de load driver moi co HMAC verify</div>
               </div>
           </div>`
        : "";

    const show = [...events].reverse().slice(0, isFallback ? 8 : 12);
    grid.innerHTML = banner + show.map((ev, idx) => {
        const realIdx = events.length - 1 - idx;
        const isTamp = ev.kind === "tamper";
        const isOk = ev.kind === "ok";
        const isPlain = ev.kind === "plain";   // ARP - no HMAC, normal
        const cls = isTamp ? "sec-event-fail" : isOk ? "sec-event-ok" : "sec-event-plain";
        const icon = isTamp ? "&#128680;" : isOk ? "&#128272;" : isPlain ? "&#128228;" : "&#8505;";
        const tcls = isTamp ? "sec-title-fail" : isOk ? "sec-title-ok" : "sec-title-plain";
        const title = isFallback
            ? (ev.msg.includes("TCP") ? "TCP packet"
                : ev.msg.includes("DNS") || ev.msg.includes("UDP") ? "UDP/DNS packet"
                    : ev.msg.includes("ICMP") ? "ICMP packet"
                        : ev.msg.includes("ARP") ? "ARP packet" : "TX packet")
            : isTamp ? "HMAC FAIL -- Goi bi TAMPER"
                : isOk ? "HMAC OK -- Goi hop le"
                    : isPlain ? "ARP -- Khong co HMAC (binh thuong)"
                        : "Crypto Info";
        const short = ev.msg.length > 80 ? ev.msg.slice(0, 80) + "..." : ev.msg;
        const hexPart = ev.hex
            ? `<div class="sec-hex" style="margin-top:3px;opacity:.75">${escHtml(ev.hex)}</div>`
            : "";
        const clickAttr = !isFallback
            ? `onclick="openSecModal(${realIdx})" title="Click de xem chi tiet"`
            : "";
        return `<div class="sec-event ${cls}" ${clickAttr} style="${isFallback ? "cursor:default" : ""}">
            <div class="sec-icon">${icon}</div>
            <div class="sec-body">
                <div class="sec-title ${tcls}">${title}</div>
                <div class="sec-hex">${escHtml(short)}</div>
                ${hexPart}
            </div>
            <div class="sec-meta">${ev.ts ? ev.ts + "s" : ""}</div>
        </div>`;
    }).join("");
}

function openSecModal(idx) {
    const ev = _secEvents[idx]; if (!ev) return;
    const isTamp = ev.kind === "tamper", isOk = ev.kind === "ok";
    const icon = isTamp ? "&#128680;" : isOk ? "&#128272;" : "&#8505;";
    const title = isTamp ? "HMAC FAIL -- Goi bi TAMPER" : isOk ? "HMAC OK -- Goi hop le" : "Crypto Info";
    const fcls = isTamp ? "fail" : isOk ? "ok" : "info";
    const explain = isTamp
        ? `<b style="color:var(--red)">Phat hien goi bi gia mao!</b><br>
           Driver tinh lai HMAC-SHA256 tren ciphertext va so sanh voi tag 8 byte cuoi payload.<br>
           Ket qua: <b>KHONG KHOP</b> &#8594; goi da bi sua doi trong qua trinh truyen.`
        : isOk
            ? `<b style="color:var(--green)">Goi tin hop le.</b><br>
           HMAC-SHA256 verify thanh cong. Driver da:<br>
           1. Tinh HMAC(key, ciphertext)<br>
           2. So sanh voi tag 8 byte cuoi payload<br>
           3. Ket qua: <b>KHOP</b> &#8594; goi toan ven, chua bi sua doi.`
            : `Thong tin chi tiet ve qua trinh ma hoa/giai ma.`;

    document.getElementById("modal-title").innerHTML = `${icon} ${title}`;
    document.getElementById("modal-body").innerHTML = `
        <div class="modal-section">
            <div class="modal-section-title">Giai thich</div>
            <div class="modal-field ${fcls}" style="font-family:var(--font-sans);font-size:12px;line-height:1.8">${explain}</div>
        </div>
        <div class="modal-section">
            <div class="modal-section-title">Thong diep tu driver</div>
            <div class="modal-field ${fcls}">${escHtml(ev.msg)}</div>
        </div>
        ${ev.hex ? `
        <div class="modal-section">
            <div class="modal-section-title">Hex dump (ciphertext/tag)</div>
            <div class="modal-field">
                <span class="modal-hex">${escHtml(ev.hex)}</span>
                <div style="margin-top:6px;font-size:10px;color:var(--text-secondary)">
                    Du lieu sau XOR encrypt (key=0xA1) + HMAC-SHA256 tag 8 bytes cuoi
                </div>
            </div>
        </div>`: ""}
        <div class="modal-section">
            <div class="modal-section-title">Raw dmesg</div>
            <div class="modal-raw">${escHtml(ev.raw)}</div>
        </div>
        <div class="modal-section">
            <div class="modal-section-title">Luong xu ly</div>
            <div class="modal-field info" style="font-family:var(--font-sans);font-size:11px;line-height:1.9;color:var(--text-secondary)">
                demo.c &#8594; XOR(payload, key=0xA1) &#8594; append HMAC[8]<br>
                &#8594; AF_PACKET sendto() &#8594; kernel dev_queue_xmit()<br>
                &#8594; <b style="color:var(--cyan)">aicsemi_net_xmit()</b> &#8594; aic_verify_hmac()<br>
                &#8594; ${isTamp
            ? '<b style="color:var(--red)">HMAC mismatch &#8594; tx_tampered++ &#8594; log [SECURITY]</b>'
            : isOk
                ? '<b style="color:var(--green)">HMAC match &#8594; tx_encrypted++ &#8594; aic_xor_decrypt() &#8594; log plaintext</b>'
                : 'log crypto info'}
            </div>
        </div>`;
    document.getElementById("sec-modal").classList.remove("hidden");
    document.body.style.overflow = "hidden";
}

function closeModal(e) {
    if (e && e.target !== document.getElementById("sec-modal")) return;
    document.getElementById("sec-modal").classList.add("hidden");
    document.body.style.overflow = "";
}
document.addEventListener("keydown", e => { if (e.key === "Escape") closeModal(); });

// ── dmesg ─────────────────────────────────────────────────────
async function loadDmesg() {
    const box = document.getElementById("dmesg-box"); box.innerHTML = "";
    try {
        const r = await fetch("/api/dmesg?n=50"); const d = await r.json();
        appendLog("dmesg-box", d.lines);
    } catch (e) { box.textContent = "Error loading dmesg"; }
}

// ── Action log polling ────────────────────────────────────────
let _lastLogLen = 0;
async function pollLog() {
    try {
        const r = await fetch("/api/log"); const d = await r.json();
        if (d.lines.length > _lastLogLen) {
            appendLog("action-log", d.lines.slice(_lastLogLen), true);
            _lastLogLen = d.lines.length;
        }
    } catch (e) { }
}
async function clearLog() {
    await fetch("/api/log/clear", { method: "POST" });
    document.getElementById("action-log").innerHTML = "";
    _lastLogLen = 0;
}

// ── Driver Actions ────────────────────────────────────────────
const ACTION_LABELS = {
    compile: "Compiling...", setup: "Running setup.bash...",
    restart: "Restarting driver...", modeswitch: "Forcing modeswitch...",
    demo: "Running demo...", unload: "Unloading module...", clear_ring: "Clearing ring buffer...",
};
async function doAction(name) {
    const btn = event.currentTarget; const orig = btn.textContent;
    btn.disabled = true; btn.innerHTML = `<span class="spin">&#8635;</span> ${ACTION_LABELS[name] || name}`;
    toast(ACTION_LABELS[name] || name, "#58a6ff");
    try {
        const r = await fetch(`/api/action/${name}`, { method: "POST" }); const d = await r.json();
        if (d.ok) toast(`OK: ${name}`, "#3fb950");
        else toast(`FAIL: ${name} -- ${d.stderr || ""}`, "#f85149");
        await refreshAll();
        if (name === "demo") await loadSecEvents();
    } catch (e) { toast("Network error", "#f85149"); }
    finally { btn.disabled = false; btn.textContent = orig; }
}

// ── Interface UP/DOWN ─────────────────────────────────────────
async function ifUp() {
    const iface = document.getElementById("if-name").textContent.trim() || "aic0";
    const ip = document.getElementById("inp-ip").value.trim() || "192.168.99.1/24";
    toast(`Setting ${iface} UP...`, "#58a6ff");
    const r = await fetch("/api/action/ifup", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ iface, ip }) });
    const d = await r.json();
    toast(d.ok ? `${iface} UP -- ${ip}` : `FAIL: ${d.link?.stderr || "failed"}`, d.ok ? "#3fb950" : "#f85149");
    await refreshStatus();
}
async function ifDown() {
    const iface = document.getElementById("if-name").textContent.trim() || "aic0";
    toast(`Setting ${iface} DOWN...`, "#d29922");
    const r = await fetch("/api/action/ifdown", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ iface }) });
    const d = await r.json();
    toast(d.ok ? `${iface} DOWN` : "FAIL", d.ok ? "#3fb950" : "#f85149");
    await refreshStatus();
}

// ── Ping ──────────────────────────────────────────────────────
async function doPing() {
    const ip = document.getElementById("ping-ip").value.trim();
    const iface = document.getElementById("ping-iface").value.trim() || "aic0";
    const count = document.getElementById("ping-count").value;
    const box = document.getElementById("ping-result");
    if (!ip) { toast("Nhap IP truoc", "#f85149"); return; }
    box.className = "ping-result";
    box.textContent = `Pinging ${ip} via ${iface} (${count} packets)...`;
    box.classList.remove("hidden");
    const r = await fetch("/api/action/ping", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ip, iface, count: Number(count) }) });
    const d = await r.json();
    box.className = "ping-result " + (d.ok ? "ping-ok" : "ping-fail");
    box.textContent = d.ok
        ? `OK: ${ip} reachable\n  Loss: ${d.loss}  RTT avg: ${d.rtt_avg}\n\n${d.stdout}`
        : `FAIL: ${ip} unreachable\n  Loss: ${d.loss}\n\n${d.stdout || d.stderr || ""}`;
}

// ── Init ──────────────────────────────────────────────────────
window.addEventListener("resize", () => drawChart(_chartData));

async function refreshAll() {
    await Promise.all([refreshStatus(), loadDmesg(), loadSecEvents()]);
}

(async function init() {
    updateClock();
    setInterval(updateClock, 1000);
    drawChart(_chartData);
    await refreshAll();
    setInterval(refreshStatus, 3000);
    setInterval(pollLog, 1500);
    setInterval(loadDmesg, 10000);
    setInterval(loadSecEvents, 5000);
})();
