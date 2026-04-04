#!/usr/bin/env python3
"""server.py - AIC Semi USB Driver Web Monitor"""
import subprocess, os, re, time, threading
from flask import Flask, jsonify, request, send_from_directory, Response

app = Flask(__name__, static_folder="static", static_url_path="/static")
app.config["JSON_AS_ASCII"]    = False
app.config["JSONIFY_MIMETYPE"] = "application/json; charset=utf-8"

DRIVER_DIR        = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_BUFFER        = []
LOG_LOCK          = threading.Lock()
SERVER_START_TIME = time.time()

# ── Logging ───────────────────────────────────────────────────
def push_log(line: str):
    with LOG_LOCK:
        LOG_BUFFER.append({"t": time.strftime("%H:%M:%S"), "msg": line.rstrip()})
        if len(LOG_BUFFER) > 200:
            LOG_BUFFER.pop(0)

def run_cmd(cmd, timeout=15, cwd=None) -> dict:
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           cwd=cwd or DRIVER_DIR)
        out = r.stdout.decode("utf-8", errors="replace").strip()
        err = r.stderr.decode("utf-8", errors="replace").strip()
        for line in (out + "\n" + err).splitlines():
            if line.strip():
                push_log(line)
        return {"ok": r.returncode == 0, "stdout": out, "stderr": err, "rc": r.returncode}
    except subprocess.TimeoutExpired:
        push_log(f"[TIMEOUT] {' '.join(str(c) for c in cmd)}")
        return {"ok": False, "stdout": "", "stderr": "timeout", "rc": -1}
    except Exception as e:
        push_log(f"[ERROR] {e}")
        return {"ok": False, "stdout": "", "stderr": str(e), "rc": -1}

# ── System helpers ────────────────────────────────────────────
def get_uptime_seconds():
    try:
        with open("/proc/uptime") as f:
            return float(f.read().split()[0])
    except Exception:
        return 0.0

def dmesg_since_start(lines):
    """Chi giu dong dmesg co timestamp >= luc server start."""
    uptime  = get_uptime_seconds()
    elapsed = time.time() - SERVER_START_TIME
    cutoff  = uptime - elapsed - 2.0   # buffer 2s
    out = []
    for line in lines:
        m = re.search(r"\[\s*(\d+\.\d+)\]", line)
        if m and float(m.group(1)) >= cutoff:
            out.append(line)
    return out

def get_iface_status(iface="aic0"):
    r = run_cmd(["ip", "link", "show", iface])
    if not r["ok"]:
        return {"exists": False, "up": False, "mac": "", "ip": ""}
    up  = "UP" in r["stdout"] and "LOWER_UP" in r["stdout"]
    mac = re.search(r"link/ether ([\da-f:]+)", r["stdout"])
    ri  = run_cmd(["ip", "addr", "show", iface])
    ip  = re.search(r"inet ([\d./]+)", ri["stdout"])
    return {"exists": True, "up": up,
            "mac": mac.group(1) if mac else "",
            "ip":  ip.group(1)  if ip  else ""}

def get_lsusb():
    r = run_cmd(["lsusb"])
    lines = [l for l in r["stdout"].splitlines() if "a69c" in l.lower()]
    if not lines:
        return {"found": False, "line": "", "mode": "none", "pid": ""}
    line = lines[0]
    pid  = "8d80" if "8d80" in line else ("5721" if "5721" in line else "unknown")
    mode = "wifi" if pid == "8d80" else ("storage" if pid == "5721" else "unknown")
    return {"found": True, "line": line, "mode": mode, "pid": pid}

def get_lsmod():
    r = run_cmd(["lsmod"])
    return any(l.split()[0] in ("aicsemi_multimode", "usb")
               for l in r["stdout"].splitlines() if l.strip())

def get_proc_monitor():
    path = "/proc/aicsemi_usbnet/monitor"
    if not os.path.exists(path):
        return None
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return None

def parse_proc(text: str) -> dict:
    key_map = {
        "TX tong":   "TX tong",   "TX bytes": "TX bytes",
        "TX bi rot": "TX bi rot", "RX tong":  "RX tong",
        "RX bytes":  "RX bytes",  "Encrypted":"Encrypted",
        "Tampered":  "Tampered",  "Plain":    "Plain",
        "Khac":      "Khac",
    }
    d = {}
    for line in text.splitlines():
        m = re.match(r"\s*(.+?)\s*:\s*(.+)", line)
        if not m:
            continue
        raw = m.group(1).strip()
        val = m.group(2).strip()
        # Normalize: strip diacritics roughly for matching
        norm = raw.encode("ascii", "ignore").decode().strip()
        d[raw]  = val
        d[norm] = val
        # Simple keys
        if raw in ("TCP","UDP","ICMP","ARP","IPv6","Other","Encrypted","Tampered","Plain"):
            d[raw] = val
    return d

def get_dmesg_tail(n=40):
    r = run_cmd(["dmesg"])
    all_aic = [l for l in r["stdout"].splitlines() if "aicsemi" in l]
    recent  = dmesg_since_start(all_aic)
    return (recent if recent else all_aic)[-n:]

def get_security_events(n=80):
    """
    Parse security events tu dmesg (chi sau khi server start).
    - Gom dong phu Ciphertext/plaintext vao event chinh.
    - ARP TX -> kind=plain.
    - Fallback neu driver cu.
    """
    r = run_cmd(["dmesg"])
    all_aic = dmesg_since_start(
        [l for l in r["stdout"].splitlines() if "aicsemi" in l]
    )
    events = []

    crypto_kw = ["hmac", "crypto", "security", "tamper", "encrypt", "plain", "cipher", "xor", "aes", "ctr"]
    raw_crypto = [l for l in all_aic if any(k in l.lower() for k in crypto_kw)]
    # ARP: dmesg log la "ARP" viet hoa, vi du: "[TX #1   ] ARP bytes=42"
    arp_lines  = [l for l in all_aic if " ARP " in l and "TX #" in l
                  and not any(k in l.lower() for k in ["hmac","security","crypto"])]

    def ts_of(line):
        m = re.search(r"\[\s*(\d+\.\d+)\]", line)
        return float(m.group(1)) if m else 0.0

    def clean(line):
        s = re.sub(r"^\[.*?\]\s*", "", line)
        return re.sub(r"\[aicsemi\]\s*", "", s, flags=re.IGNORECASE).strip()

    if raw_crypto or arp_lines:
        combined = sorted(set(raw_crypto + arp_lines), key=ts_of)
        for line in combined:
            lo    = line.lower()
            ts_m  = re.search(r"\[\s*(\d+\.\d+)\]", line)
            hex_m = re.findall(r"[0-9a-f]{2}(?:\s[0-9a-f]{2}){3,}", line)
            msg   = clean(line)

            # Dong phu: gan hex vao event truoc, khong tao event moi
            is_sub = ("ciphertext" in lo or "plaintext" in lo) and "tx #" not in lo
            if is_sub and events:
                if hex_m and not events[-1]["hex"]:
                    events[-1]["hex"] = hex_m[0]
                events[-1]["raw"] += " | " + msg
                continue

            # ARP
            if " arp " in lo and "tx #" in lo:
                events.append({"kind":"plain","ts":ts_m.group(1) if ts_m else "",
                                "msg":msg,"hex":"","raw":line,
                                "note":"ARP - no payload - HMAC not verified (normal)"})
                continue

            # Crypto main line
            if "hmac fail" in lo or ("security" in lo and "tx #" in lo):
                kind = "tamper"
            elif "hmac ok" in lo and "tx #" in lo:
                kind = "ok"
            else:
                kind = "info"

            events.append({"kind":kind,"ts":ts_m.group(1) if ts_m else "",
                            "msg":msg,"hex":hex_m[0] if hex_m else "","raw":line})
    else:
        # Fallback: driver cu, hien thi TX log
        tx = [l for l in all_aic if "TX #" in l or "NDO" in l]
        for line in tx[-n:]:
            ts_m = re.search(r"\[\s*(\d+\.\d+)\]", line)
            lo   = line.lower()
            kind = "ok" if "tcp" in lo else "info"
            events.append({"kind":kind,"ts":ts_m.group(1) if ts_m else "",
                            "msg":clean(line),"hex":"","raw":line,"fallback":True})

    return events[-n:]

# ── API Routes ────────────────────────────────────────────────
@app.route("/")
def index():
    p = os.path.join(os.path.dirname(__file__), "static", "index.html")
    with open(p, encoding="utf-8") as f:
        return Response(f.read(), mimetype="text/html; charset=utf-8")

@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory("static", filename)

@app.route("/api/status")
def api_status():
    usb    = get_lsusb()
    iface  = get_iface_status("aic0")
    if not iface["exists"]:
        iface = get_iface_status("aic1")
    proc   = get_proc_monitor()
    return jsonify({"usb":usb,"iface":iface,"loaded":get_lsmod(),
                    "proc":parse_proc(proc) if proc else {},"has_proc":proc is not None})

@app.route("/api/dmesg")
def api_dmesg():
    return jsonify({"lines": get_dmesg_tail(int(request.args.get("n",40)))})

@app.route("/api/security")
def api_security():
    events = get_security_events(80)
    counts = {"ok":0,"tamper":0,"info":0,"plain":0}
    for e in events:
        counts[e["kind"]] = counts.get(e["kind"],0) + 1
    return jsonify({"events":events,"counts":counts})

@app.route("/api/log")
def api_log():
    with LOG_LOCK:
        return jsonify({"lines": list(LOG_BUFFER)})

@app.route("/api/log/clear", methods=["POST"])
def api_log_clear():
    with LOG_LOCK:
        LOG_BUFFER.clear()
    return jsonify({"ok": True})

# ── Driver Actions ────────────────────────────────────────────
@app.route("/api/action/compile", methods=["POST"])
def action_compile():
    push_log("=== compile.bash ===")
    return jsonify(run_cmd(["bash","compile.bash"], timeout=120))

@app.route("/api/action/setup", methods=["POST"])
def action_setup():
    push_log("=== setup.bash ===")
    return jsonify(run_cmd(["bash","setup.bash"], timeout=60))

@app.route("/api/action/restart", methods=["POST"])
def action_restart():
    push_log("=== restart.bash ===")
    return jsonify(run_cmd(["bash","restart.bash"], timeout=30))

@app.route("/api/action/modeswitch", methods=["POST"])
def action_modeswitch():
    push_log("=== Manual modeswitch ===")
    steps = []
    for d in os.listdir("/sys/bus/usb/devices/"):
        vp = f"/sys/bus/usb/devices/{d}/idVendor"
        if not os.path.exists(vp): continue
        try:
            vendor = open(vp).read().strip()
        except Exception:
            continue
        if vendor != "a69c": continue
        intf = f"{d}:1.0"
        dl   = f"/sys/bus/usb/devices/{intf}/driver"
        if os.path.islink(dl):
            drv = os.path.basename(os.readlink(dl))
            if drv in ("usb-storage","usb_storage"):
                try:
                    open(f"/sys/bus/usb/drivers/usb-storage/unbind","w").write(intf)
                    steps.append(f"unbind {intf}: OK")
                except Exception as e:
                    steps.append(f"unbind failed: {e}")
    ko = os.path.join(DRIVER_DIR,"usb.ko")
    if os.path.exists(ko):
        r = run_cmd(["insmod",ko])
        steps.append(f"insmod: {'OK' if r['ok'] else r['stderr']}")
    else:
        steps.append("usb.ko not found")
    return jsonify({"ok":True,"steps":steps})

@app.route("/api/action/ifup", methods=["POST"])
def action_ifup():
    data  = request.get_json(silent=True) or {}
    iface = data.get("iface","aic0")
    ip    = data.get("ip","192.168.99.1/24")
    r1 = run_cmd(["ip","link","set",iface,"up"])
    r2 = run_cmd(["ip","addr","add",ip,"dev",iface])
    return jsonify({"ok":r1["ok"],"link":r1,"addr":r2})

@app.route("/api/action/ifdown", methods=["POST"])
def action_ifdown():
    data  = request.get_json(silent=True) or {}
    iface = data.get("iface","aic0")
    run_cmd(["ip","addr","flush","dev",iface])
    return jsonify(run_cmd(["ip","link","set",iface,"down"]))

@app.route("/api/action/unload", methods=["POST"])
def action_unload():
    for mod in ("aicsemi_multimode","usb"):
        r = run_cmd(["rmmod",mod])
        if r["ok"]:
            return jsonify({"ok":True,"mod":mod})
    return jsonify({"ok":False,"stderr":"module not loaded"})

@app.route("/api/action/ping", methods=["POST"])
def action_ping():
    data  = request.get_json(silent=True) or {}
    ip    = data.get("ip","192.168.99.2")
    iface = data.get("iface","aic0")
    count = min(int(data.get("count",4)),10)
    push_log(f"=== ping -c {count} -I {iface} {ip} ===")
    r = run_cmd(["ping","-c",str(count),"-I",iface,"-W","2",ip], timeout=30)
    loss_m = re.search(r"(\d+)% packet loss", r["stdout"])
    rtt_m  = re.search(r"rtt .* = ([\d.]+)/([\d.]+)/([\d.]+)", r["stdout"])
    return jsonify({"ok":r["ok"],"stdout":r["stdout"],
                    "loss":    loss_m.group(1)+"%" if loss_m else "N/A",
                    "rtt_avg": rtt_m.group(2)+" ms" if rtt_m else "N/A"})

@app.route("/api/action/crypto_ping", methods=["POST"])
def action_crypto_ping():
    """
    Crypto Ping: chay ./demo, doc dmesg ngay sau, tra ve ket qua HMAC
    cho tung goi (ok / tamper). Dung de demo cho thay: goi hop le thi
    PASS, goi bi tamper (HMAC sai) thi FAIL.
    """
    data   = request.get_json(silent=True) or {}
    iface  = data.get("iface","aic0")
    push_log(f"=== Crypto Ping -> {iface} ===")

    demo_path = os.path.join(DRIVER_DIR,"demo")
    if not os.path.exists(demo_path):
        return jsonify({"ok":False,"stderr":"demo not found -- run Compile first","results":[]})

    uptime_before = get_uptime_seconds()
    r = run_cmd([demo_path, iface], timeout=35)
    with _LAST_DEMO_LOCK:
        _LAST_DEMO_STDOUT = r.get("stdout", "")
    time.sleep(0.8)   # cho driver log ra dmesg

    dmesg_r = run_cmd(["dmesg"])
    results = []
    for line in dmesg_r["stdout"].splitlines():
        if "aicsemi" not in line: continue
        m = re.search(r"\[\s*(\d+\.\d+)\]", line)
        if not m or float(m.group(1)) < uptime_before: continue
        lo  = line.lower()
        msg = re.sub(r"^\[.*?\]\s*\[aicsemi\]\s*","",line,flags=re.IGNORECASE).strip()
        if "hmac ok" in lo and "tx #" in lo:
            results.append({"status":"ok",     "msg":msg, "ts":m.group(1)})
        elif "hmac fail" in lo or ("security" in lo and "tx #" in lo):
            results.append({"status":"tamper", "msg":msg, "ts":m.group(1)})

    return jsonify({
        "ok":           r["ok"],
        "results":      results,
        "count_ok":     sum(1 for x in results if x["status"]=="ok"),
        "count_tamper": sum(1 for x in results if x["status"]=="tamper"),
        "stdout":       r["stdout"][-600:] if r["stdout"] else "",
    })

@app.route("/api/action/demo", methods=["POST"])
def action_demo():
    global _LAST_DEMO_STDOUT
    push_log("=== ./demo ===")
    r = run_cmd(["./demo"], timeout=35)
    with _LAST_DEMO_LOCK:
        _LAST_DEMO_STDOUT = r.get("stdout", "")
    return jsonify(r)

@app.route("/api/packet_log")
def api_packet_log():
    """
    Tra ve danh sach chi tiet tung goi tin duoc ma hoa/giai ma.
    Parse tat ca TX log tu dmesg (sau server start), gom nhom theo TX #N.
    Moi goi co: seq, proto, src, dst, bytes, hmac_status, cipher_hex, plain_hex, ts, raw_lines
    """
    r = run_cmd(["dmesg"])
    all_aic = dmesg_since_start(
        [l for l in r["stdout"].splitlines() if "aicsemi" in l]
    )

    # Group lines by TX #N
    packets = {}   # seq -> dict
    order   = []

    for line in all_aic:
        lo  = line.lower()
        ts_m = re.search(r"\[\s*(\d+\.\d+)\]", line)
        ts   = ts_m.group(1) if ts_m else ""
        msg  = re.sub(r"^\[.*?\]\s*\[aicsemi\]\s*","",line,flags=re.IGNORECASE).strip()

        # TX main line: "[TX #N   ] IPv4 / TCP bytes=54 ..."
        tx_m = re.search(r"\[TX #(\d+)\s*\]", line)
        if tx_m:
            seq = int(tx_m.group(1))
            # Parse protocol
            proto = "Unknown"
            for p in ["IPv4 / TCP","IPv4 / UDP","IPv4 / DNS","IPv4 / DHCP",
                      "IPv4 / ICMP","IPv6","ARP","IPv4"]:
                if p in line:
                    proto = p; break
            # Parse bytes
            bytes_m = re.search(r"bytes=(\d+)", line)
            nbytes  = int(bytes_m.group(1)) if bytes_m else 0
            # Parse src/dst MAC
            src_m = re.search(r"src=([\da-f:]+)", line)
            dst_m = re.search(r"dst=([\da-f:]+)", line)

            pkt = {
                "seq":        seq,
                "proto":      proto,
                "bytes":      nbytes,
                "src_mac":    src_m.group(1) if src_m else "",
                "dst_mac":    dst_m.group(1) if dst_m else "",
                "ts":         ts,
                "hmac":       "none",   # none / ok / tamper
                "cipher_hex": "",
                "plain_hex":  "",
                "src_ip":     "",
                "dst_ip":     "",
                "flags":      "",
                "raw_lines":  [msg],
            }
            packets[seq] = pkt
            order.append(seq)
            continue

        # Detail line (IP/port info): "192.168.x.x:port -> ..."
        ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+).*?(\d+\.\d+\.\d+\.\d+)", line)
        # Find which TX# this belongs to (last seen)
        if order:
            last_seq = order[-1]
            pkt = packets[last_seq]
            pkt["raw_lines"].append(msg)
            if ip_m and not pkt["src_ip"]:
                pkt["src_ip"] = ip_m.group(1)
                pkt["dst_ip"] = ip_m.group(2)
            # TCP flags
            flags_m = re.search(r"flags=\[([^\]]+)\]", line)
            if flags_m:
                pkt["flags"] = flags_m.group(1).strip()

        # HMAC OK line
        if "hmac ok" in lo and "tx #" in lo:
            seq_m = re.search(r"tx #(\d+)", lo)
            if seq_m:
                s = int(seq_m.group(1))
                if s in packets:
                    packets[s]["hmac"] = "ok"
                    # payload size
                    pl_m = re.search(r"payload=(\d+)", line)
                    if pl_m:
                        packets[s]["payload_bytes"] = int(pl_m.group(1))
                    packets[s]["raw_lines"].append(msg)

        # HMAC FAIL line
        elif "hmac fail" in lo and "tx #" in lo:
            seq_m = re.search(r"tx #(\d+)", lo)
            if seq_m:
                s = int(seq_m.group(1))
                if s in packets:
                    packets[s]["hmac"] = "tamper"
                    packets[s]["raw_lines"].append(msg)

        # Ciphertext hex
        elif "ciphertext" in lo:
            hex_m = re.findall(r"[0-9a-f]{2}(?:\s[0-9a-f]{2}){3,}", line)
            if hex_m and order:
                packets[order[-1]]["cipher_hex"] = hex_m[0]
                packets[order[-1]]["raw_lines"].append(msg)

        # Plaintext preview
        elif "plaintext" in lo:
            hex_m = re.findall(r"[0-9a-f]{2}(?:\s[0-9a-f]{2}){3,}", line)
            if hex_m and order:
                packets[order[-1]]["plain_hex"] = hex_m[0]
                packets[order[-1]]["raw_lines"].append(msg)

    result = [packets[s] for s in order if s in packets]
    return jsonify({"packets": result, "total": len(result)})

@app.route("/api/crypto_keys")
def api_crypto_keys():
    """
    Tra ve cac key dang duoc su dung trong du an (hardcode demo).
    AES_KEY (128-bit) va HMAC_KEY (256-bit) la hai khoa doc lap nhau.
    """
    return jsonify({
        "aes_key":   "2b7e151628aed2a6abf7158809cf4f3c",
        "aes_nonce": "f0f1f2f3f4f5f6f7f8f9fafb00000001",
        "hmac_key":  "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
        "aes_bits":  128,
        "hmac_bits": 256,
        "mode":      "AES-128-CTR + HMAC-SHA256 (Encrypt-then-MAC)",
        "tag_len":   8,
        "note":      "AES_KEY va HMAC_KEY la hai khoa doc lap — best practice Encrypt-then-MAC"
    })

@app.route("/api/action/clear_ring", methods=["POST"])
def action_clear_ring():
    if os.path.exists(os.path.join(DRIVER_DIR,"ioctl_test")):
        return jsonify(run_cmd(["./ioctl_test","aic0"]))
    return jsonify({"ok":False,"stderr":"ioctl_test not built"})

# ── Raw packet capture from demo stdout ──────────────────────
_LAST_DEMO_STDOUT = ""
_LAST_DEMO_LOCK   = threading.Lock()

def _parse_demo_stdout(stdout: str) -> list:
    """
    Parse stdout cua ./demo de lay raw cipher+tag hex dump cho tung goi.
    demo.c in ra:
        plain  : "AIC-Ping-001-SECRET"
        cipher+tag:  e3 4f 2a ...
    """
    packets = []
    seq = 0
    lines = stdout.splitlines()
    current_plain = ""
    current_proto = "Unknown"
    proto_hints = {
        "ICMP+ENC": "IPv4 / ICMP", "TCP+ENC": "IPv4 / TCP",
        "DNS+ENC": "IPv4 / UDP",   "TAMPERED": "IPv4 / ICMP (TAMPERED)",
    }
    for line in lines:
        for tag, proto in proto_hints.items():
            if tag in line:
                current_proto = proto
                break
        pm = re.search(r'plain\s*:\s*"([^"]+)"', line)
        if pm:
            current_plain = pm.group(1)
        hm = re.search(r'(?:cipher\+tag|tampered)\s*:\s+((?:[0-9a-f]{2}\s*)+)', line, re.IGNORECASE)
        if hm:
            seq += 1
            raw_hex = hm.group(1).strip()
            parts   = raw_hex.split()
            tag_b   = parts[-8:] if len(parts) >= 8 else []
            ct_b    = parts[:-8] if len(parts) >= 8 else parts
            packets.append({
                "seq":        seq,
                "proto":      current_proto,
                "plain_text": current_plain,
                "cipher_hex": " ".join(ct_b),
                "hmac_tag":   " ".join(tag_b),
                "full_hex":   raw_hex,
                "tampered":   "TAMPERED" in current_proto,
            })
            current_plain = ""
    return packets

@app.route("/api/raw_packets")
def api_raw_packets():
    """
    Two-pass parse:
    Pass 1 - build pkt_map from [TX #N] lines (these always exist).
    Pass 2 - assign hmac_ok/tampered by matching TX #N in HMAC log lines.
    This fixes the ordering issue: HMAC log appears BEFORE [TX #N] line in dmesg.
    """
    r = run_cmd(["dmesg"])
    all_aic = dmesg_since_start(
        [l for l in r["stdout"].splitlines() if "aicsemi" in l]
    )

    pkt_map = {}
    order   = []

    # ── Pass 1: build skeleton from TX lines ─────────────────
    for line in all_aic:
        tx_m = re.search(r"\[TX #(\d+)\s*\]", line)
        if not tx_m:
            continue
        seq = int(tx_m.group(1))
        if seq in pkt_map:
            continue
        proto = "Unknown"
        for p in ["IPv4 / TCP","IPv4 / UDP","IPv4 / DNS","IPv4 / ICMP","IPv6","ARP","IPv4"]:
            if p in line: proto = p; break
        bytes_m = re.search(r"bytes=(\d+)", line)
        ts_m    = re.search(r"\[\s*(\d+\.\d+)\]", line)
        pkt_map[seq] = {
            "seq": seq, "proto": proto,
            "ts":  ts_m.group(1) if ts_m else "",
            "bytes": int(bytes_m.group(1)) if bytes_m else 0,
            "plain_text": "", "cipher_hex": "", "hmac_tag": "",
            "full_hex": "", "tampered": False,
            "hmac_ok": False, "src_ip": "", "dst_ip": "",
        }
        order.append(seq)

    # ── Pass 2: assign status and hex from all lines ──────────
    last_crypto_seq = None

    for line in all_aic:
        lo = line.lower()

        # HMAC OK: "✓ [CRYPTO] TX #N HMAC OK"
        if "hmac ok" in lo:
            seq_m = re.search(r"tx\s*#\s*(\d+)", lo)
            if seq_m:
                s = int(seq_m.group(1))
                if s in pkt_map:
                    pkt_map[s]["hmac_ok"] = True
                    last_crypto_seq = s
            continue

        # HMAC FAIL: "✗ [SECURITY] TX #N HMAC FAIL"
        if "hmac fail" in lo:
            seq_m = re.search(r"tx\s*#\s*(\d+)", lo)
            if seq_m:
                s = int(seq_m.group(1))
                if s in pkt_map:
                    pkt_map[s]["tampered"] = True
                    last_crypto_seq = s
            continue

        # Plaintext preview — belongs to last_crypto_seq
        if "plaintext" in lo and last_crypto_seq is not None:
            hex_m = re.findall(r"[0-9a-f]{2}(?:\s[0-9a-f]{2}){3,}", line)
            if hex_m:
                pkt_map[last_crypto_seq]["plain_text"] = hex_m[0]
            continue

        # Ciphertext hex — belongs to last_crypto_seq
        if "ciphertext" in lo and last_crypto_seq is not None:
            hex_m = re.findall(r"[0-9a-f]{2}(?:\s[0-9a-f]{2}){3,}", line)
            if hex_m:
                raw   = hex_m[0]
                parts = raw.split()
                tag_b = parts[-8:] if len(parts) >= 8 else []
                ct_b  = parts[:-8] if len(parts) >= 8 else parts
                pkt_map[last_crypto_seq]["cipher_hex"] = " ".join(ct_b)
                pkt_map[last_crypto_seq]["hmac_tag"]   = " ".join(tag_b)
                pkt_map[last_crypto_seq]["full_hex"]   = raw
            continue

        # IP detail line — attach to nearest preceding TX packet
        ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+).*?(\d+\.\d+\.\d+\.\d+)", line)
        if ip_m and "[TX #" not in line and order:
            ts_m = re.search(r"\[\s*(\d+\.\d+)\]", line)
            if ts_m:
                cur_ts = float(ts_m.group(1))
                for s in reversed(order):
                    if pkt_map[s]["ts"] and float(pkt_map[s]["ts"]) <= cur_ts:
                        if not pkt_map[s]["src_ip"]:
                            pkt_map[s]["src_ip"] = ip_m.group(1)
                            pkt_map[s]["dst_ip"] = ip_m.group(2)
                        break

    # ── Merge stdout hex if available ────────────────────────
    with _LAST_DEMO_LOCK:
        stdout = _LAST_DEMO_STDOUT
    if stdout:
        for i, sp in enumerate(_parse_demo_stdout(stdout)):
            if i < len(order):
                s = order[i]
                if not pkt_map[s]["full_hex"] and sp.get("full_hex"):
                    pkt_map[s]["cipher_hex"] = sp["cipher_hex"]
                    pkt_map[s]["hmac_tag"]   = sp["hmac_tag"]
                    pkt_map[s]["full_hex"]   = sp["full_hex"]
                if sp.get("tampered"):
                    pkt_map[s]["tampered"] = True

    result = [pkt_map[s] for s in order if s in pkt_map]
    return jsonify({"packets": result, "total": len(result)})


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Need sudo: sudo python3 server.py")
        exit(1)
    print("AIC Semi Web Monitor -- http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
