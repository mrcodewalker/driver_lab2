#!/usr/bin/env python3
"""
server.py — AIC Semi USB Driver Web Monitor
Backend Flask: gọi bash scripts, đọc /proc, chạy lệnh hệ thống
Chạy: sudo python3 server.py
"""
import subprocess, os, re, json, time, threading
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__, static_folder="static")
DRIVER_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_BUFFER = []   # lưu log realtime tối đa 200 dòng
LOG_LOCK   = threading.Lock()

def push_log(line: str):
    with LOG_LOCK:
        LOG_BUFFER.append({"t": time.strftime("%H:%M:%S"), "msg": line.rstrip()})
        if len(LOG_BUFFER) > 200:
            LOG_BUFFER.pop(0)

def run_cmd(cmd: list[str], timeout=15) -> dict:
    """Chạy lệnh, trả về {ok, stdout, stderr, rc}"""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, cwd=DRIVER_DIR)
        out = r.stdout.strip()
        err = r.stderr.strip()
        for line in (out + "\n" + err).splitlines():
            if line.strip():
                push_log(line)
        return {"ok": r.returncode == 0, "stdout": out,
                "stderr": err, "rc": r.returncode}
    except subprocess.TimeoutExpired:
        push_log(f"[TIMEOUT] {' '.join(cmd)}")
        return {"ok": False, "stdout": "", "stderr": "timeout", "rc": -1}
    except Exception as e:
        push_log(f"[ERROR] {e}")
        return {"ok": False, "stdout": "", "stderr": str(e), "rc": -1}

# ── Helpers ──────────────────────────────────────────────────────

def get_iface_status(iface="aic0"):
    r = run_cmd(["ip", "link", "show", iface])
    if not r["ok"]:
        return {"exists": False, "up": False, "mac": "", "ip": ""}
    up  = "UP" in r["stdout"] and "LOWER_UP" in r["stdout"]
    mac = re.search(r"link/ether ([\da-f:]+)", r["stdout"])
    ri  = run_cmd(["ip", "addr", "show", iface])
    ip  = re.search(r"inet ([\d./]+)", ri["stdout"])
    return {
        "exists": True,
        "up":     up,
        "mac":    mac.group(1) if mac else "",
        "ip":     ip.group(1)  if ip  else "",
    }

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
    loaded = any(
        l.split()[0] in ("aicsemi_multimode", "usb")
        for l in r["stdout"].splitlines() if l.strip()
    )
    return loaded

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
    """Parse /proc/aicsemi_usbnet/monitor thành dict"""
    d = {}
    for line in text.splitlines():
        m = re.match(r"\s*([\w\s]+?)\s*:\s*(.+)", line)
        if m:
            d[m.group(1).strip()] = m.group(2).strip()
    return d

def get_dmesg_tail(n=30):
    r = run_cmd(["dmesg"])
    lines = [l for l in r["stdout"].splitlines() if "aicsemi" in l]
    return lines[-n:]

# ── API Routes ───────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/api/status")
def api_status():
    usb   = get_lsusb()
    iface = get_iface_status("aic0")
    if not iface["exists"]:
        iface = get_iface_status("aic1")
    loaded = get_lsmod()
    proc   = get_proc_monitor()
    proc_d = parse_proc(proc) if proc else {}
    return jsonify({
        "usb":    usb,
        "iface":  iface,
        "loaded": loaded,
        "proc":   proc_d,
        "has_proc": proc is not None,
    })

@app.route("/api/dmesg")
def api_dmesg():
    n = int(request.args.get("n", 40))
    return jsonify({"lines": get_dmesg_tail(n)})

@app.route("/api/log")
def api_log():
    with LOG_LOCK:
        return jsonify({"lines": list(LOG_BUFFER)})

@app.route("/api/log/clear", methods=["POST"])
def api_log_clear():
    with LOG_LOCK:
        LOG_BUFFER.clear()
    return jsonify({"ok": True})

# ── Driver Actions ───────────────────────────────────────────────

@app.route("/api/action/compile", methods=["POST"])
def action_compile():
    push_log("=== compile.bash ===")
    r = run_cmd(["bash", "compile.bash"], timeout=120)
    return jsonify(r)

@app.route("/api/action/setup", methods=["POST"])
def action_setup():
    push_log("=== setup.bash ===")
    r = run_cmd(["bash", "setup.bash"], timeout=60)
    return jsonify(r)

@app.route("/api/action/restart", methods=["POST"])
def action_restart():
    push_log("=== restart.bash ===")
    r = run_cmd(["bash", "restart.bash"], timeout=30)
    return jsonify(r)

@app.route("/api/action/modeswitch", methods=["POST"])
def action_modeswitch():
    """Ép modeswitch thủ công: unbind usb-storage → insmod"""
    push_log("=== Manual modeswitch ===")
    steps = []
    # Tìm interface AIC trong sysfs
    for d in os.listdir("/sys/bus/usb/devices/"):
        vendor_path = f"/sys/bus/usb/devices/{d}/idVendor"
        if not os.path.exists(vendor_path):
            continue
        try:
            vendor = open(vendor_path).read().strip()
        except Exception:
            continue
        if vendor != "a69c":
            continue
        intf = f"{d}:1.0"
        drv_link = f"/sys/bus/usb/devices/{intf}/driver"
        if os.path.islink(drv_link):
            drv = os.path.basename(os.readlink(drv_link))
            if drv in ("usb-storage", "usb_storage"):
                push_log(f"Unbind usb-storage từ {intf}")
                try:
                    with open(f"/sys/bus/usb/drivers/usb-storage/unbind", "w") as f:
                        f.write(intf)
                    steps.append(f"unbind usb-storage from {intf}: OK")
                    push_log(f"Unbind OK: {intf}")
                except Exception as e:
                    steps.append(f"unbind failed: {e}")
                    push_log(f"Unbind FAIL: {e}")
    # insmod
    ko = os.path.join(DRIVER_DIR, "usb.ko")
    if os.path.exists(ko):
        r = run_cmd(["insmod", ko])
        steps.append(f"insmod: {'OK' if r['ok'] else r['stderr']}")
    else:
        steps.append("usb.ko not found — run compile first")
    return jsonify({"ok": True, "steps": steps})

@app.route("/api/action/ifup", methods=["POST"])
def action_ifup():
    data  = request.get_json(silent=True) or {}
    iface = data.get("iface", "aic0")
    ip    = data.get("ip", "192.168.99.1/24")
    push_log(f"=== ip link set {iface} up + addr {ip} ===")
    r1 = run_cmd(["ip", "link", "set", iface, "up"])
    r2 = run_cmd(["ip", "addr", "add", ip, "dev", iface])
    return jsonify({"ok": r1["ok"], "link": r1, "addr": r2})

@app.route("/api/action/ifdown", methods=["POST"])
def action_ifdown():
    data  = request.get_json(silent=True) or {}
    iface = data.get("iface", "aic0")
    push_log(f"=== ip link set {iface} down ===")
    run_cmd(["ip", "addr", "flush", "dev", iface])
    r = run_cmd(["ip", "link", "set", iface, "down"])
    return jsonify(r)

@app.route("/api/action/unload", methods=["POST"])
def action_unload():
    push_log("=== rmmod ===")
    for mod in ("aicsemi_multimode", "usb"):
        r = run_cmd(["rmmod", mod])
        if r["ok"]:
            push_log(f"rmmod {mod}: OK")
            return jsonify({"ok": True, "mod": mod})
    return jsonify({"ok": False, "stderr": "module not loaded"})

@app.route("/api/action/ping", methods=["POST"])
def action_ping():
    data  = request.get_json(silent=True) or {}
    ip    = data.get("ip", "192.168.99.2")
    iface = data.get("iface", "aic0")
    count = min(int(data.get("count", 4)), 10)
    push_log(f"=== ping -c {count} -I {iface} {ip} ===")
    r = run_cmd(["ping", "-c", str(count), "-I", iface, "-W", "2", ip], timeout=30)
    # parse kết quả
    loss_m = re.search(r"(\d+)% packet loss", r["stdout"])
    rtt_m  = re.search(r"rtt .* = ([\d.]+)/([\d.]+)/([\d.]+)", r["stdout"])
    return jsonify({
        "ok":      r["ok"],
        "stdout":  r["stdout"],
        "loss":    loss_m.group(1) + "%" if loss_m else "N/A",
        "rtt_avg": rtt_m.group(2) + " ms" if rtt_m else "N/A",
    })

@app.route("/api/action/demo", methods=["POST"])
def action_demo():
    push_log("=== ./demo ===")
    r = run_cmd(["./demo"], timeout=30)
    return jsonify(r)

@app.route("/api/action/clear_ring", methods=["POST"])
def action_clear_ring():
    """Gọi ioctl CLEAR qua ioctl_test hoặc trực tiếp"""
    push_log("=== ioctl CLEAR ring buffer ===")
    # dùng ioctl_test nếu có
    if os.path.exists(os.path.join(DRIVER_DIR, "ioctl_test")):
        r = run_cmd(["./ioctl_test", "aic0"])
        return jsonify(r)
    return jsonify({"ok": False, "stderr": "ioctl_test not built"})

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Cần sudo: sudo python3 server.py")
        exit(1)
    print("AIC Semi Web Monitor — http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
