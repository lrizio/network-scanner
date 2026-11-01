"""
Web-based network scanner.

Phase 1 (Discovery):       scapy ARP sweep finds live hosts + MAC addresses
                           (falls back to an nmap ping sweep if ARP is unavailable
                           or the target range is not on the local segment).
Phase 2 (Deep inspection): python-nmap runs service/version detection and OS
                           fingerprinting against every discovered host.

Run from an elevated shell (Administrator / root) - raw ARP packets and nmap OS
detection both need it. Only scan networks you own or are authorised to test.
"""
import argparse
import ctypes
import ipaddress
import os
import shutil
import socket
import sys
import threading
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor

import nmap
from flask import Flask, jsonify, render_template, request
from scapy.all import ARP, Ether, conf, srp

conf.verb = 0

MIN_PREFIX = 16          # refuse ranges larger than a /16 (65,536 addresses)
INSPECT_WORKERS = 4      # parallel nmap processes during deep inspection
ARP_TIMEOUT = 3
ALLOW_PUBLIC = os.environ.get("SCANNER_ALLOW_PUBLIC") == "1"

PROFILES = {
    "quick": {
        "label": "Quick (top 100 ports)",
        "args": "-F -sV --version-light --host-timeout 2m",
        "timeout": 150,
    },
    "standard": {
        "label": "Standard (top 1000 ports)",
        "args": "--top-ports 1000 -sV --host-timeout 5m",
        "timeout": 330,
    },
    "full": {
        "label": "Full (all 65535 ports)",
        "args": "-p- -sV --version-light --host-timeout 30m",
        "timeout": 1830,
    },
}
COMMON_ARGS = "-Pn -T4"          # hosts are already known to be up; skip re-pinging
OS_ARGS = "-O --osscan-guess"    # needs admin/root

FROZEN = getattr(sys, "frozen", False)            # running as a PyInstaller exe
APP_DIR = os.path.dirname(sys.executable if FROZEN else os.path.abspath(__file__))
RES_DIR = getattr(sys, "_MEIPASS", APP_DIR)       # where templates are unpacked
BUNDLED_NMAP = os.path.join(APP_DIR, "nmap")      # portable nmap shipped next to the exe

app = Flask(__name__, template_folder=os.path.join(RES_DIR, "templates"))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def is_admin():
    try:
        if os.name == "nt":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def new_scanner():
    """PortScanner using the nmap bundled next to the app, else the system one."""
    bundled = os.path.join(BUNDLED_NMAP, "nmap.exe" if os.name == "nt" else "nmap")
    if os.path.isfile(bundled):
        return nmap.PortScanner(nmap_search_path=(bundled,))
    return nmap.PortScanner()


def npcap_installed():
    """Npcap is the Windows packet driver scapy and nmap need for ARP / raw scans."""
    if os.name != "nt":
        return True
    system32 = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32")
    return os.path.isdir(os.path.join(system32, "Npcap")) or os.path.isdir("C:\\Program Files\\Npcap")


def nmap_version():
    try:
        return ".".join(str(p) for p in new_scanner().nmap_version())
    except Exception:
        return None


def guess_local_cidr():
    """Best-effort guess of the local /24 (a UDP connect sends no packets)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
    except OSError:
        ip = "192.168.1.10"
    finally:
        s.close()
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def parse_cidr(text):
    """Validate user input; returns an IPv4Network or raises ValueError."""
    try:
        net = ipaddress.ip_network((text or "").strip(), strict=False)
    except ValueError:
        raise ValueError("Invalid CIDR range. Example: 192.168.1.0/24")
    if net.version != 4:
        raise ValueError("Only IPv4 ranges are supported.")
    if net.prefixlen < MIN_PREFIX:
        raise ValueError(f"Range too large - use /{MIN_PREFIX} or smaller.")
    if not ALLOW_PUBLIC and not (net.is_private or net.is_link_local):
        raise ValueError(
            "Only private (RFC1918) ranges can be scanned. "
            "Set SCANNER_ALLOW_PUBLIC=1 if you really are authorised to scan this range."
        )
    return net


_oui_db = None


def _load_oui_db():
    """OUI prefix -> vendor from nmap's nmap-mac-prefixes (far fresher than scapy's bundled list)."""
    dirs = [BUNDLED_NMAP, os.environ.get("NMAPDIR", "")]
    exe = shutil.which("nmap")
    if exe:
        dirs.append(os.path.dirname(exe))
    dirs += [r"C:\Program Files (x86)\Nmap", r"C:\Program Files\Nmap",
             "/usr/share/nmap", "/usr/local/share/nmap", "/opt/homebrew/share/nmap"]
    for d in filter(None, dirs):
        path = os.path.join(d, "nmap-mac-prefixes")
        if not os.path.isfile(path):
            continue
        db = {}
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                prefix, _, name = line.strip().partition(" ")
                if len(prefix) == 6 and name and not line.startswith("#"):
                    db[prefix.upper()] = name.strip()
        if db:
            return db
    return {}


def lookup_vendor(mac):
    global _oui_db
    if _oui_db is None:
        _oui_db = _load_oui_db()
    digits = "".join(c for c in mac if c.isalnum()).upper()
    if len(digits) < 6:
        return ""
    if int(digits[1], 16) & 0x2:        # locally administered bit -> randomised/private MAC
        return "Private (randomised MAC)"
    vendor = _oui_db.get(digits[:6])
    if vendor:
        return vendor
    try:
        vendor = conf.manufdb._get_manuf(mac)
    except Exception:
        return ""
    return "" if not vendor or vendor.lower() == mac.lower() else vendor


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


# Service banners are the only OS evidence available without raw-socket access.
OS_HINTS = (
    ("windows", "Windows"), ("microsoft", "Windows"), ("ubuntu", "Linux (Ubuntu)"),
    ("debian", "Linux (Debian)"), ("raspbian", "Linux (Raspbian)"), ("linux", "Linux"),
    ("freebsd", "FreeBSD"), ("openbsd", "OpenBSD"), ("routeros", "MikroTik RouterOS"),
    ("apple", "Apple (macOS/iOS)"), ("darwin", "Apple (macOS/iOS)"),
)


def guess_os_from_services(ports):
    blob = " ".join(
        f"{p['product']} {p['version']} {p['extrainfo']} {p['cpe']}" for p in ports
    ).lower()
    for needle, label in OS_HINTS:
        if needle in blob:
            return label
    return ""


# --------------------------------------------------------------------------- #
# Scan job
# --------------------------------------------------------------------------- #
class ScanJob:
    """State of one scan. Workers only ever mutate their own job object."""

    def __init__(self, cidr, profile):
        self.lock = threading.Lock()
        self.cancel = threading.Event()
        self.thread = None
        self.id = int(time.time() * 1000)
        self.cidr = cidr
        self.profile = profile
        self.state = "running"      # running | cancelling | done | cancelled | error
        self.phase = "Starting"
        self.message = "Starting scan..."
        self.progress = 0
        self.started = time.time()
        self.finished = None
        self.error = None
        self.warnings = []
        self.devices = {}           # ip -> dict

    def update(self, **fields):
        with self.lock:
            for k, v in fields.items():
                setattr(self, k, v)

    def warn(self, text):
        with self.lock:
            self.warnings.append(text)

    def update_device(self, ip, **fields):
        with self.lock:
            self.devices[ip].update(fields)

    def snapshot(self):
        with self.lock:
            devices = sorted(
                (dict(d) for d in self.devices.values()),
                key=lambda d: ipaddress.ip_address(d["ip"]),
            )
            return {
                "id": self.id,
                "state": self.state,
                "phase": self.phase,
                "message": self.message,
                "progress": round(self.progress),
                "cidr": self.cidr,
                "profile": self.profile,
                "started": self.started,
                "finished": self.finished,
                "error": self.error,
                "warnings": list(self.warnings),
                "devices": devices,
            }


current_job = None
job_guard = threading.Lock()


def new_device(ip, mac="", vendor=""):
    return {
        "ip": ip, "mac": mac, "vendor": vendor, "hostname": "",
        "os": "", "os_accuracy": None, "ports": [],
        "state": "discovered",      # discovered | inspecting | done | failed
        "error": None,
    }


# --------------------------------------------------------------------------- #
# Phase 1: discovery
# --------------------------------------------------------------------------- #
def arp_sweep(job, net):
    """ARP-scan in /24 chunks so progress and cancellation work on big ranges."""
    found = {}
    chunks = list(net.subnets(new_prefix=max(net.prefixlen, 24)))
    for i, chunk in enumerate(chunks):
        if job.cancel.is_set():
            break
        answered, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(chunk)),
            timeout=ARP_TIMEOUT, retry=1, verbose=False,
        )
        for _, reply in answered:
            found[reply.psrc] = reply.hwsrc.lower()
        job.update(progress=20 * (i + 1) / len(chunks),
                   message=f"ARP sweep {chunk} ({len(found)} hosts so far)")
    return found


def ping_sweep(job, net):
    """Fallback for ranges that are not on the local L2 segment."""
    nm = new_scanner()
    nm.scan(hosts=str(net), arguments="-sn -PE -PS22,80,443 -PA3389 -T4", timeout=600)
    found = {}
    for ip in nm.all_hosts():
        if nm[ip].state() == "up":
            found[ip] = (nm[ip]["addresses"].get("mac") or "").lower()
    return found


def discover(job, net):
    job.update(phase="Discovery Phase", message=f"ARP sweep of {net}...")
    found = {}
    try:
        found = arp_sweep(job, net)
    except Exception as exc:    # Npcap missing, no privileges, wrong interface...
        job.warn(f"ARP discovery failed ({exc}); falling back to nmap ping sweep.")
    if not found and not job.cancel.is_set():
        job.update(message="No ARP replies - trying nmap ping sweep...")
        found = ping_sweep(job, net)

    with job.lock:
        for ip, mac in found.items():
            job.devices[ip] = new_device(ip, mac, lookup_vendor(mac) if mac else "")
    return list(found)


# --------------------------------------------------------------------------- #
# Phase 2: deep inspection
# --------------------------------------------------------------------------- #
def inspect_host(job, ip, admin):
    if job.cancel.is_set():
        return
    job.update_device(ip, state="inspecting")
    profile = PROFILES[job.profile]
    args = f"{COMMON_ARGS} {profile['args']}" + (f" {OS_ARGS}" if admin else "")

    try:
        nm = new_scanner()
        nm.scan(hosts=ip, arguments=args, timeout=profile["timeout"])
        if ip not in nm.all_hosts():
            raise RuntimeError("host did not respond to nmap")
        host = nm[ip]

        ports = []
        for proto in host.all_protocols():
            for number, info in sorted(host[proto].items()):
                if not info.get("state", "").startswith("open"):
                    continue
                ports.append({
                    "port": number, "protocol": proto, "state": info["state"],
                    "service": info.get("name", ""),
                    "product": info.get("product", ""),
                    "version": info.get("version", ""),
                    "extrainfo": info.get("extrainfo", ""),
                    "cpe": info.get("cpe", ""),
                })

        os_name, accuracy = "", None
        matches = host.get("osmatch") or []
        if matches:
            os_name, accuracy = matches[0]["name"], int(matches[0].get("accuracy", 0))
        elif guess_os_from_services(ports):
            os_name = guess_os_from_services(ports) + " (from service banners)"

        mac_info = host.get("vendor") or {}
        with job.lock:
            dev = job.devices[ip]
            if not dev["vendor"] and mac_info:
                dev["vendor"] = next(iter(mac_info.values()))
        hostname = host.hostname() or reverse_dns(ip)
        job.update_device(ip, ports=ports, os=os_name or "Unknown",
                          os_accuracy=accuracy, hostname=hostname, state="done")
    except Exception as exc:
        job.update_device(ip, state="failed", error=str(exc).strip()[:300] or "scan failed",
                          hostname=reverse_dns(ip))


def run_scan(job, net):
    try:
        admin = is_admin()
        if not admin:
            job.warn("Not running as Administrator/root: OS fingerprinting is disabled "
                     "(OS guesses come from service banners only).")

        ips = discover(job, net)
        if job.cancel.is_set():
            job.update(state="cancelled", phase="Cancelled", message="Scan cancelled.")
            return
        if not ips:
            job.update(state="done", phase="Complete", progress=100,
                       message="Scan complete - no live hosts found.")
            return

        job.update(phase="Deep Inspection", progress=20,
                   message=f"Found {len(ips)} hosts. Inspecting services and OS...")
        done = 0
        with ThreadPoolExecutor(max_workers=INSPECT_WORKERS) as pool:
            futures = [pool.submit(inspect_host, job, ip, admin) for ip in ips]
            for fut in futures:
                fut.result()
                done += 1
                job.update(progress=20 + 80 * done / len(ips),
                           message=f"Deep inspection: {done}/{len(ips)} hosts")

        if job.cancel.is_set():
            job.update(state="cancelled", phase="Cancelled",
                       message=f"Scan cancelled after {done}/{len(ips)} hosts.")
        else:
            job.update(state="done", phase="Complete", progress=100,
                       message=f"Scan complete - {len(ips)} hosts inspected.")
    except Exception as exc:
        job.update(state="error", phase="Error", error=str(exc), message=f"Scan failed: {exc}")
    finally:
        job.update(finished=time.time())


# --------------------------------------------------------------------------- #
# HTTP API
# --------------------------------------------------------------------------- #
@app.before_request
def guard_requests():
    # Block DNS-rebinding when bound to loopback, and require JSON on POSTs
    # (forces a CORS preflight, so other websites cannot trigger scans).
    allowed = app.config.get("ALLOWED_HOSTS")
    if allowed and request.host.rsplit(":", 1)[0].strip("[]") not in allowed:
        return jsonify(error="Forbidden host"), 403
    if request.method == "POST" and not request.is_json:
        return jsonify(error="Content-Type must be application/json"), 415


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/guide")
def guide():
    return render_template("guide.html")


@app.get("/api/info")
def api_info():
    version = nmap_version()
    return jsonify(
        admin=is_admin(),
        npcap=npcap_installed(),
        nmap_version=version,
        default_cidr=guess_local_cidr(),
        profiles={k: v["label"] for k, v in PROFILES.items()},
        platform=os.name,
    )


@app.post("/api/scan")
def api_scan():
    global current_job
    body = request.get_json(silent=True) or {}
    profile = body.get("profile", "standard")
    if profile not in PROFILES:
        return jsonify(error="Unknown scan profile."), 400
    try:
        net = parse_cidr(body.get("cidr"))
    except ValueError as exc:
        return jsonify(error=str(exc)), 400

    with job_guard:
        if current_job and current_job.thread.is_alive():
            return jsonify(error="A scan is already running."), 409
        job = ScanJob(str(net), profile)
        job.thread = threading.Thread(target=run_scan, args=(job, net), daemon=True)
        current_job = job
        job.thread.start()
    return jsonify(id=job.id), 202


@app.get("/api/status")
def api_status():
    job = current_job
    if job is None:
        return jsonify(state="idle", phase="Idle", message="Ready.", progress=0,
                       devices=[], warnings=[], error=None)
    return jsonify(job.snapshot())


@app.post("/api/cancel")
def api_cancel():
    job = current_job
    if job and job.thread.is_alive():
        job.cancel.set()
        job.update(state="cancelling", message="Cancelling - waiting for running nmap jobs to finish...")
    return jsonify(ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web network scanner")
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind address (default 127.0.0.1; the API has no authentication)")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--no-browser", action="store_true", help="don't open the dashboard automatically")
    args = parser.parse_args()

    if args.host in ("127.0.0.1", "localhost", "::1"):
        app.config["ALLOWED_HOSTS"] = {"127.0.0.1", "localhost", "::1"}
    if not is_admin():
        print("WARNING: not running as Administrator/root - ARP discovery and OS detection will be limited.")
    if not npcap_installed():
        print("WARNING: Npcap not found - install it from https://npcap.com for ARP discovery.")
    if FROZEN and not os.path.isfile(os.path.join(BUNDLED_NMAP, "nmap.exe")):
        print("NOTE: no 'nmap' folder next to the exe; using the system-installed nmap if present.")

    port = args.port
    try:
        # Walk up to the next free port if the preferred one is taken.
        for port in range(args.port, args.port + 20):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                if probe.connect_ex(("127.0.0.1", port)) != 0:
                    break
        else:
            raise OSError(f"no free port between {args.port} and {args.port + 19}")

        url = f"http://{'127.0.0.1' if args.host in ('0.0.0.0', '::') else args.host}:{port}"
        print(f"\n  Network Scanner dashboard:  {url}\n  (Ctrl+click the link to open it; close this window to quit)\n")
        if not args.no_browser:
            threading.Timer(1.0, webbrowser.open, args=(url,)).start()
        app.run(host=args.host, port=port, threaded=True, debug=False)
    except Exception as exc:
        print(f"\nFatal error: {exc}")
        if FROZEN:
            input("Press Enter to close...")
        raise SystemExit(1)
