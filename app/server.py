#!/usr/bin/env python3
"""qBit Lite: a small mobile-friendly web UI for qBittorrent.

Serves a static single-page UI and reverse-proxies /api/v2/* to the
qBittorrent WebUI API. The connection is set up in a first-run wizard and
stored in CONFIG_DIR/settings.json. It can sign in to qBittorrent in one of
three ways:

  bypass       qBittorrent whitelists qBit Lite's network, no login at all
  credentials  qBit Lite keeps the qBittorrent account and signs in by itself
  login        every browser signs in with the qBittorrent account

Environment variables (QBIT_URL, QBIT_USERNAME, QBIT_PASSWORD, QBIT_AUTH_BYPASS)
override the saved settings and disable the wizard.
"""
import http.client
import ipaddress
import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode, urlparse

VERSION = "1.1"
PORT = int(os.environ.get("PORT", "8097"))
STATIC_DIR = Path(__file__).parent / "static"
CONFIG_DIR = Path(os.environ.get("CONFIG_DIR", "/config"))
SETTINGS_FILE = CONFIG_DIR / "settings.json"
SUGGESTED_URL = "http://host.docker.internal:8080"

# qBittorrent bans an IP after a few failed logins (default 5). All requests
# reach it from this container's IP, so throttle failures here first.
MAX_FAILS, FAIL_WINDOW = 3, 300
_fails = []
_fails_lock = threading.Lock()

_server_sid = {"sid": None}
_sid_lock = threading.Lock()
_cfg_lock = threading.Lock()


# ---------------------------------------------------------------- settings
def env_settings():
    url = os.environ.get("QBIT_URL", "").strip()
    if not url:
        return None
    user = os.environ.get("QBIT_USERNAME", "")
    bypass = os.environ.get("QBIT_AUTH_BYPASS", "").lower() in ("1", "true", "yes")
    mode = "credentials" if user else "bypass" if bypass else "login"
    return {"url": url, "mode": mode, "username": user,
            "password": os.environ.get("QBIT_PASSWORD", ""), "source": "env"}


def load_settings():
    env = env_settings()
    if env:
        return env
    try:
        s = json.loads(SETTINGS_FILE.read_text())
        if s.get("url") and s.get("mode") in ("bypass", "credentials", "login"):
            s["source"] = "file"
            return s
    except (OSError, ValueError):
        pass
    return None


def save_settings(s):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp = SETTINGS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps({k: s[k] for k in ("url", "mode", "username", "password", "subnet") if k in s}, indent=2))
    os.chmod(tmp, 0o600)  # may hold the qBittorrent password
    tmp.replace(SETTINGS_FILE)


CFG = {"s": load_settings()}


def settings():
    return CFG["s"]


def set_settings(s):
    with _cfg_lock:
        CFG["s"] = s
    with _sid_lock:
        _server_sid["sid"] = None


# ---------------------------------------------------------------- qBittorrent HTTP
class Target:
    def __init__(self, url):
        u = urlparse(url.rstrip("/"))
        if u.scheme not in ("http", "https") or not u.hostname:
            raise ValueError("Use a full address, like http://192.168.1.10:8080")
        self.url = url.rstrip("/")
        self.host, self.https = u.hostname, u.scheme == "https"
        self.port = u.port or (443 if self.https else 80)
        self.netloc = u.netloc
        self.origin = f"{u.scheme}://{u.netloc}"


def qbit_request(method, path, body=None, headers=None, target=None, timeout=60):
    t = target or Target(settings()["url"])
    conn_cls = http.client.HTTPSConnection if t.https else http.client.HTTPConnection
    conn = conn_cls(t.host, t.port, timeout=timeout)
    # qBittorrent's CSRF and host-header checks want these to match its own address.
    h = {"Host": t.netloc, "Referer": t.origin + "/", "Origin": t.origin}
    h.update(headers or {})
    try:
        conn.request(method, path, body=body, headers=h)
        r = conn.getresponse()
        return r.status, r.getheaders(), r.read()
    finally:
        conn.close()


def login_ok(status, data):
    # Old versions answer 200 "Ok.", newer ones 204 with an empty body.
    return status in (200, 204) and data.strip() in (b"Ok.", b"")


def qbit_login(username, password, target=None):
    """Returns (cookie, error)."""
    if recent_failures() >= MAX_FAILS:
        return None, "Too many failed logins. Wait a few minutes before trying again."
    body = urlencode({"username": username, "password": password})
    status, headers, data = qbit_request("POST", "/api/v2/auth/login", body,
                                         {"Content-Type": "application/x-www-form-urlencoded"}, target)
    if login_ok(status, data):
        with _fails_lock:
            _fails.clear()
        for k, v in headers:
            # qBittorrent < 5.1 uses "SID", newer versions "QBT_SID_<port>".
            if k.lower() == "set-cookie" and "SID" in v.split("=", 1)[0]:
                return v.split(";", 1)[0], None
        return "", None
    if status == 403:
        return None, "qBittorrent has temporarily banned this IP after too many failed logins. Wait and try again."
    with _fails_lock:
        _fails.append(time.time())
    return None, "Wrong username or password."


def server_sid(refresh=False):
    s = settings()
    with _sid_lock:
        if refresh or not _server_sid["sid"]:
            _server_sid["sid"], _ = qbit_login(s["username"], s["password"])
        return _server_sid["sid"]


def recent_failures():
    now = time.time()
    with _fails_lock:
        _fails[:] = [t for t in _fails if now - t < FAIL_WINDOW]
        return len(_fails)


def re_hash(h):
    return 40 <= len(h) <= 64 and all(c in "0123456789abcdef" for c in h)


# ---------------------------------------------------------------- network detection
def own_network(target):
    """The network qBittorrent most likely sees qBit Lite's requests from.

    The local address used to reach qBittorrent, widened to its interface's
    network (read from /proc/net/route), so it survives container restarts.
    """
    ip = None
    try:
        info = socket.getaddrinfo(target.host, target.port, socket.AF_INET, socket.SOCK_DGRAM)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(info[0][4])
            ip = ipaddress.ip_address(s.getsockname()[0])
    except OSError:
        return None
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            f = line.split()
            dest, mask = int(f[1], 16), int(f[7], 16)
            if dest == 0:
                continue
            # /proc/net/route stores addresses little-endian.
            net = ipaddress.ip_network((socket.inet_ntoa(dest.to_bytes(4, "little")),
                                        socket.inet_ntoa(mask.to_bytes(4, "little"))), strict=False)
            if ip in net and net.prefixlen >= 16:
                return str(net)
    except (OSError, ValueError, IndexError):
        pass
    return f"{ip}/32"


COMMON_PORTS = [8080, 8090, 8081, 8085, 8088, 8888, 9080, 9090, 8000, 8008]
LAN_PORTS = [8080, 8090]
SERVICE_NAMES = ["qbittorrent", "qbit", "qbittorrent-vpn", "qbittorrentvpn", "gluetun"]


def probe(url, timeout=1.5):
    """Returns {"url", "version", "open"} if url is a qBittorrent Web UI, else None."""
    try:
        t = Target(url)
        status, _, data = qbit_request("GET", "/api/v2/app/version", target=t, timeout=timeout)
        if status == 200 and data[:1] == b"v" and len(data) < 40:
            return {"url": t.url, "version": data.decode(errors="replace").strip(), "open": True}
        if status == 403 and data.strip() == b"Forbidden":
            # Any app could answer 403; make sure the page is qBittorrent's (or VueTorrent's).
            status, _, page = qbit_request("GET", "/", target=t, timeout=timeout)
            low = page[:4000].lower()
            if b"qbittorrent" in low or b"vuetorrent" in low:
                return {"url": t.url, "version": "", "open": False}
    except (OSError, ValueError, http.client.HTTPException):
        pass
    return None


def resolves(name):
    try:
        socket.getaddrinfo(name, None, socket.AF_INET)
        return True
    except OSError:
        return False


def discover(page_host):
    """Looks for qBittorrent: on the Docker host, under usual container names,
    and on the LAN around the address the browser used to open qBit Lite."""
    cands = []
    if resolves("host.docker.internal"):
        cands += [("This server", f"http://host.docker.internal:{p}") for p in COMMON_PORTS]
    cands += [("Container “%s”" % n, f"http://{n}:{p}") for n in SERVICE_NAMES if resolves(n) for p in (8080, 8090)]
    lan_ip = None
    try:
        lan_ip = ipaddress.ip_address(page_host)
    except ValueError:
        pass
    if lan_ip and lan_ip.version == 4 and lan_ip.is_private:
        cands += [("This server", f"http://{lan_ip}:{p}") for p in COMMON_PORTS]
        for ip in ipaddress.ip_network(f"{lan_ip}/24", strict=False).hosts():
            if ip != lan_ip:
                cands += [(str(ip), f"http://{ip}:{p}") for p in LAN_PORTS]
    found, lock = [], threading.Lock()
    it = iter(cands)

    def worker():
        while True:
            with lock:
                c = next(it, None)
            if c is None:
                return
            r = probe(c[1], timeout=0.8)
            if r:
                r["label"] = c[0]
                with lock:
                    found.append(r)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(64)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(timeout=20)
    # The same qBittorrent often answers on host.docker.internal and on the LAN IP:
    # keep host.docker.internal, which also suits the "No login" whitelist.
    order = {u: i for i, (_, u) in enumerate(cands)}
    found.sort(key=lambda r: order.get(r["url"], 1e9))
    out, seen_ports = [], set()
    for r in found:
        u = urlparse(r["url"])
        if u.hostname in ("host.docker.internal", str(lan_ip)):
            if u.port in seen_ports:
                continue
            seen_ports.add(u.port)
        out.append(r)
    return out


def open_access(target):
    """True if qBittorrent answers without any login (whitelisted or auth off)."""
    status, _, _ = qbit_request("GET", "/api/v2/app/version", target=target, timeout=10)
    return status == 200


# ---------------------------------------------------------------- move progress
# qBittorrent doesn't report how far a "moving" torrent has got. When its folders
# are mounted here at the same paths (read-only), we measure the files that have
# already arrived at the destination instead.
_files_cache = {}


def qbit_json(path, cookie):
    h = {"Cookie": cookie} if cookie else {}
    status, _, data = qbit_request("GET", path, None, h, timeout=15)
    if status != 200:
        raise PermissionError(status)
    return json.loads(data)


def move_progress(hashes, cookie):
    info = qbit_json("/api/v2/torrents/info?hashes=" + quote("|".join(hashes)), cookie)
    out = {}
    for t in info:
        h = t["hash"]
        if t.get("state") != "moving":
            continue
        files = _files_cache.get(h)
        if files is None:
            files = [f for f in qbit_json(f"/api/v2/torrents/files?hash={h}", cookie) if f.get("priority", 1) > 0]
            _files_cache[h] = files
        dest = Path(t.get("save_path") or "")
        src = Path(t.get("download_path") or "") if t.get("download_path") else None
        total = sum(f["size"] for f in files) or 1
        if not dest.is_dir():
            out[h] = {"known": False}
            continue
        done = 0
        for f in files:
            try:
                done += min((dest / f["name"]).stat().st_size, f["size"])
            except OSError:
                pass
        # Only a move from the incomplete folder to the save path can be measured.
        known = src is not None and src != dest
        out[h] = {"known": known, "done": done, "total": total, "progress": done / total}
    return out


# ---------------------------------------------------------------- turtle automation
# Turns qBittorrent's alternative speed limits ("turtle mode") on while something
# is downloading and off again once nothing has downloaded for a while. With a
# low alternative upload limit, uploads stay unlimited except while you download.
AUTO_FILE = CONFIG_DIR / "automation.json"
AUTO_DEFAULTS = {"enabled": False, "interval": 30, "off_delay": 120}
DOWNLOADING = {"downloading", "forcedDL", "metaDL", "forcedMetaDL"}
_auto = {"cfg": None, "status": {}, "wake": threading.Event()}


def auto_cfg():
    if _auto["cfg"] is None:
        cfg = dict(AUTO_DEFAULTS)
        try:
            cfg.update({k: v for k, v in json.loads(AUTO_FILE.read_text()).items() if k in AUTO_DEFAULTS})
        except (OSError, ValueError):
            pass
        _auto["cfg"] = cfg
    return _auto["cfg"]


def save_auto_cfg(new):
    cfg = dict(auto_cfg())
    if "enabled" in new:
        cfg["enabled"] = bool(new["enabled"])
    for k, lo, hi in (("interval", 5, 600), ("off_delay", 0, 3600)):
        if k in new:
            cfg[k] = max(lo, min(hi, int(new[k])))
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    AUTO_FILE.write_text(json.dumps(cfg, indent=2))
    _auto["cfg"] = cfg
    _auto["status"].pop("want", None)  # re-apply on the next check
    _auto["wake"].set()
    return cfg


def server_cookie():
    """Cookie for requests qBit Lite makes on its own, or False if it can't sign in by itself."""
    s = settings()
    if not s or s["mode"] == "login":
        return False
    return server_sid() if s["mode"] == "credentials" else None


def auto_check():
    st = _auto["status"]
    cookie = server_cookie()
    if cookie is False:
        st.update(error="Needs “No login” or “Remember my account” (Settings → Run setup again).")
        return
    h = {"Cookie": cookie} if cookie else {}
    status, _, data = qbit_request("GET", "/api/v2/torrents/info?filter=downloading", None, h, timeout=15)
    if status == 403 and settings()["mode"] == "credentials":
        server_sid(refresh=True)
    if status != 200:
        st.update(error=f"qBittorrent answered HTTP {status}")
        return
    active = [t for t in json.loads(data) if t.get("state") in DOWNLOADING or t.get("dlspeed", 0) > 0]
    now = time.time()
    if active:
        st["last_active"] = now
    want = bool(active) or now - st.get("last_active", 0) < auto_cfg()["off_delay"]
    _, _, cur = qbit_request("GET", "/api/v2/transfer/speedLimitsMode", None, h, timeout=15)
    on = cur.strip() == b"1"
    # Only act when the wanted state changes, so a manual tap on the turtle
    # sticks until a download starts or ends.
    if st.get("want") != want:
        if on != want:
            qbit_request("POST", "/api/v2/transfer/toggleSpeedLimitsMode", None, h, timeout=15)
            on = want
            st["last_change"] = now
        st["want"] = want
    st.update(error=None, downloading=len(active), turtle=on, checked=now)


def auto_loop():
    while True:
        cfg = auto_cfg()
        if cfg["enabled"] and settings():
            try:
                auto_check()
            except (OSError, ValueError, http.client.HTTPException) as e:
                _auto["status"]["error"] = f"Can't reach qBittorrent: {e}"
        _auto["wake"].wait(cfg["interval"])
        _auto["wake"].clear()


# ---------------------------------------------------------------- HTTP handler
class Handler(BaseHTTPRequestHandler):
    server_version = "qBitLite/" + VERSION
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def send_bytes(self, code, data, ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, obj, code=200):
        self.send_bytes(code, json.dumps(obj).encode())

    def read_body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def read_json(self):
        try:
            return json.loads(self.read_body() or b"{}")
        except ValueError:
            return {}

    # ---- routing
    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def route(self, method):
        path = urlparse(self.path).path
        if path == "/lite/config":
            return self.config()
        if path.startswith("/lite/setup/") and method == "POST":
            return self.setup_step(path.rsplit("/", 1)[1])
        if path == "/lite/automation":
            return self.automation(method)
        if path == "/lite/moves":
            return self.moves()
        if path.startswith("/api/v2/"):
            if not settings():
                return self.send_json({"error": "not set up"}, 503)
            return self.proxy(method)
        if method == "GET":
            return self.serve_static(path)
        return self.send_json({"error": "not found"}, 404)

    def config(self):
        s = settings()
        if not s:
            return self.send_json({"configured": False, "suggested_url": SUGGESTED_URL, "version": VERSION})
        return self.send_json({"configured": True, "mode": s["mode"], "url": s["url"],
                               "env": s.get("source") == "env", "subnet": s.get("subnet"),
                               "server_auth": s["mode"] != "login", "version": VERSION})

    def auth_cookie(self):
        s = settings()
        if s["mode"] == "credentials":
            return server_sid()
        if s["mode"] == "bypass":
            return None
        return self.headers.get("Cookie")

    def can_change_settings(self):
        """Before setup anyone may set it up; afterwards only someone who can
        already control qBittorrent through qBit Lite."""
        s = settings()
        if not s:
            return True
        if s.get("source") == "env":
            return False
        try:
            c = self.auth_cookie()
            status, _, _ = qbit_request("GET", "/api/v2/app/version", None, {"Cookie": c} if c else {}, timeout=10)
            # With the whitelist or the saved account no longer accepted, qBit Lite
            # is unusable anyway: let it be set up again. In "login" mode the
            # browser must be signed in.
            return status == 200 or (status == 403 and s["mode"] != "login")
        except OSError:
            # qBittorrent unreachable: allow fixing the address.
            return True

    # ---- first-run setup
    def setup_step(self, step):
        req = self.read_json()
        if not self.can_change_settings():
            msg = "Settings come from environment variables." if (settings() or {}).get("source") == "env" else "Sign in first."
            return self.send_json({"ok": False, "error": msg}, 403)
        if step == "discover":
            host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]")
            return self.send_json({"ok": True, "found": discover(host)})
        if step == "reset":
            try:
                SETTINGS_FILE.unlink()
            except FileNotFoundError:
                pass
            set_settings(None)
            return self.send_json({"ok": True})
        try:
            target = Target(str(req.get("url", "")).strip())
        except ValueError as e:
            return self.send_json({"ok": False, "error": str(e)})
        try:
            if step == "test":
                return self.setup_test(target)
            if step == "login":
                cookie, err = qbit_login(req.get("username", ""), req.get("password", ""), target)
                if err:
                    return self.send_json({"ok": False, "error": err})
                return self.send_json({"ok": True, "subnet": own_network(target)})
            if step == "finish":
                return self.setup_finish(target, req)
        except (OSError, http.client.HTTPException) as e:
            return self.send_json({"ok": False, "error": f"Can't reach qBittorrent at {target.url}: {e}"})
        return self.send_json({"ok": False, "error": "unknown step"}, 404)

    def setup_test(self, target):
        status, _, data = qbit_request("GET", "/api/v2/app/version", target=target, timeout=10)
        if status == 200:
            return self.send_json({"ok": True, "open": True, "version": data.decode(errors="replace").strip(),
                                   "subnet": own_network(target)})
        if status == 403:
            # 403 is what qBittorrent answers to a request without a session.
            return self.send_json({"ok": True, "open": False, "subnet": own_network(target)})
        if status == 401:
            return self.send_json({"ok": False, "error": "qBittorrent refused the request (401). If you use a reverse proxy, point qBit Lite at qBittorrent directly."})
        return self.send_json({"ok": False, "error": f"That address answered HTTP {status}. Is it the qBittorrent WebUI?"})

    def setup_finish(self, target, req):
        mode = req.get("mode")
        user, pw = req.get("username", ""), req.get("password", "")
        new = {"url": target.url, "mode": mode}
        if mode == "open":
            # qBittorrent needs no login from here already.
            if not open_access(target):
                return self.send_json({"ok": False, "error": "qBittorrent asks for a login. Go back and sign in."})
            new["mode"] = "bypass"
        elif mode == "bypass":
            subnet = str(req.get("subnet", "")).strip()
            try:
                subnet = str(ipaddress.ip_network(subnet, strict=False))
            except ValueError:
                return self.send_json({"ok": False, "error": f"“{subnet}” isn't a valid network, like 172.31.250.0/24."})
            cookie, err = qbit_login(user, pw, target)
            if err:
                return self.send_json({"ok": False, "error": err})
            h = {"Cookie": cookie} if cookie else {}
            status, _, data = qbit_request("GET", "/api/v2/app/preferences", None, h, target)
            if status != 200:
                return self.send_json({"ok": False, "error": f"Couldn't read qBittorrent's settings (HTTP {status})."})
            prefs = json.loads(data)
            current = [x.strip() for x in str(prefs.get("bypass_auth_subnet_whitelist", "")).replace(",", "\n").splitlines() if x.strip()]
            if subnet not in current:
                current.append(subnet)
            body = urlencode({"json": json.dumps({"bypass_auth_subnet_whitelist_enabled": True,
                                                  "bypass_auth_subnet_whitelist": "\n".join(current)})})
            h["Content-Type"] = "application/x-www-form-urlencoded"
            status, _, _ = qbit_request("POST", "/api/v2/app/setPreferences", body, h, target)
            if status != 200:
                return self.send_json({"ok": False, "error": f"qBittorrent didn't accept the change (HTTP {status})."})
            if not open_access(target):
                return self.send_json({"ok": False, "added": True, "error":
                    f"{subnet} is now whitelisted in qBittorrent, but it still asks qBit Lite for a login, "
                    "so it sees qBit Lite's requests from another address. This happens when qBittorrent runs "
                    "on another machine. Enter the address qBittorrent sees (usually this server's LAN IP, as "
                    "x.x.x.x/32) or choose “Remember my account” instead."})
            new["subnet"] = subnet
        elif mode == "credentials":
            cookie, err = qbit_login(user, pw, target)
            if err:
                return self.send_json({"ok": False, "error": err})
            new.update(username=user, password=pw)
        elif mode == "login":
            pass
        else:
            return self.send_json({"ok": False, "error": "Choose a sign-in method."})
        try:
            save_settings(new)
        except OSError as e:
            return self.send_json({"ok": False, "error": f"Couldn't save settings in {CONFIG_DIR}: {e}. Is the config volume writable?"})
        new["source"] = "file"
        set_settings(new)
        return self.send_json({"ok": True})

    # ---- turtle automation
    def automation(self, method):
        if method == "POST":
            if not settings() or not self.can_change_settings():
                return self.send_json({"ok": False, "error": "Sign in first."}, 403)
            try:
                save_auto_cfg(self.read_json())
            except (OSError, ValueError, TypeError) as e:
                return self.send_json({"ok": False, "error": str(e)}, 400)
        st = dict(_auto["status"])
        return self.send_json({"ok": True, **auto_cfg(), "status": st,
                               "supported": bool(settings()) and settings()["mode"] != "login"})

    # ---- move progress
    def moves(self):
        if not settings():
            return self.send_json({})
        q = parse_qs(urlparse(self.path).query)
        hashes = [h for h in (q.get("hashes", [""])[0]).split(",") if re_hash(h)]
        if not hashes:
            return self.send_json({})
        try:
            return self.send_json(move_progress(hashes, self.auth_cookie()))
        except PermissionError:
            return self.send_json({"error": "forbidden"}, 403)
        except (OSError, ValueError) as e:
            return self.send_json({"error": str(e)}, 502)

    # ---- proxy
    def proxy(self, method):
        body = self.read_body() or None
        path = urlparse(self.path).path
        cfg = settings()
        if not cfg:
            return self.send_json({"error": "not set up"}, 503)
        mode = cfg["mode"]
        # GETs are small; a slow answer means qBittorrent is stalled (for
        # example while it copies a large move between disks). Fail fast so
        # the UI can say so, instead of hanging for a minute.
        timeout = 15 if method == "GET" else 60
        is_login = path == "/api/v2/auth/login"

        if is_login and recent_failures() >= MAX_FAILS:
            return self.send_bytes(429, b"Too many failed logins. Wait a few minutes.", "text/plain")

        fwd = {}
        for k in ("Content-Type", "Accept"):
            if self.headers.get(k):
                fwd[k] = self.headers[k]

        server_mode = mode == "credentials" and not is_login
        if server_mode:
            sid = server_sid()
            if sid:
                fwd["Cookie"] = sid
        elif mode == "login" and self.headers.get("Cookie"):
            fwd["Cookie"] = self.headers["Cookie"]

        try:
            status, headers, data = qbit_request(method, self.path, body, fwd, timeout=timeout)
            if server_mode and status == 403:
                sid = server_sid(refresh=True)
                if sid:
                    fwd["Cookie"] = sid
                    status, headers, data = qbit_request(method, self.path, body, fwd, timeout=timeout)
        except TimeoutError:
            return self.send_bytes(504, f"qBittorrent at {cfg['url']} is not responding.".encode(), "text/plain")
        except (OSError, http.client.HTTPException) as e:
            return self.send_bytes(502, f"Cannot reach qBittorrent at {cfg['url']}: {e}".encode(), "text/plain")

        if is_login:
            with _fails_lock:
                if login_ok(status, data):
                    _fails.clear()
                else:
                    _fails.append(time.time())

        extra = []
        ctype = "text/plain"
        for k, v in headers:
            lk = k.lower()
            if lk == "content-type":
                ctype = v
            elif lk == "set-cookie" and mode == "login":
                # Keep the session cookie across browser restarts (qBittorrent still
                # expires idle sessions on its side, then the UI asks to log in again).
                if "max-age" not in v.lower():
                    v += "; Max-Age=2592000"
                extra.append(("Set-Cookie", v))
        self.send_bytes(status, data, ctype, extra)

    # ---- static
    def serve_static(self, path):
        if path in ("", "/"):
            path = "/index.html"
        f = (STATIC_DIR / path.lstrip("/")).resolve()
        if STATIC_DIR.resolve() not in f.parents or not f.is_file():
            return self.send_json({"error": "not found"}, 404)
        ctype = {".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css",
                 ".svg": "image/svg+xml", ".png": "image/png",
                 ".webmanifest": "application/manifest+json"}.get(f.suffix, "application/octet-stream")
        self.send_bytes(200, f.read_bytes(), ctype, [("Cache-Control", "no-cache")])


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    threading.Thread(target=auto_loop, daemon=True).start()
    s = settings()
    state = f"{s['url']} ({s['mode']}, from {s['source']})" if s else "not set up yet: open the web UI to connect"
    print(f"qBit Lite {VERSION} on :{PORT} -> {state}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
