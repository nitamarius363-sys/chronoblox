"""ChronoBlox 2020 backend - stdlib only, no pip needed.
Run: python backend.py  (serves on :3004)
Data: ./data/users.json, bans.json, sessions.json
"""
import hashlib
import hmac
import json
import os
import secrets
import threading as _th
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
os.makedirs(DATA, exist_ok=True)

USERS_F = os.path.join(DATA, "users.json")
BANS_F = os.path.join(DATA, "bans.json")
SESS_F = os.path.join(DATA, "sessions.json")

OWNER = "chronoblox"
SESSION_DAYS = 30

def is_admin(name):
    """True for the owner or any user with admin flag. Owner can never lose it."""
    if not isinstance(name, str) or not name:
        return False
    if name.lower() == OWNER:
        return True
    try:
        rec = load(USERS_F, {}).get(name.lower())
        return bool(rec and rec.get("admin") is True)
    except Exception:
        return False

# Discord logging (embeds). URL lives in data/webhook.url so it is never
# sent to browsers. Passwords are NEVER logged anywhere.
def _webhook_url():
    try:
        with open(os.path.join(DATA, "webhook.url"), encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return ""

def discord_embed(title, color, fields):
    url = _webhook_url()
    if not url:
        return
    payload = {
        "embeds": [{
            "title": title,
            "color": color,
            "fields": [{"name": k, "value": str(v)[:500], "inline": True} for k, v in fields],
            "footer": {"text": "ChronoBlox 2020"},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }]
    }
    def _send():
        try:
            req = urllib.request.Request(
                url, data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json",
                         "User-Agent": "ChronoBlox/1.0"}, method="POST")
            urllib.request.urlopen(req, timeout=8).read()
        except Exception:
            pass
    _th.Thread(target=_send, daemon=True).start()

# throttled security alerts (max 1 per key per 5 min so floods can't
# spam the channel or get the webhook rate-limited by Discord)
_alerts = {}
_alerts_lock = _th.Lock()

def sec_alert(key, title, color, fields):
    now = time.time()
    with _alerts_lock:
        if now - _alerts.get(key, 0) < 300:
            return
        _alerts[key] = now
    discord_embed(title, color, fields)

# mass-registration guard: 3 accounts per IP per 10 min.
# 10+ in 60s = bot burst -> terminate those accounts + device-ban 1 day.
REG_MAX = 3
REG_WIN = 600
BURST_N = 10
BURST_WIN = 60
_regs = {}
_regs_lock = _th.Lock()

def reg_event(ip):
    """Returns 'slow' | 'burst' | 'ok'. Records this attempt."""
    now = time.time()
    with _regs_lock:
        lst = _regs.get(ip, [])
        lst = [t for t in lst if now - t < max(REG_WIN, BURST_WIN)]
        lst.append(now)
        _regs[ip] = lst
        recent60 = sum(1 for t in lst if now - t < BURST_WIN)
        recent600 = len(lst)
        if recent60 >= BURST_N:
            return "burst"
        if recent600 > REG_MAX:
            return "slow"
        return "ok"
# login/register: 10 tries per 60s per IP, then 429. slows brute force + basic floods.
RATE_MAX = 10
RATE_WIN = 60
_rate = {}
_rate_lock = _th.Lock()

def rate_hit(ip):
    now = time.time()
    with _rate_lock:
        rec = _rate.get(ip)
        if not rec or now - rec["start"] > RATE_WIN:
            rec = {"start": now, "n": 0}
            _rate[ip] = rec
        rec["n"] += 1
        # prune sometimes
        if len(_rate) > 2000 and now - rec["start"] > RATE_WIN:
            for k in [k for k, v in _rate.items() if now - v["start"] > RATE_WIN]:
                _rate.pop(k, None)
        return rec["n"] > RATE_MAX

SEC_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
}

def load(p, d):
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return d

def save(p, o):
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(o, f)
    os.replace(tmp, p)

def now_ms():
    return int(time.time() * 1000)

def valid_name(n):
    if not isinstance(n, str):
        return False
    if len(n) < 3 or len(n) > 16:
        return False
    return all(c.isalnum() or c == "_" for c in n)

def hash_pw(pw, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), bytes.fromhex(salt), 200_000)
    return salt, dk.hex()

def check_pw(pw, salt, want):
    _, h = hash_pw(pw, salt)
    return hmac.compare_digest(h, want)

def ban_left(b):
    left = b.get("until", 0) - now_ms()
    return left if left > 0 else 0

def active_user_ban(bans, name):
    b = bans.get(name.lower())
    if b and ban_left(b) > 0:
        return b
    return None

def active_device_ban(bans, device):
    if not device:
        return None
    for b in bans.values():
        if b.get("device") and b["device"] == device and ban_left(b) > 0:
            return b
    return None

MIME = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".json": "application/json",
}

# Admin panel markup. Served ONLY via GET /api/panel to admins - it is NOT
# part of index.html, so guests and normal users never receive this HTML.
PANEL_HTML = """<section class="page active" id="page-panel">
<h1>Panel</h1>
<div style="max-width:420px;margin:12px 0">
<label style="display:block;font-size:13px;color:#bbb;margin:8px 0 4px">Username to ban</label>
<input id="ban-user" maxlength="16" placeholder="e.g. noob123" style="width:100%;padding:9px 10px;border-radius:6px;border:1px solid #555">
<label style="display:block;font-size:13px;color:#bbb;margin:8px 0 4px">Reason</label>
<input id="ban-reason" maxlength="120" placeholder="e.g. exploiting" style="width:100%;padding:9px 10px;border-radius:6px;border:1px solid #555">
<div style="display:flex;gap:8px;margin-top:8px">
<input id="ban-num" type="number" min="1" max="9999" value="1" style="flex:1;padding:9px 10px;border-radius:6px;border:1px solid #555">
<select id="ban-unit" style="flex:1;padding:9px;border-radius:6px">
<option value="hours">Hours</option>
<option value="days" selected>Days</option>
<option value="years">Years</option>
</select>
</div>
<button type="button" id="btn-ban" style="margin-top:10px;background:#c00;color:#fff;border:0;border-radius:6px;padding:10px 16px;font-weight:700;cursor:pointer">Ban</button>
<div id="ban-msg" style="min-height:18px;font-size:13px;color:#ff8a8a;margin-top:8px"></div>
</div>
<h2>Banned</h2>
<div id="ban-list" style="color:#bbb;font-size:14px">None.</div>
<h2 style="margin-top:18px">Reset password</h2>
<div style="max-width:420px">
<label style="display:block;font-size:13px;color:#bbb;margin:8px 0 4px">Username</label>
<input id="rp-user" maxlength="16" placeholder="e.g. noob123" style="width:100%;padding:9px 10px;border-radius:6px;border:1px solid #555">
<label style="display:block;font-size:13px;color:#bbb;margin:8px 0 4px">New password</label>
<input id="rp-pass" maxlength="64" placeholder="min 4 chars" style="width:100%;padding:9px 10px;border-radius:6px;border:1px solid #555">
<button type="button" id="btn-rp" style="margin-top:10px;background:#00a2ff;color:#fff;border:0;border-radius:6px;padding:10px 16px;font-weight:700;cursor:pointer">Set password</button>
<div id="rp-msg" style="min-height:18px;font-size:13px;color:#ff8a8a;margin-top:8px"></div>
</div>
</section>"""

class Handler(BaseHTTPRequestHandler):
    server_version = "Server"
    sys_version = ""

    def log_message(self, *a):
        pass

    def client_ip(self):
        return self.client_address[0] if self.client_address else "?"

    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in SEC_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def body_json(self, limit=65536):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except Exception:
            n = 0
        if n <= 0 or n > limit:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            return {}

    def token_name(self):
        h = self.headers.get("Authorization") or ""
        tok = h[7:] if h.startswith("Bearer ") else ""
        if not tok:
            return None, None
        sess = load(SESS_F, {})
        s = sess.get(tok)
        if not s or s.get("exp", 0) < int(time.time()):
            return None, None
        return tok, s.get("name")

    def require_admin(self):
        """(tok, name) if caller is admin, else sends 403 Unauthorized and returns (None, None)."""
        tok, me = self.token_name()
        if not me or not is_admin(me):
            self.send_json({"error": "Unauthorized"}, 403)
            return None, None
        return tok, me

    # ---- API ----
    def do_POST(self):
        u = urlparse(self.path).path
        if not u.startswith("/api/"):
            return self.send_json({"error": "not found"}, 404)

        if u == "/api/register":
            if rate_hit(self.client_ip()):
                sec_alert("rl:" + self.client_ip(), ":rotating_light: Rate limited", 0xFF5500,
                          [("IP", self.client_ip()), ("On", "/api/register")])
                return self.send_json({"error": "Too many tries. Wait a minute."}, 429)
            d = self.body_json()
            name = str(d.get("username") or "").strip()
            pw = str(d.get("password") or "")
            dev = str(d.get("deviceId") or "")[:64]
            if not valid_name(name):
                return self.send_json({"error": "Username: 3-16 letters, numbers or _."}, 400)
            if len(pw) < 4 or len(pw) > 128:
                return self.send_json({"error": "Password needs 4-128 chars."}, 400)
            users = load(USERS_F, {})
            bans = load(BANS_F, {})
            if users.get(name.lower()):
                return self.send_json({"error": "That name is taken."}, 409)
            # mass-registration guard
            verdict = reg_event(self.client_ip())
            if verdict == "burst" and name.lower() != OWNER:
                # terminate: wipe accounts from this IP made in last 10 min + device-ban 1 day
                ip = self.client_ip()
                cutoff = now_ms() - REG_WIN * 1000
                killed = []
                for k, rec in list(users.items()):
                    if k != OWNER and rec.get("ip") == ip and rec.get("created", 0) >= cutoff:
                        killed.append(rec.get("name", k))
                        users.pop(k, None)
                bans["~spamlock"] = {
                    "name": "~spamlock", "until": now_ms() + 86400000,
                    "reason": "mass registration blocked", "device": dev, "by": "auto",
                }
                save(USERS_F, users)
                save(BANS_F, bans)
                sess = load(SESS_F, {})
                sess = {t: s for t, s in sess.items() if s.get("name", "") not in killed}
                save(SESS_F, sess)
                discord_embed(":rotating_light: Auto spam block", 0xCC0000,
                              [("IP", ip), ("Killed", ", ".join(killed) or "-"),
                               ("Device", dev or "-")])
                return self.send_json({"error": "banned", "until": bans["~spamlock"]["until"], "reason": "mass registration blocked"}, 403)
            if verdict == "slow" and name.lower() != OWNER:
                sec_alert("slow:" + self.client_ip(), ":warning: Mass accounts blocked", 0xFFAA00,
                          [("IP", self.client_ip()), ("Tried", name)])
                return self.send_json({"error": "Too many accounts from here. Wait 10 minutes."}, 429)
            # device banned? no fresh accounts (owner name can still be claimed once)
            if name.lower() != OWNER:
                db = active_device_ban(bans, dev)
                if db:
                    return self.send_json({"error": "banned", "until": db["until"], "reason": db.get("reason", "")}, 403)
            salt, h = hash_pw(pw)
            users[name.lower()] = {"name": name, "salt": salt, "hash": h, "created": now_ms(), "ip": self.client_ip(), "device": dev, "admin": name.lower() == OWNER}
            save(USERS_F, users)
            tok = secrets.token_hex(32)
            sess = load(SESS_F, {})
            sess[tok] = {"name": name, "exp": int(time.time()) + SESSION_DAYS * 86400}
            save(SESS_F, sess)
            ip = self.client_ip()
            discord_embed(":inbox_tray: Account created", 0x00B06F,
                          [("User", name), ("Account #", len(users)),
                           ("IP", ip), ("Device", dev or "-")])
            return self.send_json({"token": tok, "name": name, "isAdmin": is_admin(name)})

        if u == "/api/login":
            if rate_hit(self.client_ip()):
                sec_alert("rl:" + self.client_ip(), ":rotating_light: Rate limited", 0xFF5500,
                          [("IP", self.client_ip()), ("On", "/api/login")])
                return self.send_json({"error": "Too many tries. Wait a minute."}, 429)
            d = self.body_json()
            name = str(d.get("username") or "").strip()
            pw = str(d.get("password") or "")
            dev = str(d.get("deviceId") or "")[:64]
            users = load(USERS_F, {})
            bans = load(BANS_F, {})
            b = active_user_ban(bans, name)
            if b:
                return self.send_json({"error": "banned", "until": b["until"], "reason": b.get("reason", "")}, 403)
            if name.lower() != OWNER:
                db = active_device_ban(bans, dev)
                if db:
                    return self.send_json({"error": "banned", "until": db["until"], "reason": db.get("reason", "")}, 403)
            rec = users.get(name.lower())
            if not rec:
                sec_alert("fail:" + self.client_ip(), ":warning: Failed login", 0xFFAA00,
                          [("User", name), ("Why", "no such account"),
                           ("IP", self.client_ip()), ("Device", dev or "-")])
                return self.send_json({"error": "Wrong username or password."}, 401)
            ok = check_pw(pw, rec["salt"], rec["hash"])
            if not ok:
                sec_alert("fail:" + self.client_ip(), ":warning: Failed login", 0xFFAA00,
                          [("User", name), ("Why", "wrong password"),
                           ("IP", self.client_ip()), ("Device", dev or "-")])
                return self.send_json({"error": "Wrong username or password."}, 401)
            tok = secrets.token_hex(32)
            sess = load(SESS_F, {})
            sess[tok] = {"name": rec["name"], "exp": int(time.time()) + SESSION_DAYS * 86400}
            save(SESS_F, sess)
            discord_embed(":key: Login", 0x00A2FF,
                          [("User", rec["name"]), ("IP", self.client_ip()), ("Device", dev or "-")])
            return self.send_json({"token": tok, "name": rec["name"], "isAdmin": is_admin(rec["name"])})

        if u == "/api/logout":
            tok, _ = self.token_name()
            if tok:
                sess = load(SESS_F, {})
                sess.pop(tok, None)
                save(SESS_F, sess)
            return self.send_json({"ok": True})

        if u == "/api/ban":
            _, me = self.require_admin()
            if not me:
                return
            d = self.body_json()
            target = str(d.get("target") or "").strip()
            reason = str(d.get("reason") or "")[:120]
            try:
                num = int(d.get("amount", 0))
            except Exception:
                num = 0
            unit = str(d.get("unit") or "days")
            if not valid_name(target):
                return self.send_json({"error": "Bad username."}, 400)
            if target.lower() == OWNER:
                return self.send_json({"error": "Cant ban owner."}, 400)
            if is_admin(target) and me.lower() != OWNER:
                return self.send_json({"error": "Unauthorized"}, 403)
            if num < 1 or num > 9999 or unit not in ("hours", "days", "years"):
                return self.send_json({"error": "Pick 1-9999 hours/days/years."}, 400)
            mult = {"hours": 3600000, "days": 86400000, "years": 31536000000}[unit]
            dev = str(d.get("deviceId") or "")[:64]
            # if target exists on this server we know nothing extra about their device;
            # lock the request device too so same-browser alts are blocked
            bans = load(BANS_F, {})
            until = now_ms() + num * mult
            bans[target.lower()] = {
                "name": target, "until": until,
                "reason": reason, "device": dev, "by": me,
            }
            save(BANS_F, bans)
            # kill their sessions
            sess = load(SESS_F, {})
            sess = {t: s for t, s in sess.items() if s.get("name", "").lower() != target.lower()}
            save(SESS_F, sess)
            discord_embed(":hammer: Banned", 0xCC0000,
                          [("User", target), ("For", "%s %s" % (num, unit)),
                           ("Until", time.strftime("%Y-%m-%d %H:%M", time.localtime(until / 1000))),
                           ("Reason", reason or "-"), ("By", me)])
            return self.send_json({"ok": True})

        if u == "/api/unban":
            _, me = self.require_admin()
            if not me:
                return
            d = self.body_json()
            target = str(d.get("target") or "").strip().lower()
            bans = load(BANS_F, {})
            bans.pop(target, None)
            save(BANS_F, bans)
            discord_embed(":white_check_mark: Unbanned", 0x808080,
                          [("User", target), ("By", me)])
            return self.send_json({"ok": True})

        if u == "/api/resetpw":
            _, me = self.require_admin()
            if not me:
                return
            d = self.body_json()
            target = str(d.get("target") or "").strip()
            pw = str(d.get("newPassword") or "")
            if not valid_name(target) or target.lower() == OWNER:
                return self.send_json({"error": "Bad username."}, 400)
            if len(pw) < 4 or len(pw) > 128:
                return self.send_json({"error": "Password needs 4-128 chars."}, 400)
            users = load(USERS_F, {})
            rec = users.get(target.lower())
            if not rec:
                return self.send_json({"error": "No such account."}, 404)
            if is_admin(target) and me.lower() != OWNER:
                return self.send_json({"error": "Unauthorized"}, 403)
            salt, h = hash_pw(pw)
            rec["salt"] = salt
            rec["hash"] = h
            save(USERS_F, users)
            # kill their sessions so the new password takes effect now
            sess = load(SESS_F, {})
            sess = {t: s for t, s in sess.items() if s.get("name", "").lower() != target.lower()}
            save(SESS_F, sess)
            discord_embed(":key: Password reset", 0xFFAA00,
                          [("User", rec["name"]), ("By", me)])
            return self.send_json({"ok": True})

        if u == "/api/setadmin":
            _, me = self.token_name()
            if not me or me.lower() != OWNER:
                return self.send_json({"error": "Unauthorized"}, 403)
            d = self.body_json()
            target = str(d.get("target") or "").strip()
            want = d.get("admin")
            if not valid_name(target) or target.lower() == OWNER:
                return self.send_json({"error": "Bad username."}, 400)
            users = load(USERS_F, {})
            rec = users.get(target.lower())
            if not rec:
                return self.send_json({"error": "No such account."}, 404)
            rec["admin"] = bool(want) if isinstance(want, bool) else True
            save(USERS_F, users)
            discord_embed(":shield: Admin changed", 0x800080,
                          [("User", rec["name"]),
                           ("Admin", "yes" if rec["admin"] else "no"),
                           ("By", me)])
            return self.send_json({"ok": True, "admin": rec["admin"]})

        return self.send_json({"error": "not found"}, 404)

    def do_GET(self):
        u = urlparse(self.path).path
        if u == "/api/me":
            _, me = self.token_name()
            if not me:
                return self.send_json({"error": "no session"}, 401)
            return self.send_json({"name": me, "isOwner": me.lower() == OWNER,
                                   "isAdmin": is_admin(me)})
        if u == "/api/bans":
            _, me = self.require_admin()
            if not me:
                return
            bans = load(BANS_F, {})
            out = [b for b in bans.values() if ban_left(b) > 0]
            return self.send_json({"bans": out})
        if u == "/api/panel":
            _, me = self.require_admin()
            if not me:
                return
            return self.send_json({"html": PANEL_HTML})
        if u == "/api/health":
            return self.send_json({"ok": True})

        if u == "/api/auth/google":
            try:
                cfg = json.load(open(os.path.join(DATA, "google.json"), encoding="utf-8"))
                cid = cfg.get("client_id", "")
            except Exception:
                cid = ""
            if not cid:
                return self.send_json({"error": "Google login not configured"}, 500)
            base = "https://chronoblox.brave16.free" if not ROOT.endswith("dev") else "http://localhost:3004"
            cb = base + "/api/auth/google/callback"
            url = ("https://accounts.google.com/o/oauth2/v2/auth?"
                   "client_id=%s&redirect_uri=%s&response_type=code&scope=openid%%20email%%20profile"
                   "&access_type=offline" % (cid, urllib.parse.quote(cb, safe="")))
            self.send_response(302)
            self.send_header("Location", url)
            self.end_headers()
            return None

        if u == "/api/auth/google/callback":
            q = urllib.parse.parse_qs(urlparse(self.path).query)
            code = (q.get("code") or [""])[0]
            err = (q.get("error") or [""])[0]
            if err or not code:
                return self.send_json({"error": "Google auth failed: " + (err or "no code")}, 400)
            try:
                cfg = json.load(open(os.path.join(DATA, "google.json"), encoding="utf-8"))
                cid = cfg.get("client_id", "")
                cs = cfg.get("client_secret", "")
            except Exception:
                return self.send_json({"error": "Google login not configured"}, 500)
            base = "https://chronoblox.brave16.free" if not ROOT.endswith("dev") else "http://localhost:3004"
            cb = base + "/api/auth/google/callback"
            body = urllib.parse.urlencode({
                "code": code, "client_id": cid, "client_secret": cs,
                "redirect_uri": cb, "grant_type": "authorization_code",
            }).encode()
            req = urllib.request.Request("https://oauth2.googleapis.com/token", data=body,
                                         headers={"Content-Type": "application/x-www-form-urlencoded"},
                                         method="POST")
            with urllib.request.urlopen(req, timeout=15) as r:
                tok = json.loads(r.read().decode())
            at = tok.get("access_token", "")
            if not at:
                return self.send_json({"error": "Google token exchange failed"}, 500)
            req2 = urllib.request.Request(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": "Bearer " + at})
            with urllib.request.urlopen(req2, timeout=15) as r:
                prof = json.loads(r.read().decode())
            gid = prof.get("sub", "")
            gname = prof.get("name", "")[:20]
            if not gid:
                return self.send_json({"error": "Google profile fetch failed"}, 500)
            # map google user -> local account
            users = load(USERS_F, {})
            gkey = "g_" + gid
            if gkey not in users:
                uname = gname or ("User" + gid[:6])
                # ensure unique
                base_name = uname[:16]
                i = 1
                while uname.lower() in users:
                    uname = base_name[:14] + str(i)
                    i += 1
                salt, h = hash_pw(secrets.token_hex(16))
                users[gkey] = {"name": uname, "salt": salt, "hash": h,
                               "created": now_ms(), "ip": "google", "device": "",
                               "admin": gkey == OWNER, "google_sub": gid}
                save(USERS_F, users)
            tok_sess = secrets.token_hex(32)
            sess = load(SESS_F, {})
            sess[tok_sess] = {"name": users[gkey]["name"], "exp": int(time.time()) + SESSION_DAYS * 86400}
            save(SESS_F, sess)
            discord_embed(":inbox_tray: Google sign-in", 0x4285F4,
                          [("User", users[gkey]["name"]), ("Google ID", gid[:12] + "...")])
            self.send_response(302)
            self.send_header("Location", base + "/#token=" + tok_sess + "&name=" + urllib.parse.quote(users[gkey]["name"]))
            self.end_headers()
            return None

        # static files
        path = u.lstrip("/") or "index.html"
        # block data dir + server source + backups (readable script lives in .bak)
        if (path.startswith("data/") or path in ("backend.py", "obf.py")
                or path.endswith((".bak", ".tmp"))):
            return self.send_json({"error": "not found"}, 404)
        full = os.path.normpath(os.path.join(ROOT, path))
        if not full.startswith(ROOT) or not os.path.isfile(full):
            full = os.path.join(ROOT, "index.html")
        ext = os.path.splitext(full)[1].lower()
        try:
            with open(full, "rb") as f:
                body = f.read()
        except Exception:
            return self.send_json({"error": "not found"}, 404)
        self.send_response(200)
        self.send_header("Content-Type", MIME.get(ext, "application/octet-stream"))
        self.send_header("Content-Length", str(len(body)))
        for k, v in SEC_HEADERS.items():
            if k == "Cache-Control" and not full.endswith("index.html"):
                continue
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else int(os.environ.get("PORT", 3004))
    # localhost only: not reachable from the internet, your biggest DDoS shield.
    # small queue + timeouts so one slow client can't eat everything.
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.request_queue_size = 64
    srv.timeout = 10
    Handler.timeout = 10
    print(f"ChronoBlox backend on http://localhost:{port}/", flush=True)
    try:
        nu = len(load(USERS_F, {}))
        nb = len([b for b in load(BANS_F, {}).values() if ban_left(b) > 0])
    except Exception:
        nu, nb = 0, 0
    discord_embed(":green_circle: Server online", 0x00B06F,
                  [("Port", port), ("Users", nu), ("Active bans", nb),
                   ("At", time.strftime("%H:%M:%S", time.localtime()))])
    srv.serve_forever()
