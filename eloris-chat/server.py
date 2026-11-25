#!/usr/bin/env python3
"""Eloris backend. REST API + SQLite + realtime events. Python standard library only (3.9+).

Run:  python3 server.py            (then open http://localhost:8000)
Docs: see README.md
"""
import argparse
import hashlib
import hmac
import json
import mimetypes
import os
import pathlib
import queue
import re
import secrets
import sqlite3
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

import db

# ----------------------------------------------------------------------------
# Clock (functions, so tests can fake time)
# ----------------------------------------------------------------------------
DAY = 86400


def now():
    return int(time.time())


def day_of(ts):
    return time.strftime("%Y-%m-%d", time.gmtime(ts))


def today():
    return day_of(now())


def yesterday():
    return day_of(now() - DAY)


def env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


POST_TTL = DAY                      # Eloments and Glides disappear after 24h
SESSION_TTL = 30 * DAY
MAX_JSON = 1_000_000
MAX_VIDEO_SECONDS = 300             # short videos: 5 minutes
QUIET = False


class ApiError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


# ----------------------------------------------------------------------------
# Small utilities
# ----------------------------------------------------------------------------
CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def text_field(d, key, lo, hi, label, multiline=False):
    v = d.get(key)
    if not isinstance(v, str):
        raise ApiError(400, "bad_" + key, f"{label} is required.")
    v = CTRL.sub("", v)
    if not multiline:
        v = re.sub(r"\s+", " ", v)
    v = v.strip()
    if not lo <= len(v) <= hi:
        raise ApiError(400, "bad_" + key, f"{label} must be {lo} to {hi} characters." if lo else f"{label} is too long (max {hi}).")
    return v


def as_int(v, label="id"):
    if isinstance(v, bool):
        raise ApiError(400, "bad_" + label, f"Invalid {label}.")
    try:
        return int(v)
    except (TypeError, ValueError):
        raise ApiError(400, "bad_" + label, f"Invalid {label}.")


EMAIL_RX = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")


def norm_email(v):
    """Emails are compared in lower case, so Ada@Mail.com and ada@mail.com are the same account."""
    e = v.strip().lower() if isinstance(v, str) else ""
    if len(e) > 254 or not EMAIL_RX.match(e) or ".." in e or e.startswith(".") or "@." in e:
        raise ApiError(400, "bad_email", "Enter a valid email address.")
    return e


def hash_pw(password, salt):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


class Limiter:
    """Tiny in-memory sliding window limiter."""

    def __init__(self):
        self.h, self.lock = {}, threading.Lock()

    def _prune(self, key, window):
        t = time.time()
        q = [x for x in self.h.get(key, []) if t - x < window]
        self.h[key] = q
        return q

    def count(self, key, window):
        with self.lock:
            return len(self._prune(key, window))

    def hit(self, key, limit, window):
        """Record an event. Returns False if the limit was already reached."""
        with self.lock:
            q = self._prune(key, window)
            if len(q) >= limit:
                return False
            q.append(time.time())
            return True

    def clear(self, key=None):
        with self.lock:
            self.h.clear() if key is None else self.h.pop(key, None)


LIMITER = Limiter()


def rate_limit(key, limit, window, what="requests"):
    if not LIMITER.hit(key, limit, window):
        raise ApiError(429, "rate_limited", f"Too many {what}. Please wait a bit and try again.")


# ----------------------------------------------------------------------------
# Secrets, signed media URLs
# ----------------------------------------------------------------------------
_secret = None


def secret():
    global _secret
    if _secret is None:
        path = db.data_dir() / "secret.key"
        if path.exists():
            _secret = path.read_bytes()
        else:
            _secret = secrets.token_bytes(32)
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(_secret)
    return _secret


def sign_media(mid, uid, exp):
    sig = hmac.new(secret(), f"{mid}.{uid}.{exp}".encode(), "sha256").hexdigest()[:32]
    return f"{exp}.{uid}.{sig}"


def verify_media_token(mid, token):
    try:
        exp, uid, sig = token.split(".")
        good = hmac.new(secret(), f"{mid}.{uid}.{exp}".encode(), "sha256").hexdigest()[:32]
        return hmac.compare_digest(sig, good) and int(exp) > now()
    except (ValueError, AttributeError):
        return False


# ----------------------------------------------------------------------------
# Realtime hub (Server-Sent Events)
# ----------------------------------------------------------------------------
class Hub:
    def __init__(self):
        self.lock, self.subs = threading.Lock(), {}

    def subscribe(self, uid):
        q = queue.Queue(maxsize=200)
        with self.lock:
            self.subs.setdefault(uid, set()).add(q)
        return q

    def unsubscribe(self, uid, q):
        with self.lock:
            s = self.subs.get(uid)
            if s:
                s.discard(q)
                if not s:
                    self.subs.pop(uid, None)

    def publish(self, uid, event):
        with self.lock:
            targets = list(self.subs.get(uid, ()))
        for q in targets:
            try:
                q.put_nowait(event)
            except queue.Full:
                pass


HUB = Hub()
TICKETS = {}          # one-time SSE tickets: ticket -> (user_id, expires)

# ----------------------------------------------------------------------------
# Routing
# ----------------------------------------------------------------------------
ROUTES = []


def route(method, pattern, auth=True):
    rx = re.compile("^" + re.sub(r":(\w+)", r"(?P<\1>[^/]+)", pattern) + "$")

    def deco(fn):
        ROUTES.append((method, rx, auth, fn))
        return fn

    return deco


class Ctx:
    def __init__(self, handler, con, params, query):
        self.h, self.con, self.p, self.q = handler, con, params, query
        self.user = None
        self.token_hash = None
        self._json = None

    def json(self):
        if self._json is None:
            raw = self.h.read_body(MAX_JSON)
            try:
                self._json = json.loads(raw.decode("utf-8") or "{}")
            except (ValueError, UnicodeDecodeError):
                raise ApiError(400, "bad_json", "Request body must be valid JSON.")
            if not isinstance(self._json, dict):
                raise ApiError(400, "bad_json", "Request body must be a JSON object.")
        return self._json

    @property
    def uid(self):
        return self.user["id"]

    def pid(self, name="id"):
        try:
            return int(self.p[name])
        except ValueError:
            raise ApiError(404, "not_found", "Not found.")


# ----------------------------------------------------------------------------
# JSON shapes
# ----------------------------------------------------------------------------
def user_json(u):
    return {"id": u["id"], "name": u["name"], "email": u["email"], "created_at": u["created_at"]}


def media_json(con, media_id, viewer):
    if media_id is None:
        return None
    m = con.execute("SELECT * FROM media WHERE id=?", (media_id,)).fetchone()
    if not m:
        return None
    exp = now() + 3600
    return {"id": m["id"], "kind": m["kind"], "mime": m["mime"], "size": m["size"], "duration": m["duration"],
            "url": f"/api/media/{m['id']}?t={sign_media(m['id'], viewer, exp)}"}


def message_json(con, m, viewer):
    sender = con.execute("SELECT name FROM users WHERE id=?", (m["sender_id"],)).fetchone() if m["sender_id"] else None
    return {"id": m["id"], "chat_id": m["conversation_id"], "sender_id": m["sender_id"],
            "sender_name": sender["name"] if sender else "Deleted user", "kind": m["kind"], "body": m["body"],
            "media": media_json(con, m["media_id"], viewer), "created_at": m["created_at"]}


def is_contact(con, a, b):
    return con.execute("SELECT 1 FROM contacts WHERE user_id=? AND contact_id=?", (a, b)).fetchone() is not None


# ----------------------------------------------------------------------------
# Auth
# ----------------------------------------------------------------------------
def new_session(con, uid):
    token = secrets.token_urlsafe(32)
    t = now()
    con.execute("INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",
                (sha(token), uid, t, t + SESSION_TTL))
    return token


def authenticate(con, header):
    if not header or not header.startswith("Bearer "):
        return None, None
    th = sha(header[7:].strip())
    row = con.execute("SELECT u.*, s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?",
                      (th,)).fetchone()
    if not row or row["expires_at"] < now():
        return None, None
    return row, th


@route("GET", "/api/health", auth=False)
def health(c):
    return {"ok": True, "time": now()}


@route("POST", "/api/auth/signup", auth=False)
def signup(c):
    rate_limit("signup:" + c.h.client_address[0], 10, 3600, "sign-ups")
    d = c.json()
    name = text_field(d, "name", 1, 40, "Name")
    email = norm_email(d.get("email"))
    pw = d.get("password")
    if not isinstance(pw, str) or not 6 <= len(pw) <= 200:
        raise ApiError(400, "bad_password", "Password must be at least 6 characters.")
    salt = os.urandom(16)
    h = hash_pw(pw, salt)
    try:
        with db.tx(c.con):
            cur = c.con.execute("INSERT INTO users(name,email,pw_salt,pw_hash,created_at) VALUES(?,?,?,?,?)",
                                (name, email, salt, h, now()))
            uid = cur.lastrowid
            token = new_session(c.con, uid)
    except sqlite3.IntegrityError:
        raise ApiError(409, "email_taken", "An account with this email already exists.")
    u = c.con.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return 201, {"token": token, "user": user_json(u)}


@route("POST", "/api/auth/login", auth=False)
def login(c):
    d = c.json()
    email = norm_email(d.get("email"))
    pw = d.get("password")
    if not isinstance(pw, str):
        raise ApiError(400, "bad_password", "Enter your password.")
    keys = ("login-email:" + email, "login-ip:" + c.h.client_address[0])
    if LIMITER.count(keys[0], 600) >= 5 or LIMITER.count(keys[1], 600) >= 30:
        raise ApiError(429, "rate_limited", "Too many failed attempts. Try again in a few minutes.")
    u = c.con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    # Always do the expensive hash so timing does not reveal which numbers exist.
    h = hash_pw(pw, u["pw_salt"] if u else b"\0" * 16)
    if not u or not hmac.compare_digest(h, u["pw_hash"]):
        LIMITER.hit(keys[0], 10 ** 6, 600)
        LIMITER.hit(keys[1], 10 ** 6, 600)
        raise ApiError(401, "bad_credentials", "Wrong email or password.")
    LIMITER.clear(keys[0])
    token = new_session(c.con, u["id"])
    return {"token": token, "user": user_json(u)}


@route("POST", "/api/auth/logout")
def logout(c):
    c.con.execute("DELETE FROM sessions WHERE token_hash=?", (c.token_hash,))
    return {"ok": True}


@route("GET", "/api/me")
def me(c):
    return {"user": user_json(c.user)}


@route("PATCH", "/api/me")
def update_me(c):
    d = c.json()
    name = text_field(d, "name", 1, 40, "Name") if "name" in d else c.user["name"]
    email = norm_email(d["email"]) if "email" in d else c.user["email"]
    try:
        c.con.execute("UPDATE users SET name=?, email=? WHERE id=?", (name, email, c.uid))
    except sqlite3.IntegrityError:
        raise ApiError(409, "email_taken", "That email belongs to another account.")
    return {"user": user_json(c.con.execute("SELECT * FROM users WHERE id=?", (c.uid,)).fetchone())}


@route("POST", "/api/me/password")
def change_password(c):
    d = c.json()
    cur, new = d.get("current"), d.get("new")
    if not isinstance(cur, str) or not isinstance(new, str):
        raise ApiError(400, "bad_password", "Current and new password are required.")
    if not 6 <= len(new) <= 200:
        raise ApiError(400, "bad_password", "New password must be at least 6 characters.")
    rate_limit(f"pw:{c.uid}", 10, 600, "attempts")
    if not hmac.compare_digest(hash_pw(cur, c.user["pw_salt"]), c.user["pw_hash"]):
        raise ApiError(403, "wrong_password", "Current password is wrong.")
    salt = os.urandom(16)
    with db.tx(c.con):
        c.con.execute("UPDATE users SET pw_salt=?, pw_hash=? WHERE id=?", (salt, hash_pw(new, salt), c.uid))
        c.con.execute("DELETE FROM sessions WHERE user_id=? AND token_hash<>?", (c.uid, c.token_hash))  # log out other devices
    return {"ok": True}


@route("DELETE", "/api/me")
def delete_me(c):
    d = c.json()
    pw = d.get("password")
    if not isinstance(pw, str) or not hmac.compare_digest(hash_pw(pw, c.user["pw_salt"]), c.user["pw_hash"]):
        raise ApiError(403, "wrong_password", "Password is wrong.")
    files = [r["file"] for r in c.con.execute("SELECT file FROM media WHERE owner_id=?", (c.uid,))]
    with db.tx(c.con):
        c.con.execute("DELETE FROM users WHERE id=?", (c.uid,))
    for f in files:
        unlink_media_file(f)
    return {"ok": True}


# ----------------------------------------------------------------------------
# Contacts
# ----------------------------------------------------------------------------
@route("GET", "/api/users/lookup")
def lookup(c):
    rate_limit(f"lookup:{c.uid}", 30, 60, "lookups")
    email = norm_email(c.q.get("email", ""))
    u = c.con.execute("SELECT id,name,email FROM users WHERE email=?", (email,)).fetchone()
    if not u:
        raise ApiError(404, "not_found", "Nobody on Eloris uses that email.")
    return {"user": {"id": u["id"], "name": u["name"]}}


@route("GET", "/api/contacts")
def contacts(c):
    rows = c.con.execute("SELECT u.id,u.name,u.email FROM contacts k JOIN users u ON u.id=k.contact_id "
                         "WHERE k.user_id=? ORDER BY u.name COLLATE NOCASE", (c.uid,)).fetchall()
    return {"contacts": [dict(r) for r in rows]}


@route("POST", "/api/contacts")
def add_contact(c):
    rate_limit(f"addc:{c.uid}", 60, 3600, "contact additions")
    email = norm_email(c.json().get("email"))
    u = c.con.execute("SELECT id,name,email FROM users WHERE email=?", (email,)).fetchone()
    if not u:
        raise ApiError(404, "not_found", "Nobody on Eloris uses that email.")
    if u["id"] == c.uid:
        raise ApiError(400, "self", "You cannot add yourself.")
    t = now()
    with db.tx(c.con):
        c.con.execute("INSERT OR IGNORE INTO contacts(user_id,contact_id,created_at) VALUES(?,?,?)", (c.uid, u["id"], t))
        c.con.execute("INSERT OR IGNORE INTO contacts(user_id,contact_id,created_at) VALUES(?,?,?)", (u["id"], c.uid, t))
    return 201, {"contact": dict(u)}


def remove_contact(con, a, b):
    con.execute("DELETE FROM contacts WHERE (user_id=? AND contact_id=?) OR (user_id=? AND contact_id=?)", (a, b, b, a))


@route("DELETE", "/api/contacts/:id")
def delete_contact(c):
    other = c.pid()
    with db.tx(c.con):
        remove_contact(c.con, c.uid, other)
        hide_direct_chat(c.con, c.uid, other)
    return {"ok": True}


# ----------------------------------------------------------------------------
# Conversations and messages
# ----------------------------------------------------------------------------
def direct_key(a, b):
    return f"{min(a, b)}:{max(a, b)}"


def get_direct(con, a, b, create=True):
    row = con.execute("SELECT * FROM conversations WHERE direct_key=?", (direct_key(a, b),)).fetchone()
    if row or not create:
        return row
    t = now()
    cur = con.execute("INSERT INTO conversations(kind,direct_key,created_by,created_at) VALUES('direct',?,?,?)",
                      (direct_key(a, b), a, t))
    for u in (a, b):
        con.execute("INSERT INTO members(conversation_id,user_id,joined_at) VALUES(?,?,?)", (cur.lastrowid, u, t))
    return con.execute("SELECT * FROM conversations WHERE id=?", (cur.lastrowid,)).fetchone()


def get_saved(con, uid):
    key = f"saved:{uid}"
    row = con.execute("SELECT * FROM conversations WHERE direct_key=?", (key,)).fetchone()
    if row:
        return row
    t = now()
    cur = con.execute("INSERT INTO conversations(kind,title,direct_key,created_by,created_at) VALUES('saved','Saved Messages',?,?,?)",
                      (key, uid, t))
    con.execute("INSERT INTO members(conversation_id,user_id,joined_at) VALUES(?,?,?)", (cur.lastrowid, uid, t))
    return con.execute("SELECT * FROM conversations WHERE id=?", (cur.lastrowid,)).fetchone()


def hide_direct_chat(con, a, b):
    conv = get_direct(con, a, b, create=False)
    if conv:
        last = con.execute("SELECT COALESCE(MAX(id),0) FROM messages WHERE conversation_id=?", (conv["id"],)).fetchone()[0]
        con.execute("UPDATE members SET cleared_before=?, last_read=? WHERE conversation_id=? AND user_id=?",
                    (last, last, conv["id"], a))


def membership(con, chat_id, uid):
    row = con.execute("SELECT c.*, m.cleared_before, m.last_read FROM conversations c "
                      "JOIN members m ON m.conversation_id=c.id WHERE c.id=? AND m.user_id=?", (chat_id, uid)).fetchone()
    if not row:
        raise ApiError(404, "not_found", "Chat not found.")
    return row


def member_ids(con, chat_id):
    return [r["user_id"] for r in con.execute("SELECT user_id FROM members WHERE conversation_id=?", (chat_id,))]


def streak_effective(row):
    return 0 if (row["last_day"] and row["last_day"] < yesterday()) or not row["last_day"] else row["count"]


def streak_view(row, me):
    other = row["user_b"] if row["user_a"] == me else row["user_a"]
    t = today()
    mine, theirs = (row["a_day"], row["b_day"]) if row["user_a"] == me else (row["b_day"], row["a_day"])
    day_end = (now() // DAY + 1) * DAY
    return {"user_id": other, "count": streak_effective(row), "best": row["best"],
            "done_today": row["last_day"] == t, "you_sent_today": mine == t, "they_sent_today": theirs == t,
            "deadline": day_end}


def get_streak(con, a, b):
    lo, hi = min(a, b), max(a, b)
    return con.execute("SELECT * FROM streaks WHERE user_a=? AND user_b=?", (lo, hi)).fetchone()


def chat_item(con, conv, me):
    cid = conv["id"]
    last = con.execute("SELECT * FROM messages WHERE conversation_id=? AND id>? ORDER BY id DESC LIMIT 1",
                       (cid, conv["cleared_before"])).fetchone()
    unread = con.execute("SELECT COUNT(*) FROM messages WHERE conversation_id=? AND id>? AND sender_id IS NOT ?",
                         (cid, max(conv["last_read"], conv["cleared_before"]), me)).fetchone()[0]
    item = {"id": cid, "kind": conv["kind"], "title": conv["title"], "unread": unread,
            "last": message_json(con, last, me) if last else None, "created_at": conv["created_at"]}
    if conv["kind"] == "direct":
        o = con.execute("SELECT u.id,u.name FROM members m JOIN users u ON u.id=m.user_id "
                        "WHERE m.conversation_id=? AND m.user_id<>?", (cid, me)).fetchone()
        item["user_id"] = o["id"] if o else None
        item["title"] = o["name"] if o else "Deleted user"
        item["is_contact"] = bool(o) and is_contact(con, me, o["id"])
        sr = get_streak(con, me, o["id"]) if o else None
        item["streak"] = streak_view(sr, me) if sr and streak_effective(sr) > 0 else None
        if not item["is_contact"] and not last:
            return None
    elif conv["kind"] == "group":
        item["members"] = len(member_ids(con, cid))
    return item


@route("GET", "/api/chats")
def list_chats(c):
    with db.tx(c.con):
        get_saved(c.con, c.uid)
    rows = c.con.execute("SELECT c.*, m.cleared_before, m.last_read FROM conversations c "
                         "JOIN members m ON m.conversation_id=c.id WHERE m.user_id=?", (c.uid,)).fetchall()
    items = [i for i in (chat_item(c.con, r, c.uid) for r in rows) if i]
    items.sort(key=lambda i: (i["last"]["id"] if i["last"] else 0, i["id"]), reverse=True)
    return {"chats": items}


@route("POST", "/api/chats")
def create_chat(c):
    d = c.json()
    if d.get("user_id") is not None:                              # open (or create) a direct chat
        other = as_int(d["user_id"], "user_id")
        if other == c.uid or not is_contact(c.con, c.uid, other):
            raise ApiError(403, "not_contacts", "You can only chat with your contacts.")
        with db.tx(c.con):
            conv = get_direct(c.con, c.uid, other)
        return 201, {"chat": chat_item(c.con, membership(c.con, conv["id"], c.uid), c.uid)}
    title = text_field(d, "title", 1, 60, "Group name")
    ids = d.get("member_ids")
    if not isinstance(ids, list) or not 1 <= len(ids) <= 255:
        raise ApiError(400, "bad_members", "Pick between 1 and 255 contacts for the group.")
    ids = {as_int(i, "member_id") for i in ids}
    for i in ids:
        if i == c.uid or not is_contact(c.con, c.uid, i):
            raise ApiError(403, "not_contacts", "Everyone in the group must be one of your contacts.")
    t = now()
    with db.tx(c.con):
        cur = c.con.execute("INSERT INTO conversations(kind,title,created_by,created_at) VALUES('group',?,?,?)", (title, c.uid, t))
        for u in ids | {c.uid}:
            c.con.execute("INSERT INTO members(conversation_id,user_id,joined_at) VALUES(?,?,?)", (cur.lastrowid, u, t))
    item = chat_item(c.con, membership(c.con, cur.lastrowid, c.uid), c.uid)
    for u in ids:
        HUB.publish(u, {"type": "chat", "chat_id": cur.lastrowid})
    return 201, {"chat": item}


@route("GET", "/api/chats/:id")
def get_chat(c):
    conv = membership(c.con, c.pid(), c.uid)
    item = chat_item(c.con, conv, c.uid)
    if conv["kind"] == "group":
        item["member_list"] = [dict(r) for r in c.con.execute(
            "SELECT u.id,u.name FROM members m JOIN users u ON u.id=m.user_id WHERE m.conversation_id=? ORDER BY u.name",
            (conv["id"],))]
    return {"chat": item}


@route("GET", "/api/chats/:id/messages")
def get_messages(c):
    conv = membership(c.con, c.pid(), c.uid)
    limit = min(max(env_int_q(c.q, "limit", 50), 1), 100)
    before = c.q.get("before")
    lo = conv["cleared_before"]
    if before:
        rows = c.con.execute("SELECT * FROM messages WHERE conversation_id=? AND id>? AND id<? ORDER BY id DESC LIMIT ?",
                             (conv["id"], lo, as_int(before, "before"), limit + 1)).fetchall()
    else:
        rows = c.con.execute("SELECT * FROM messages WHERE conversation_id=? AND id>? ORDER BY id DESC LIMIT ?",
                             (conv["id"], lo, limit + 1)).fetchall()
    more = len(rows) > limit
    rows = list(reversed(rows[:limit]))
    return {"messages": [message_json(c.con, r, c.uid) for r in rows], "has_more": more}


def env_int_q(q, key, default):
    try:
        return int(q.get(key, default))
    except ValueError:
        return default


def insert_message(con, conv, sender, kind, body, media_id=None):
    cur = con.execute("INSERT INTO messages(conversation_id,sender_id,kind,body,media_id,created_at) VALUES(?,?,?,?,?,?)",
                      (conv["id"], sender, kind, body, media_id, now()))
    return con.execute("SELECT * FROM messages WHERE id=?", (cur.lastrowid,)).fetchone()


def broadcast_message(con, conv_id, msg):
    for u in member_ids(con, conv_id):
        HUB.publish(u, {"type": "message", "chat_id": conv_id, "message": message_json(con, msg, u)})


def require_can_send(con, conv, me):
    if conv["kind"] == "direct":
        o = [u for u in member_ids(con, conv["id"]) if u != me]
        if not o or not is_contact(con, me, o[0]) or not is_contact(con, o[0], me):
            raise ApiError(403, "not_contacts", "You are no longer contacts with this person.")


@route("POST", "/api/chats/:id/messages")
def send_message(c):
    rate_limit(f"msg:{c.uid}", 120, 60, "messages")
    conv = membership(c.con, c.pid(), c.uid)
    body = text_field(c.json(), "body", 1, 4000, "Message", multiline=True)
    require_can_send(c.con, conv, c.uid)
    with db.tx(c.con):
        msg = insert_message(c.con, conv, c.uid, "text", body)
        c.con.execute("UPDATE members SET last_read=? WHERE conversation_id=? AND user_id=?", (msg["id"], conv["id"], c.uid))
    broadcast_message(c.con, conv["id"], msg)
    return 201, {"message": message_json(c.con, msg, c.uid)}


@route("POST", "/api/chats/:id/read")
def mark_read(c):
    conv = membership(c.con, c.pid(), c.uid)
    last = c.con.execute("SELECT COALESCE(MAX(id),0) FROM messages WHERE conversation_id=?", (conv["id"],)).fetchone()[0]
    c.con.execute("UPDATE members SET last_read=? WHERE conversation_id=? AND user_id=?", (last, conv["id"], c.uid))
    return {"ok": True}


@route("DELETE", "/api/chats/:id")
def delete_chat(c):
    """?mode=chat  -> delete the messages for me only (the contact stays)
       ?mode=contact -> delete the contact too (direct chats)
       ?mode=leave -> leave the group"""
    conv = membership(c.con, c.pid(), c.uid)
    mode = c.q.get("mode", "chat")
    cid = conv["id"]
    with db.tx(c.con):
        if mode == "chat":
            last = c.con.execute("SELECT COALESCE(MAX(id),0) FROM messages WHERE conversation_id=?", (cid,)).fetchone()[0]
            c.con.execute("UPDATE members SET cleared_before=?, last_read=? WHERE conversation_id=? AND user_id=?",
                          (last, last, cid, c.uid))
        elif mode == "contact" and conv["kind"] == "direct":
            other = [u for u in member_ids(c.con, cid) if u != c.uid]
            if other:
                remove_contact(c.con, c.uid, other[0])
            last = c.con.execute("SELECT COALESCE(MAX(id),0) FROM messages WHERE conversation_id=?", (cid,)).fetchone()[0]
            c.con.execute("UPDATE members SET cleared_before=?, last_read=? WHERE conversation_id=? AND user_id=?",
                          (last, last, cid, c.uid))
        elif mode == "leave" and conv["kind"] == "group":
            c.con.execute("DELETE FROM members WHERE conversation_id=? AND user_id=?", (cid, c.uid))
            if not member_ids(c.con, cid):
                c.con.execute("DELETE FROM conversations WHERE id=?", (cid,))
        else:
            raise ApiError(400, "bad_mode", "That option is not available for this chat.")
    return {"ok": True}


# ----------------------------------------------------------------------------
# Media upload / download
# ----------------------------------------------------------------------------
MIME_EXT = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif",
            "video/mp4": "mp4", "video/webm": "webm", "video/quicktime": "mov"}


def sniff_ok(head, mime):
    if mime == "image/jpeg":
        return head[:3] == b"\xff\xd8\xff"
    if mime == "image/png":
        return head[:8] == b"\x89PNG\r\n\x1a\n"
    if mime == "image/gif":
        return head[:6] in (b"GIF87a", b"GIF89a")
    if mime == "image/webp":
        return head[:4] == b"RIFF" and head[8:12] == b"WEBP"
    if mime in ("video/mp4", "video/quicktime"):
        return head[4:8] == b"ftyp"
    if mime == "video/webm":
        return head[:4] == b"\x1a\x45\xdf\xa3"
    return False


def unlink_media_file(name):
    try:
        (db.media_dir() / pathlib.Path(name).name).unlink()
    except OSError:
        pass


@route("POST", "/api/media")
def upload_media(c):
    """Raw body upload. Send the file bytes with Content-Type: image/jpeg (etc.).
    Videos must also send X-Duration (seconds, max 300)."""
    rate_limit(f"upload:{c.uid}", 60, 3600, "uploads")
    mime = (c.h.headers.get("Content-Type") or "").split(";")[0].strip().lower()
    if mime not in MIME_EXT:
        raise ApiError(415, "bad_type", "Unsupported file type. Use JPEG, PNG, WebP, GIF, MP4, WebM or MOV.")
    kind = "image" if mime.startswith("image/") else "video"
    limit = env_int("ELORIS_MAX_IMAGE_MB", 15) * 1048576 if kind == "image" else env_int("ELORIS_MAX_VIDEO_MB", 200) * 1048576
    duration = None
    if kind == "video":
        try:
            duration = int(float(c.h.headers.get("X-Duration", "")))
        except ValueError:
            raise ApiError(400, "duration_required", "Send the video length in seconds in the X-Duration header.")
        if duration < 1:
            raise ApiError(400, "bad_duration", "Invalid video length.")
        if duration > MAX_VIDEO_SECONDS:
            raise ApiError(413, "video_too_long", "Short videos can be at most 5 minutes.")
    try:
        length = int(c.h.headers.get("Content-Length", ""))
    except ValueError:
        raise ApiError(411, "length_required", "Content-Length is required.")
    if length <= 0:
        raise ApiError(400, "empty", "The file is empty.")
    if length > limit:
        c.h.close_connection = True
        raise ApiError(413, "too_large", f"File too large (max {limit // 1048576} MB).")
    name = secrets.token_hex(16) + "." + MIME_EXT[mime]
    path = db.media_dir() / name
    remaining, first = length, True
    try:
        with open(path, "wb") as f:
            while remaining:
                chunk = c.h.rfile.read(min(65536, remaining))
                if not chunk:
                    raise ApiError(400, "short_body", "Upload was cut off.")
                if first:
                    if len(chunk) < 12 or not sniff_ok(chunk[:16], mime):
                        raise ApiError(415, "bad_content", "The file content does not match its type.")
                    first = False
                f.write(chunk)
                remaining -= len(chunk)
        c.h._body_consumed = True
        cur = c.con.execute("INSERT INTO media(owner_id,kind,mime,size,duration,file,created_at) VALUES(?,?,?,?,?,?,?)",
                            (c.uid, kind, mime, length, duration, name, now()))
    except BaseException:
        c.h.close_connection = True
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return 201, {"media": media_json(c.con, cur.lastrowid, c.uid)}


def can_view_media(con, mid, uid):
    return con.execute(
        "SELECT 1 FROM media m WHERE m.id=? AND (m.owner_id=? "
        "OR EXISTS(SELECT 1 FROM messages x JOIN members mem ON mem.conversation_id=x.conversation_id AND mem.user_id=? WHERE x.media_id=m.id) "
        "OR EXISTS(SELECT 1 FROM posts p WHERE p.media_id=m.id AND p.expires_at>? AND (p.kind='glide' OR p.author_id=? "
        "OR EXISTS(SELECT 1 FROM contacts k WHERE k.user_id=p.author_id AND k.contact_id=?))))",
        (mid, uid, uid, now(), uid, uid)).fetchone() is not None


@route("GET", "/api/media/:id", auth=False)
def get_media(c):
    mid = c.pid()
    token = c.q.get("t")
    if token:
        if not verify_media_token(mid, token):
            raise ApiError(403, "bad_token", "This link has expired.")
    else:
        user, _ = authenticate(c.con, c.h.headers.get("Authorization"))
        if not user:
            raise ApiError(401, "auth_required", "Please log in.")
        if not can_view_media(c.con, mid, user["id"]):
            raise ApiError(404, "not_found", "Not found.")
    m = c.con.execute("SELECT * FROM media WHERE id=?", (mid,)).fetchone()
    path = db.media_dir() / pathlib.Path(m["file"]).name if m else None
    if not m or not path.exists():
        raise ApiError(404, "not_found", "Not found.")
    c.h.send_file(path, m["mime"], extra={"Cache-Control": "private, max-age=3600", "Content-Disposition": "inline"})
    return None


# ----------------------------------------------------------------------------
# Eloments (contacts only) and Glides (everyone)
# ----------------------------------------------------------------------------
POST_SQL = (
    "SELECT p.*, u.name AS author_name, "
    "(SELECT COUNT(*) FROM post_likes WHERE post_id=p.id) AS likes, "
    "(SELECT COUNT(*) FROM post_views WHERE post_id=p.id) AS views, "
    "EXISTS(SELECT 1 FROM post_likes WHERE post_id=p.id AND user_id=:me) AS liked "
    "FROM posts p JOIN users u ON u.id=p.author_id "
)
VISIBLE = ("p.expires_at>:now AND (p.kind='glide' OR p.author_id=:me OR "
           "EXISTS(SELECT 1 FROM contacts k WHERE k.user_id=p.author_id AND k.contact_id=:me))")


def post_json(con, p, me):
    return {"id": p["id"], "kind": p["kind"], "author": {"id": p["author_id"], "name": p["author_name"]},
            "mine": p["author_id"] == me, "body": p["body"], "media": media_json(con, p["media_id"], me),
            "created_at": p["created_at"], "expires_at": p["expires_at"],
            "likes": p["likes"], "liked": bool(p["liked"]), "views": p["views"]}


def visible_post(con, pid, me):
    p = con.execute(POST_SQL + f"WHERE p.id=:id AND {VISIBLE}", {"me": me, "now": now(), "id": pid}).fetchone()
    if not p:
        raise ApiError(404, "not_found", "That post is gone.")
    return p


@route("GET", "/api/posts")
def list_posts(c):
    kind = c.q.get("kind", "glide")
    if kind not in ("eloment", "glide"):
        raise ApiError(400, "bad_kind", "kind must be eloment or glide.")
    limit = min(max(env_int_q(c.q, "limit", 50), 1), 100)
    before = c.q.get("before")
    sql = POST_SQL + f"WHERE p.kind=:kind AND {VISIBLE} " + ("AND p.id<:before " if before else "") + "ORDER BY p.id DESC LIMIT :limit"
    args = {"me": c.uid, "now": now(), "kind": kind, "limit": limit}
    if before:
        args["before"] = as_int(before, "before")
    return {"posts": [post_json(c.con, p, c.uid) for p in c.con.execute(sql, args)]}


@route("POST", "/api/posts")
def create_post(c):
    rate_limit(f"post:{c.uid}", 60, 3600, "posts")
    d = c.json()
    kind = d.get("kind")
    if kind not in ("eloment", "glide"):
        raise ApiError(400, "bad_kind", "kind must be eloment or glide.")
    body = text_field({"b": d.get("body", "")}, "b", 0, 280, "Post", multiline=True) if isinstance(d.get("body", ""), str) else ""
    media_id = d.get("media_id")
    if media_id is not None:
        media_id = as_int(media_id, "media_id")
        m = c.con.execute("SELECT 1 FROM media WHERE id=? AND owner_id=?", (media_id, c.uid)).fetchone()
        if not m:
            raise ApiError(400, "bad_media", "That upload was not found.")
    if not body and media_id is None:
        raise ApiError(400, "empty", "Write something or attach a photo or video.")
    t = now()
    with db.tx(c.con):
        cur = c.con.execute("INSERT INTO posts(author_id,kind,body,media_id,created_at,expires_at) VALUES(?,?,?,?,?,?)",
                            (c.uid, kind, body, media_id, t, t + POST_TTL))
    return 201, {"post": post_json(c.con, visible_post(c.con, cur.lastrowid, c.uid), c.uid)}


@route("POST", "/api/posts/:id/like")
def like_post(c):
    p = visible_post(c.con, c.pid(), c.uid)
    with db.tx(c.con):
        cur = c.con.execute("DELETE FROM post_likes WHERE post_id=? AND user_id=?", (p["id"], c.uid))
        if cur.rowcount == 0:
            c.con.execute("INSERT INTO post_likes(post_id,user_id) VALUES(?,?)", (p["id"], c.uid))
    n = c.con.execute("SELECT COUNT(*) FROM post_likes WHERE post_id=?", (p["id"],)).fetchone()[0]
    liked = c.con.execute("SELECT 1 FROM post_likes WHERE post_id=? AND user_id=?", (p["id"], c.uid)).fetchone() is not None
    return {"liked": liked, "likes": n}


@route("POST", "/api/posts/:id/view")
def view_post(c):
    p = visible_post(c.con, c.pid(), c.uid)
    c.con.execute("INSERT OR IGNORE INTO post_views(post_id,user_id) VALUES(?,?)", (p["id"], c.uid))
    return {"views": c.con.execute("SELECT COUNT(*) FROM post_views WHERE post_id=?", (p["id"],)).fetchone()[0]}


@route("DELETE", "/api/posts/:id")
def delete_post(c):
    pid = c.pid()
    cur = c.con.execute("DELETE FROM posts WHERE id=? AND author_id=?", (pid, c.uid))
    if cur.rowcount == 0:
        raise ApiError(404, "not_found", "Not found.")
    return {"ok": True}


# ----------------------------------------------------------------------------
# Snaps and streaks
# ----------------------------------------------------------------------------
def apply_snap(con, sender, recipient):
    lo, hi = min(sender, recipient), max(sender, recipient)
    con.execute("INSERT OR IGNORE INTO streaks(user_a,user_b) VALUES(?,?)", (lo, hi))
    r = con.execute("SELECT * FROM streaks WHERE user_a=? AND user_b=?", (lo, hi)).fetchone()
    t, y = today(), yesterday()
    count, best, last, a_day, b_day = r["count"], r["best"], r["last_day"], r["a_day"], r["b_day"]
    if last and last < y:            # missed a whole day: streak is lost
        count, last = 0, ""
    if sender == lo:
        a_day = t
    else:
        b_day = t
    if a_day == t and b_day == t and last != t:
        count = count + 1 if (last == y and count > 0) else 1
        last, best = t, max(best, count)
    con.execute("UPDATE streaks SET count=?,best=?,last_day=?,a_day=?,b_day=? WHERE user_a=? AND user_b=?",
                (count, best, last, a_day, b_day, lo, hi))


@route("POST", "/api/snaps")
def send_snap(c):
    """Send a pic to a contact. Keeps the streak alive when both of you send one on the same day."""
    rate_limit(f"snap:{c.uid}", 200, 3600, "pics")
    d = c.json()
    to = as_int(d.get("to_user_id"), "to_user_id")
    mid = as_int(d.get("media_id"), "media_id")
    if to == c.uid or not is_contact(c.con, c.uid, to) or not is_contact(c.con, to, c.uid):
        raise ApiError(403, "not_contacts", "You can only send pics to your contacts.")
    m = c.con.execute("SELECT kind FROM media WHERE id=? AND owner_id=?", (mid, c.uid)).fetchone()
    if not m or m["kind"] != "image":
        raise ApiError(400, "bad_media", "Upload a photo first, then send it.")
    with db.tx(c.con):
        conv = get_direct(c.con, c.uid, to)
        msg = insert_message(c.con, conv, c.uid, "snap", "Snap", mid)
        apply_snap(c.con, c.uid, to)
    broadcast_message(c.con, conv["id"], msg)
    sr = get_streak(c.con, c.uid, to)
    for u in (c.uid, to):
        HUB.publish(u, {"type": "streak", "streak": streak_view(sr, u)})
    return 201, {"message": message_json(c.con, msg, c.uid), "streak": streak_view(sr, c.uid)}


@route("GET", "/api/streaks")
def list_streaks(c):
    rows = c.con.execute("SELECT * FROM streaks WHERE user_a=? OR user_b=?", (c.uid, c.uid)).fetchall()
    out = []
    for r in rows:
        v = streak_view(r, c.uid)
        if v["count"] > 0 and is_contact(c.con, c.uid, v["user_id"]):
            name = c.con.execute("SELECT name FROM users WHERE id=?", (v["user_id"],)).fetchone()
            v["name"] = name["name"] if name else "Deleted user"
            out.append(v)
    out.sort(key=lambda v: (-v["count"], v["name"].lower()))
    return {"streaks": out}


# ----------------------------------------------------------------------------
# Realtime events (Server-Sent Events)
# ----------------------------------------------------------------------------
@route("POST", "/api/events/ticket")
def events_ticket(c):
    t = now()
    for k in [k for k, v in TICKETS.items() if v[1] < t]:
        TICKETS.pop(k, None)
    ticket = secrets.token_urlsafe(24)
    TICKETS[ticket] = (c.uid, t + 60)
    return {"ticket": ticket}


@route("GET", "/api/events", auth=False)
def events(c):
    entry = TICKETS.pop(c.q.get("ticket", ""), None)
    if not entry or entry[1] < now():
        raise ApiError(401, "bad_ticket", "Ask for a new ticket with POST /api/events/ticket.")
    uid = entry[0]
    c.con.close()                       # do not hold a database connection while streaming
    h = c.h
    h.send_response(200)
    h.send_header("Content-Type", "text/event-stream")
    h.send_header("Cache-Control", "no-cache")
    h.send_header("X-Accel-Buffering", "no")
    h.cors()
    h.end_headers()
    h.close_connection = True
    q = HUB.subscribe(uid)
    try:
        h.wfile.write(b": connected\n\n")
        h.wfile.flush()
        while not h.server.stopping:
            try:
                ev = q.get(timeout=15)
                h.wfile.write(f"event: {ev['type']}\ndata: {json.dumps(ev, ensure_ascii=False)}\n\n".encode("utf-8"))
            except queue.Empty:
                h.wfile.write(b": ping\n\n")
            h.wfile.flush()
    except OSError:
        pass
    finally:
        HUB.unsubscribe(uid, q)
    return None


# ----------------------------------------------------------------------------
# Background cleanup: expired posts, sessions, old snaps, orphaned files
# ----------------------------------------------------------------------------
def cleanup():
    con = db.connect()
    try:
        t = now()
        with db.tx(con):
            con.execute("DELETE FROM sessions WHERE expires_at<?", (t,))
            con.execute("DELETE FROM posts WHERE expires_at<=?", (t,))
            con.execute("UPDATE messages SET media_id=NULL WHERE kind='snap' AND media_id IS NOT NULL AND created_at<?", (t - DAY,))
            rows = con.execute("SELECT id,file FROM media WHERE created_at<? "
                               "AND id NOT IN (SELECT media_id FROM posts WHERE media_id IS NOT NULL) "
                               "AND id NOT IN (SELECT media_id FROM messages WHERE media_id IS NOT NULL)", (t - 3600,)).fetchall()
            con.executemany("DELETE FROM media WHERE id=?", [(r["id"],) for r in rows])
        for r in rows:
            unlink_media_file(r["file"])
        return len(rows)
    finally:
        con.close()


def cleanup_loop(server):
    while not server.stopping:
        try:
            cleanup()
        except Exception:                                   # never let the janitor die
            traceback.print_exc()
        for _ in range(60):
            if server.stopping:
                return
            time.sleep(1)


# ----------------------------------------------------------------------------
# HTTP layer
# ----------------------------------------------------------------------------
def public_dir():
    return pathlib.Path(os.environ.get("ELORIS_PUBLIC") or db.HERE / "public").resolve()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Eloris"
    sys_version = ""

    def log_message(self, fmt, *args):
        if not QUIET:
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # ---- helpers ----
    def cors(self):
        allowed = os.environ.get("ELORIS_CORS", "*")
        origin = self.headers.get("Origin")
        if allowed == "*":
            self.send_header("Access-Control-Allow-Origin", "*")
        elif origin and origin in [x.strip() for x in allowed.split(",")]:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Duration")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Expose-Headers", "Content-Range, Accept-Ranges")

    def send_json(self, status, data):
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.cors()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def read_body(self, limit):
        n = self.headers.get("Content-Length")
        if n is None:
            if self.headers.get("Transfer-Encoding"):
                raise ApiError(411, "length_required", "Content-Length is required.")
            return b""
        try:
            n = int(n)
        except ValueError:
            raise ApiError(400, "bad_length", "Bad Content-Length.")
        if n < 0 or n > limit:
            self.close_connection = True
            raise ApiError(413, "too_large", "Request body is too large.")
        chunks, remaining = [], n
        while remaining:
            chunk = self.rfile.read(min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        self._body_consumed = True
        return b"".join(chunks)

    def send_file(self, path, mime, extra=None):
        size = path.stat().st_size
        start, end, status = 0, size - 1, 200
        rng = self.headers.get("Range")
        if rng:
            m = re.fullmatch(r"bytes=(\d*)-(\d*)", rng.strip())
            if not m or (not m.group(1) and not m.group(2)):
                raise ApiError(416, "bad_range", "Bad Range header.")
            if m.group(1):
                start = int(m.group(1))
                end = min(int(m.group(2)), size - 1) if m.group(2) else size - 1
            else:
                start = max(size - int(m.group(2)), 0)
            if start > end or start >= size:
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{size}")
                self.send_header("Content-Length", "0")
                self.cors()
                self.end_headers()
                return
            status = 206
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(end - start + 1))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("X-Content-Type-Options", "nosniff")
        if status == 206:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.cors()
        self.end_headers()
        if self.command == "HEAD":
            return
        try:
            with open(path, "rb") as f:
                f.seek(start)
                left = end - start + 1
                while left:
                    buf = f.read(min(65536, left))
                    if not buf:
                        break
                    self.wfile.write(buf)
                    left -= len(buf)
        except OSError:
            self.close_connection = True

    # ---- dispatch ----
    def do_OPTIONS(self):
        self.send_response(204)
        self.cors()
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self.dispatch()

    def do_HEAD(self):
        self.dispatch()

    def do_POST(self):
        self.dispatch()

    def do_PATCH(self):
        self.dispatch()

    def do_DELETE(self):
        self.dispatch()

    def do_PUT(self):
        self.dispatch()

    def dispatch(self):
        self._body_consumed = False
        parts = urlsplit(self.path)
        path = unquote(parts.path)
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        try:
            if not path.startswith("/api/"):
                return self.serve_static(path)
            method = "GET" if self.command == "HEAD" else self.command
            matched_path = False
            for m, rx, auth, fn in ROUTES:
                mt = rx.match(path)
                if not mt:
                    continue
                matched_path = True
                if m != method:
                    continue
                con = db.connect()
                try:
                    ctx = Ctx(self, con, mt.groupdict(), query)
                    ctx.user, ctx.token_hash = authenticate(con, self.headers.get("Authorization"))
                    if auth and not ctx.user:
                        raise ApiError(401, "auth_required", "Please log in.")
                    result = fn(ctx)
                finally:
                    con.close()
                if result is not None:
                    status, data = result if isinstance(result, tuple) else (200, result)
                    self.send_json(status, data)
                break
            else:
                if matched_path:
                    raise ApiError(405, "method_not_allowed", "Method not allowed.")
                raise ApiError(404, "not_found", "Not found.")
        except ApiError as e:
            self.send_json(e.status, {"error": {"code": e.code, "message": e.message}})
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True
        except Exception:
            traceback.print_exc()
            try:
                self.send_json(500, {"error": {"code": "server_error", "message": "Something went wrong on our side."}})
            except OSError:
                pass
        finally:
            if not self._body_consumed and int(self.headers.get("Content-Length") or 0) > 0:
                self.close_connection = True      # unread body would corrupt the next keep-alive request

    def serve_static(self, path):
        if self.command not in ("GET", "HEAD"):
            raise ApiError(405, "method_not_allowed", "Method not allowed.")
        root = public_dir()
        rel = path.lstrip("/") or "index.html"
        target = (root / rel).resolve()
        if root not in target.parents and target != root:
            raise ApiError(404, "not_found", "Not found.")
        if target.is_dir():
            target = target / "index.html"
        if not target.is_file() or any(p.startswith(".") for p in target.relative_to(root).parts):
            raise ApiError(404, "not_found", "Not found.")
        mime = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if mime.startswith("text/") or mime in ("application/javascript", "application/json"):
            mime += "; charset=utf-8"
        self.send_file(target, mime, extra={"Cache-Control": "no-cache"})


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.stopping = False


def make_server(host="127.0.0.1", port=8000):
    db.init()
    return Server((host, port), Handler)


def main():
    global QUIET
    ap = argparse.ArgumentParser(description="Eloris backend")
    ap.add_argument("--host", default=os.environ.get("ELORIS_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=env_int("ELORIS_PORT", 8000))
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()
    QUIET = args.quiet
    srv = make_server(args.host, args.port)
    threading.Thread(target=cleanup_loop, args=(srv,), daemon=True).start()
    print(f"Eloris backend running at http://{args.host}:{args.port}  (data: {db.data_dir()})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        srv.stopping = True
        srv.server_close()


if __name__ == "__main__":
    main()