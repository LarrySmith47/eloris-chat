"""End to end tests: start a real server on a free port with a temporary database.

Run:  python3 -m unittest discover -s tests -v
"""
import http.client
import json
import os
import pathlib
import shutil
import sys
import tempfile
import threading
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TMP = tempfile.mkdtemp(prefix="eloris-test-")
os.environ["ELORIS_DATA"] = TMP
os.environ["ELORIS_PUBLIC"] = str(ROOT / "public")

import db      # noqa: E402
import server  # noqa: E402

server.QUIET = True
JPEG = b"\xff\xd8\xff\xe0" + b"\x00\x10JFIF\x00" + b"x" * 200
MP4 = b"\x00\x00\x00\x18ftypmp42" + b"y" * 200


class Api:
    def __init__(self, port):
        self.port = port

    def call(self, method, path, body=None, token=None, headers=None, raw=None):
        h = dict(headers or {})
        if token:
            h["Authorization"] = "Bearer " + token
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(method, path, body=data, headers=h)
        r = conn.getresponse()
        payload = r.read()
        conn.close()
        try:
            parsed = json.loads(payload) if payload else None
        except ValueError:
            parsed = payload
        return r.status, parsed, r


class Base(unittest.TestCase):
    n = 0          # shared counter for unique phone numbers
    skew = 0       # fake clock offset in seconds

    @classmethod
    def setUpClass(cls):
        cls.srv = server.make_server("127.0.0.1", 0)
        cls.api = Api(cls.srv.server_address[1])
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.stopping = True
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        server.LIMITER.clear()
        server.now = lambda: int(time.time()) + getattr(Base, "skew", 0)
        Base.skew = 0

    def user(self, name="User"):
        Base.n += 1
        email = f"user{Base.n}@example.com"
        st, d, _ = self.api.call("POST", "/api/auth/signup", {"name": f"{name}{Base.n}", "email": email, "password": "secret1"})
        self.assertEqual(st, 201, d)
        return {"token": d["token"], "id": d["user"]["id"], "email": email, "name": d["user"]["name"]}

    def friends(self, a, b):
        st, d, _ = self.api.call("POST", "/api/contacts", {"email": b["email"]}, a["token"])
        self.assertEqual(st, 201, d)

    def upload(self, u, data=JPEG, mime="image/jpeg", extra=None):
        h = {"Content-Type": mime}
        h.update(extra or {})
        return self.api.call("POST", "/api/media", token=u["token"], headers=h, raw=data)


class AuthTests(Base):
    def test_signup_login_me_logout(self):
        st, d, _ = self.api.call("POST", "/api/auth/signup", {"name": "Ada Obi", "email": "  Ada.Obi@Example.COM ", "password": "secret1"})
        self.assertEqual(st, 201)
        self.assertEqual(d["user"]["email"], "ada.obi@example.com")        # trimmed and lower-cased
        self.assertNotIn("password", json.dumps(d))
        st, d2, _ = self.api.call("POST", "/api/auth/signup", {"name": "Dup", "email": "ADA.OBI@example.com", "password": "secret1"})
        self.assertEqual((st, d2["error"]["code"]), (409, "email_taken"))   # same email in a different case
        st, d3, _ = self.api.call("POST", "/api/auth/login", {"email": "Ada.Obi@example.com", "password": "secret1"})
        self.assertEqual(st, 200)
        tok = d3["token"]
        self.assertEqual(self.api.call("GET", "/api/me", token=tok)[1]["user"]["name"], "Ada Obi")
        self.assertEqual(self.api.call("POST", "/api/auth/logout", token=tok)[0], 200)
        self.assertEqual(self.api.call("GET", "/api/me", token=tok)[0], 401)

    def test_validation(self):
        c = self.api.call
        self.assertEqual(c("POST", "/api/auth/signup", {"name": "", "email": "a@example.com", "password": "secret1"})[0], 400)
        self.assertEqual(c("POST", "/api/auth/signup", {"name": "A", "email": "abc", "password": "secret1"})[0], 400)
        for bad in ("a@b", "@example.com", "a b@example.com", "a@@example.com", "a..b@example.com", "x" * 300 + "@example.com"):
            self.assertEqual(c("POST", "/api/auth/signup", {"name": "A", "email": bad, "password": "secret1"})[0], 400, bad)
        self.assertEqual(c("POST", "/api/auth/signup", {"name": "A", "email": "a@example.com", "password": "123"})[0], 400)
        self.assertEqual(c("POST", "/api/auth/signup", raw=b"not json", headers={"Content-Type": "application/json"})[0], 400)
        self.assertEqual(c("GET", "/api/me")[0], 401)
        self.assertEqual(c("GET", "/api/me", token="garbage")[0], 401)

    def test_wrong_password_and_lockout(self):
        u = self.user()
        for _ in range(5):
            self.assertEqual(self.api.call("POST", "/api/auth/login", {"email": u["email"], "password": "nope123"})[0], 401)
        st, d, _ = self.api.call("POST", "/api/auth/login", {"email": u["email"], "password": "secret1"})
        self.assertEqual((st, d["error"]["code"]), (429, "rate_limited"))     # locked even for the right password

    def test_password_change_logs_out_other_devices(self):
        u = self.user()
        _, d, _ = self.api.call("POST", "/api/auth/login", {"email": u["email"], "password": "secret1"})
        other = d["token"]
        self.assertEqual(self.api.call("POST", "/api/me/password", {"current": "wrong", "new": "newpass1"}, u["token"])[0], 403)
        self.assertEqual(self.api.call("POST", "/api/me/password", {"current": "secret1", "new": "newpass1"}, u["token"])[0], 200)
        self.assertEqual(self.api.call("GET", "/api/me", token=other)[0], 401)
        self.assertEqual(self.api.call("GET", "/api/me", token=u["token"])[0], 200)
        self.assertEqual(self.api.call("POST", "/api/auth/login", {"email": u["email"], "password": "newpass1"})[0], 200)

    def test_update_profile(self):
        a, b = self.user(), self.user()
        st, d, _ = self.api.call("PATCH", "/api/me", {"name": "New Name"}, a["token"])
        self.assertEqual(d["user"]["name"], "New Name")
        st, d, _ = self.api.call("PATCH", "/api/me", {"email": b["email"]}, a["token"])
        self.assertEqual(st, 409)

    def test_delete_account(self):
        a, b = self.user(), self.user()
        self.friends(a, b)
        st, m, _ = self.upload(a)
        files_before = len(list(db.media_dir().iterdir()))
        self.assertEqual(self.api.call("DELETE", "/api/me", {"password": "wrong"}, a["token"])[0], 403)
        self.assertEqual(self.api.call("DELETE", "/api/me", {"password": "secret1"}, a["token"])[0], 200)
        self.assertEqual(self.api.call("GET", "/api/me", token=a["token"])[0], 401)
        self.assertEqual(len(list(db.media_dir().iterdir())), files_before - 1)
        self.assertEqual(self.api.call("GET", "/api/contacts", token=b["token"])[1]["contacts"], [])


class ContactChatTests(Base):
    def test_contacts_are_mutual(self):
        a, b = self.user(), self.user()
        self.assertEqual(self.api.call("GET", f"/api/users/lookup?email={b['email'].upper()}", token=a["token"])[1]["user"]["id"], b["id"])
        self.assertEqual(self.api.call("POST", "/api/contacts", {"email": a["email"]}, a["token"])[0], 400)
        self.assertEqual(self.api.call("POST", "/api/contacts", {"email": "nobody@example.com"}, a["token"])[0], 404)
        self.friends(a, b)
        self.assertEqual([c["id"] for c in self.api.call("GET", "/api/contacts", token=b["token"])[1]["contacts"]], [a["id"]])

    def test_direct_messaging_and_unread(self):
        a, b, stranger = self.user(), self.user(), self.user()
        self.assertEqual(self.api.call("POST", "/api/chats", {"user_id": b["id"]}, a["token"])[0], 403)   # not contacts yet
        self.friends(a, b)
        st, d, _ = self.api.call("POST", "/api/chats", {"user_id": b["id"]}, a["token"])
        chat = d["chat"]["id"]
        self.assertEqual(self.api.call("POST", "/api/chats", {"user_id": a["id"]}, b["token"])[1]["chat"]["id"], chat)  # same chat from the other side
        self.assertEqual(self.api.call("POST", f"/api/chats/{chat}/messages", {"body": "  hello b  "}, a["token"])[0], 201)
        self.api.call("POST", f"/api/chats/{chat}/messages", {"body": "second"}, a["token"])
        chats = self.api.call("GET", "/api/chats", token=b["token"])[1]["chats"]
        mine = [c for c in chats if c["id"] == chat][0]
        self.assertEqual((mine["unread"], mine["title"], mine["last"]["body"]), (2, a["name"], "second"))
        self.assertEqual(self.api.call("POST", f"/api/chats/{chat}/read", token=b["token"])[0], 200)
        self.assertEqual([c for c in self.api.call("GET", "/api/chats", token=b["token"])[1]["chats"] if c["id"] == chat][0]["unread"], 0)
        msgs = self.api.call("GET", f"/api/chats/{chat}/messages", token=b["token"])[1]
        self.assertEqual([m["body"] for m in msgs["messages"]], ["hello b", "second"])
        self.assertEqual(self.api.call("GET", f"/api/chats/{chat}/messages", token=stranger["token"])[0], 404)   # no peeking
        self.assertEqual(self.api.call("POST", f"/api/chats/{chat}/messages", {"body": "x"}, stranger["token"])[0], 404)
        self.assertEqual(self.api.call("POST", f"/api/chats/{chat}/messages", {"body": "   "}, a["token"])[0], 400)

    def test_message_paging(self):
        a, b = self.user(), self.user()
        self.friends(a, b)
        chat = self.api.call("POST", "/api/chats", {"user_id": b["id"]}, a["token"])[1]["chat"]["id"]
        for i in range(7):
            self.api.call("POST", f"/api/chats/{chat}/messages", {"body": f"m{i}"}, a["token"])
        d = self.api.call("GET", f"/api/chats/{chat}/messages?limit=3", token=a["token"])[1]
        self.assertEqual(([m["body"] for m in d["messages"]], d["has_more"]), (["m4", "m5", "m6"], True))
        d = self.api.call("GET", f"/api/chats/{chat}/messages?limit=3&before={d['messages'][0]['id']}", token=a["token"])[1]
        self.assertEqual([m["body"] for m in d["messages"]], ["m1", "m2", "m3"])

    def test_delete_chat_vs_delete_contact(self):
        a, b = self.user(), self.user()
        self.friends(a, b)
        chat = self.api.call("POST", "/api/chats", {"user_id": b["id"]}, a["token"])[1]["chat"]["id"]
        self.api.call("POST", f"/api/chats/{chat}/messages", {"body": "hi"}, a["token"])
        # delete chat: messages vanish for A only, contact stays
        self.assertEqual(self.api.call("DELETE", f"/api/chats/{chat}?mode=chat", token=a["token"])[0], 200)
        self.assertEqual(self.api.call("GET", f"/api/chats/{chat}/messages", token=a["token"])[1]["messages"], [])
        self.assertEqual(len(self.api.call("GET", f"/api/chats/{chat}/messages", token=b["token"])[1]["messages"]), 1)
        self.assertIn(b["id"], [c["id"] for c in self.api.call("GET", "/api/contacts", token=a["token"])[1]["contacts"]])
        self.assertEqual(self.api.call("POST", f"/api/chats/{chat}/messages", {"body": "again"}, a["token"])[0], 201)
        # delete contact: gone for both, chat hidden for A, B cannot message A any more
        self.assertEqual(self.api.call("DELETE", f"/api/chats/{chat}?mode=contact", token=a["token"])[0], 200)
        self.assertEqual(self.api.call("GET", "/api/contacts", token=a["token"])[1]["contacts"], [])
        self.assertEqual(self.api.call("GET", "/api/contacts", token=b["token"])[1]["contacts"], [])
        self.assertNotIn(chat, [c["id"] for c in self.api.call("GET", "/api/chats", token=a["token"])[1]["chats"]])
        self.assertEqual(self.api.call("POST", f"/api/chats/{chat}/messages", {"body": "?"}, b["token"])[0], 403)

    def test_groups(self):
        a, b, c, outsider = self.user(), self.user(), self.user(), self.user()
        self.friends(a, b)
        self.friends(a, c)
        self.assertEqual(self.api.call("POST", "/api/chats", {"title": "Crew", "member_ids": [b["id"], outsider["id"]]}, a["token"])[0], 403)
        st, d, _ = self.api.call("POST", "/api/chats", {"title": "Crew", "member_ids": [b["id"], c["id"]]}, a["token"])
        self.assertEqual((st, d["chat"]["members"]), (201, 3))
        g = d["chat"]["id"]
        self.assertEqual(self.api.call("POST", f"/api/chats/{g}/messages", {"body": "welcome"}, b["token"])[0], 201)
        self.assertEqual(self.api.call("GET", f"/api/chats/{g}/messages", token=c["token"])[1]["messages"][0]["body"], "welcome")
        self.assertEqual(self.api.call("DELETE", f"/api/chats/{g}?mode=leave", token=c["token"])[0], 200)
        self.assertEqual(self.api.call("GET", f"/api/chats/{g}/messages", token=c["token"])[0], 404)
        self.assertEqual(self.api.call("DELETE", f"/api/chats/{g}?mode=contact", token=a["token"])[0], 400)

    def test_saved_messages(self):
        a = self.user()
        chats = self.api.call("GET", "/api/chats", token=a["token"])[1]["chats"]
        saved = [c for c in chats if c["kind"] == "saved"]
        self.assertEqual(len(saved), 1)
        self.assertEqual(self.api.call("POST", f"/api/chats/{saved[0]['id']}/messages", {"body": "note to self"}, a["token"])[0], 201)

    def test_realtime_events(self):
        a, b = self.user(), self.user()
        self.friends(a, b)
        chat = self.api.call("POST", "/api/chats", {"user_id": b["id"]}, a["token"])[1]["chat"]["id"]
        ticket = self.api.call("POST", "/api/events/ticket", token=b["token"])[1]["ticket"]
        conn = http.client.HTTPConnection("127.0.0.1", self.api.port, timeout=10)
        conn.request("GET", f"/api/events?ticket={ticket}")
        r = conn.getresponse()
        self.assertEqual((r.status, r.getheader("Content-Type")), (200, "text/event-stream"))
        self.assertTrue(r.fp.readline().startswith(b": connected"))
        r.fp.readline()
        time.sleep(0.2)
        self.api.call("POST", f"/api/chats/{chat}/messages", {"body": "live!"}, a["token"])
        lines = [r.fp.readline().decode() for _ in range(2)]
        self.assertEqual(lines[0].strip(), "event: message")
        self.assertEqual(json.loads(lines[1][6:])["message"]["body"], "live!")
        conn.close()
        self.assertEqual(self.api.call("GET", f"/api/events?ticket={ticket}")[0], 401)   # tickets are single use


class PostTests(Base):
    def test_eloments_contacts_only_glides_everyone(self):
        a, b, c = self.user(), self.user(), self.user()
        self.friends(a, b)
        ea = self.api.call("POST", "/api/posts", {"kind": "eloment", "body": "private moment"}, a["token"])[1]["post"]
        ga = self.api.call("POST", "/api/posts", {"kind": "glide", "body": "hello world"}, a["token"])[1]["post"]
        ids = lambda u, k: [p["id"] for p in self.api.call("GET", f"/api/posts?kind={k}", token=u["token"])[1]["posts"]]
        self.assertIn(ea["id"], ids(a, "eloment"))
        self.assertIn(ea["id"], ids(b, "eloment"))               # contact sees it
        self.assertNotIn(ea["id"], ids(c, "eloment"))            # stranger does not
        self.assertIn(ga["id"], ids(c, "glide"))                 # everyone sees glides
        self.assertEqual(self.api.call("POST", f"/api/posts/{ea['id']}/like", token=c["token"])[0], 404)
        self.assertEqual(self.api.call("POST", "/api/posts", {"kind": "glide"}, a["token"])[0], 400)
        self.assertEqual(self.api.call("POST", "/api/posts", {"kind": "nope", "body": "x"}, a["token"])[0], 400)
        self.assertEqual(self.api.call("POST", "/api/posts", {"kind": "glide", "body": "x" * 281}, a["token"])[0], 400)

    def test_likes_views_delete(self):
        a, b = self.user(), self.user()
        p = self.api.call("POST", "/api/posts", {"kind": "glide", "body": "like me"}, a["token"])[1]["post"]
        self.assertEqual(self.api.call("POST", f"/api/posts/{p['id']}/like", token=b["token"])[1], {"liked": True, "likes": 1})
        self.assertEqual(self.api.call("POST", f"/api/posts/{p['id']}/like", token=b["token"])[1], {"liked": False, "likes": 0})
        self.api.call("POST", f"/api/posts/{p['id']}/view", token=b["token"])
        self.assertEqual(self.api.call("POST", f"/api/posts/{p['id']}/view", token=b["token"])[1]["views"], 1)   # unique per viewer
        self.assertEqual(self.api.call("DELETE", f"/api/posts/{p['id']}", token=b["token"])[0], 404)
        self.assertEqual(self.api.call("DELETE", f"/api/posts/{p['id']}", token=a["token"])[0], 200)

    def test_posts_expire_after_24_hours(self):
        a = self.user()
        st, m, _ = self.upload(a)
        p = self.api.call("POST", "/api/posts", {"kind": "glide", "body": "short lived", "media_id": m["media"]["id"]}, a["token"])[1]["post"]
        self.assertEqual(p["expires_at"] - p["created_at"], 86400)
        Base.skew = 86400 - 60
        self.assertIn(p["id"], [x["id"] for x in self.api.call("GET", "/api/posts?kind=glide", token=a["token"])[1]["posts"]])
        Base.skew = 86400 + 5
        self.assertNotIn(p["id"], [x["id"] for x in self.api.call("GET", "/api/posts?kind=glide", token=a["token"])[1]["posts"]])
        # the janitor deletes the row and the (now unreferenced) media file
        con = db.connect()
        con.execute("UPDATE media SET created_at=created_at-7200 WHERE id=?", (m["media"]["id"],))   # old enough for orphan cleanup
        name = con.execute("SELECT file FROM media WHERE id=?", (m["media"]["id"],)).fetchone()["file"]
        con.close()
        self.assertTrue((db.media_dir() / name).exists())
        server.cleanup()
        self.assertFalse((db.media_dir() / name).exists())
        con = db.connect()
        self.assertIsNone(con.execute("SELECT 1 FROM posts WHERE id=?", (p["id"],)).fetchone())
        self.assertIsNone(con.execute("SELECT 1 FROM media WHERE id=?", (m["media"]["id"],)).fetchone())
        con.close()

    def test_media_post_visibility(self):
        a, b, c = self.user(), self.user(), self.user()
        self.friends(a, b)
        mid = self.upload(a)[1]["media"]["id"]
        self.api.call("POST", "/api/posts", {"kind": "eloment", "body": "pic", "media_id": mid}, a["token"])
        self.assertEqual(self.api.call("GET", f"/api/media/{mid}", token=b["token"])[0], 200)    # contact can load it
        self.assertEqual(self.api.call("GET", f"/api/media/{mid}", token=c["token"])[0], 404)    # stranger cannot
        self.assertEqual(self.api.call("GET", f"/api/media/{mid}")[0], 401)


class MediaTests(Base):
    def test_upload_and_signed_url_and_range(self):
        a = self.user()
        st, d, _ = self.upload(a)
        self.assertEqual(st, 201)
        url = d["media"]["url"]
        st, body, r = self.api.call("GET", url)
        self.assertEqual((st, r.getheader("Content-Type")), (200, "image/jpeg"))
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")
        st, part, r = self.api.call("GET", url, headers={"Range": "bytes=0-9"})
        self.assertEqual((st, r.getheader("Content-Range"), len(part)), (206, f"bytes 0-9/{len(JPEG)}", 10))
        self.assertEqual(self.api.call("GET", url[:-3] + "bad")[0], 403)               # tampered signature
        self.assertEqual(self.api.call("GET", url.split("?")[0] + "?t=1.1.abc")[0], 403)

    def test_rejects_bad_uploads(self):
        a = self.user()
        self.assertEqual(self.upload(a, b"hello", "text/html")[0], 415)                          # not an allowed type
        self.assertEqual(self.upload(a, b"<script>alert(1)</script>" * 5, "image/jpeg")[0], 415) # content is not a jpeg
        self.assertEqual(self.upload(a, b"", "image/jpeg")[0], 400)
        self.assertEqual(self.upload(a, MP4, "video/mp4")[0], 400)                               # missing X-Duration
        self.assertEqual(self.upload(a, MP4, "video/mp4", {"X-Duration": "301"})[0], 413)        # over 5 minutes
        self.assertEqual(self.upload(a, MP4, "video/mp4", {"X-Duration": "300"})[0], 201)        # exactly 5 minutes is fine
        os.environ["ELORIS_MAX_IMAGE_MB"] = "0"
        try:
            self.assertEqual(self.upload(a)[0], 413)
        finally:
            del os.environ["ELORIS_MAX_IMAGE_MB"]
        self.assertEqual(len(list(db.media_dir().glob("*.html"))), 0)

    def test_cannot_attach_someone_elses_upload(self):
        a, b = self.user(), self.user()
        mid = self.upload(a)[1]["media"]["id"]
        self.assertEqual(self.api.call("POST", "/api/posts", {"kind": "glide", "body": "x", "media_id": mid}, b["token"])[0], 400)


class StreakTests(Base):
    def snap(self, u, to):
        mid = self.upload(u)[1]["media"]["id"]
        st, d, _ = self.api.call("POST", "/api/snaps", {"to_user_id": to["id"], "media_id": mid}, u["token"])
        self.assertEqual(st, 201, d)
        return d

    def count(self, u):
        s = self.api.call("GET", "/api/streaks", token=u["token"])[1]["streaks"]
        return s[0]["count"] if s else 0

    def test_streak_needs_both_sides_each_day(self):
        a, b = self.user(), self.user()
        self.friends(a, b)
        d = self.snap(a, b)
        self.assertEqual((d["streak"]["count"], d["streak"]["you_sent_today"], d["streak"]["they_sent_today"]), (0, True, False))
        self.assertEqual(self.count(a), 0)                        # only one side so far
        d = self.snap(b, a)
        self.assertEqual((d["streak"]["count"], d["streak"]["done_today"]), (1, True))
        self.snap(a, b)
        self.snap(b, a)
        self.assertEqual(self.count(a), 1)                        # extra pics the same day do not add more
        Base.skew = 86400
        self.snap(a, b)
        self.assertEqual(self.count(a), 1)                        # day 2: waiting for B
        self.snap(b, a)
        self.assertEqual(self.count(a), 2)
        Base.skew = 86400 * 2
        self.snap(a, b)
        self.snap(b, a)
        self.assertEqual((self.count(a), self.count(b)), (3, 3))

    def test_missed_day_loses_streak(self):
        a, b = self.user(), self.user()
        self.friends(a, b)
        self.snap(a, b)
        self.snap(b, a)
        self.assertEqual(self.count(a), 1)
        Base.skew = 86400 * 2                                     # a whole day skipped
        self.assertEqual(self.count(a), 0)
        self.snap(a, b)
        self.snap(b, a)
        self.assertEqual(self.count(a), 1)                        # starts again from 1

    def test_snap_rules_and_chat_message(self):
        a, b, c = self.user(), self.user(), self.user()
        self.friends(a, b)
        mid = self.upload(a)[1]["media"]["id"]
        self.assertEqual(self.api.call("POST", "/api/snaps", {"to_user_id": c["id"], "media_id": mid}, a["token"])[0], 403)
        self.assertEqual(self.api.call("POST", "/api/snaps", {"to_user_id": a["id"], "media_id": mid}, b["token"])[0], 400)
        v = self.upload(a, MP4, "video/mp4", {"X-Duration": "5"})[1]["media"]["id"]
        self.assertEqual(self.api.call("POST", "/api/snaps", {"to_user_id": b["id"], "media_id": v}, a["token"])[0], 400)   # pics only
        self.snap(a, b)
        chat = [x for x in self.api.call("GET", "/api/chats", token=b["token"])[1]["chats"] if x["kind"] == "direct"][0]
        self.assertEqual((chat["last"]["kind"], chat["unread"]), ("snap", 1))
        self.assertEqual(self.api.call("GET", chat["last"]["media"]["url"])[0], 200)             # recipient can open the pic

    def test_snap_streak_event(self):
        a, b = self.user(), self.user()
        self.friends(a, b)
        ticket = self.api.call("POST", "/api/events/ticket", token=b["token"])[1]["ticket"]
        conn = http.client.HTTPConnection("127.0.0.1", self.api.port, timeout=10)
        conn.request("GET", f"/api/events?ticket={ticket}")
        r = conn.getresponse()
        r.fp.readline()
        r.fp.readline()
        time.sleep(0.2)
        self.snap(a, b)
        seen = set()
        for _ in range(8):
            line = r.fp.readline().decode().strip()
            if line.startswith("event:"):
                seen.add(line[7:])
            if {"message", "streak"} <= seen:
                break
        conn.close()
        self.assertEqual(seen, {"message", "streak"})


class HttpTests(Base):
    def test_health_cors_404_405(self):
        self.assertEqual(self.api.call("GET", "/api/health")[1]["ok"], True)
        st, _, r = self.api.call("OPTIONS", "/api/me", headers={"Origin": "null"})
        self.assertEqual((st, r.getheader("Access-Control-Allow-Origin")), (204, "*"))
        self.assertEqual(self.api.call("GET", "/api/nothing")[1]["error"]["code"], "not_found")
        self.assertEqual(self.api.call("PUT", "/api/me")[1]["error"]["code"], "method_not_allowed")
        self.assertEqual(self.api.call("DELETE", "/api/health")[0], 405)

    def test_oversized_json_rejected(self):
        import socket
        s = socket.create_connection(("127.0.0.1", self.api.port), timeout=10)
        s.sendall(b"POST /api/auth/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 5000000\r\n\r\n")
        reply = s.recv(4096)
        s.close()
        self.assertTrue(reply.startswith(b"HTTP/1.1 413"), reply[:60])      # refused from the header alone

    def test_static_files_and_traversal(self):
        (ROOT / "public").mkdir(exist_ok=True)
        idx = ROOT / "public" / "index.html"
        made = not idx.exists()
        if made:
            idx.write_text("<h1>hi</h1>")
        try:
            st, body, r = self.api.call("GET", "/")
            self.assertEqual(st, 200)
            for evil in ("/../server.py", "/..%2fserver.py", "/%2e%2e/server.py", "/../../etc/passwd"):
                self.assertEqual(self.api.call("GET", evil)[0], 404, evil)
        finally:
            if made:
                idx.unlink()

    def test_db_has_no_plaintext_passwords_or_tokens(self):
        u = self.user()
        con = db.connect()
        blob = repr(con.execute("SELECT * FROM users").fetchall() and [tuple(r) for r in con.execute("SELECT * FROM users")]) + \
            repr([tuple(r) for r in con.execute("SELECT * FROM sessions")])
        con.close()
        self.assertNotIn("secret1", blob)
        self.assertNotIn(u["token"], blob)


class MigrationTests(unittest.TestCase):
    def test_phone_database_upgrades_to_email_without_losing_data(self):
        import sqlite3
        old = os.environ["ELORIS_DATA"]
        tmp = tempfile.mkdtemp(prefix="eloris-mig-")
        os.environ["ELORIS_DATA"] = tmp
        try:
            (pathlib.Path(tmp) / "media").mkdir()
            con = sqlite3.connect(str(pathlib.Path(tmp) / "eloris.db"))
            con.executescript((ROOT / "schema.sql").read_text(encoding="utf-8"))      # version 1: phone numbers
            con.execute("PRAGMA user_version=1")
            con.execute("INSERT INTO users VALUES(1,'Old User','+2348012345678',x'00',x'01',100)")
            con.execute("INSERT INTO users VALUES(2,'Friend','+2348099999999',x'00',x'02',100)")
            con.execute("INSERT INTO contacts VALUES(1,2,100),(2,1,100)")
            con.commit()
            con.close()
            db.init()
            con = db.connect()
            self.assertEqual(con.execute("PRAGMA user_version").fetchone()[0], len(db.MIGRATIONS))
            self.assertEqual(con.execute("SELECT email FROM users WHERE id=1").fetchone()[0], "user1@phone-signup.invalid")
            self.assertEqual(con.execute("SELECT COUNT(*) FROM contacts").fetchone()[0], 2)
            self.assertEqual(con.execute("PRAGMA foreign_key_check").fetchall(), [])
            con.execute("DELETE FROM users WHERE id=2")
            self.assertEqual(con.execute("SELECT COUNT(*) FROM contacts").fetchone()[0], 0)   # cascades still work
            con.close()
        finally:
            os.environ["ELORIS_DATA"] = old
            shutil.rmtree(tmp, ignore_errors=True)


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()