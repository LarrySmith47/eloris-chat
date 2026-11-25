-- Eloris database schema, version 1.
-- Times are unix seconds (UTC). Passwords are never stored, only a salted scrypt hash.

CREATE TABLE users (
  id          INTEGER PRIMARY KEY,
  name        TEXT    NOT NULL,
  phone       TEXT    NOT NULL UNIQUE,          -- normalised, e.g. +2348012345678
  pw_salt     BLOB    NOT NULL,
  pw_hash     BLOB    NOT NULL,
  created_at  INTEGER NOT NULL
);

-- Only a SHA-256 of the session token is stored, so a leaked database cannot be used to log in.
CREATE TABLE sessions (
  token_hash  TEXT    PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);

-- Contacts are mutual: adding someone inserts two rows.
CREATE TABLE contacts (
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  contact_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (user_id, contact_id),
  CHECK (user_id <> contact_id)
);

CREATE TABLE media (
  id          INTEGER PRIMARY KEY,
  owner_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind        TEXT    NOT NULL CHECK (kind IN ('image','video')),
  mime        TEXT    NOT NULL,
  size        INTEGER NOT NULL,
  duration    INTEGER,                           -- seconds, videos only
  file        TEXT    NOT NULL,                  -- file name inside data/media/
  created_at  INTEGER NOT NULL
);
CREATE INDEX media_owner ON media(owner_id);

-- direct = one to one, group = many, saved = notes to self.
CREATE TABLE conversations (
  id          INTEGER PRIMARY KEY,
  kind        TEXT    NOT NULL CHECK (kind IN ('direct','group','saved')),
  title       TEXT,
  direct_key  TEXT    UNIQUE,                    -- "minId:maxId" or "saved:id", prevents duplicates
  created_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
  created_at  INTEGER NOT NULL
);

CREATE TABLE members (
  conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  joined_at       INTEGER NOT NULL,
  cleared_before  INTEGER NOT NULL DEFAULT 0,    -- "delete chat" hides messages up to this id for this user only
  last_read       INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (conversation_id, user_id)
);
CREATE INDEX members_user ON members(user_id);

CREATE TABLE messages (
  id              INTEGER PRIMARY KEY,
  conversation_id INTEGER NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  sender_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,
  kind            TEXT    NOT NULL DEFAULT 'text' CHECK (kind IN ('text','snap')),
  body            TEXT    NOT NULL DEFAULT '',
  media_id        INTEGER REFERENCES media(id) ON DELETE SET NULL,
  created_at      INTEGER NOT NULL
);
CREATE INDEX messages_conv ON messages(conversation_id, id);

-- Eloments (contacts only) and Glides (everyone). Both vanish 24 hours after posting.
CREATE TABLE posts (
  id          INTEGER PRIMARY KEY,
  author_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind        TEXT    NOT NULL CHECK (kind IN ('eloment','glide')),
  body        TEXT    NOT NULL DEFAULT '',
  media_id    INTEGER REFERENCES media(id) ON DELETE SET NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX posts_feed    ON posts(kind, id DESC);
CREATE INDEX posts_expires ON posts(expires_at);

CREATE TABLE post_likes (
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (post_id, user_id)
);
CREATE TABLE post_views (
  post_id INTEGER NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (post_id, user_id)
);

-- Snapchat style streaks. One row per pair, user_a < user_b.
-- a_day / b_day = the (UTC) day each side last sent a pic. When both equal today the streak goes up.
CREATE TABLE streaks (
  user_a   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  user_b   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  count    INTEGER NOT NULL DEFAULT 0,
  best     INTEGER NOT NULL DEFAULT 0,
  last_day TEXT    NOT NULL DEFAULT '',
  a_day    TEXT    NOT NULL DEFAULT '',
  b_day    TEXT    NOT NULL DEFAULT '',
  PRIMARY KEY (user_a, user_b),
  CHECK (user_a < user_b)
);
