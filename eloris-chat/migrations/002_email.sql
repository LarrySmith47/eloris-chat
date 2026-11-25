-- Version 2: accounts use an email address instead of a phone number.
-- SQLite cannot swap a column in place, so the users table is rebuilt (db.py turns foreign keys off for this step).
CREATE TABLE users_new (
  id          INTEGER PRIMARY KEY,
  name        TEXT    NOT NULL,
  email       TEXT    NOT NULL UNIQUE COLLATE NOCASE,   -- stored in lower case
  pw_salt     BLOB    NOT NULL,
  pw_hash     BLOB    NOT NULL,
  created_at  INTEGER NOT NULL
);
-- Accounts created with a phone number before this change have no email. They get an unusable placeholder
-- (it ends in .invalid) and can no longer log in; those people simply sign up again.
INSERT INTO users_new (id, name, email, pw_salt, pw_hash, created_at)
  SELECT id, name, 'user' || id || '@phone-signup.invalid', pw_salt, pw_hash, created_at FROM users;
DROP TABLE users;
ALTER TABLE users_new RENAME TO users;
