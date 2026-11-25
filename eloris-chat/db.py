"""SQLite helpers: connection, migrations, transactions."""
import os
import pathlib
import sqlite3
from contextlib import contextmanager

HERE = pathlib.Path(__file__).resolve().parent


def data_dir():
    """Where the database and uploaded media live. Override with ELORIS_DATA."""
    return pathlib.Path(os.environ.get("ELORIS_DATA") or HERE / "data")


def db_path():
    return data_dir() / "eloris.db"


def media_dir():
    return data_dir() / "media"


# Add new schema changes to the END of this list. Never edit an old entry.
MIGRATIONS = [
    (HERE / "schema.sql").read_text(encoding="utf-8"),
    (HERE / "migrations" / "002_email.sql").read_text(encoding="utf-8"),
]


def connect():
    # isolation_level=None -> autocommit; transactions are explicit via tx().
    con = sqlite3.connect(str(db_path()), timeout=15, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA busy_timeout=15000")
    return con


def check_writable():
    """Fail early with a plain explanation instead of a cryptic error a minute later."""
    problem = None
    try:
        probe = media_dir() / ".write-test"
        probe.write_bytes(b"x")
        probe.unlink()
        if db_path().exists() and not os.access(str(db_path()), os.W_OK):
            raise OSError("the file eloris.db is marked read-only")
        con = connect()
        try:
            version = con.execute("PRAGMA user_version").fetchone()[0]
            con.execute("BEGIN IMMEDIATE")      # a real write, so a read-only database file is caught here
            con.execute(f"PRAGMA user_version={int(version)}")
            con.execute("COMMIT")
        finally:
            con.close()
    except (OSError, sqlite3.OperationalError) as e:
        problem = str(e)
    if problem:
        raise SystemExit(
            "\nEloris cannot write to its data folder:\n  " + str(data_dir()) + "\n(" + problem + ")\n\n"
            "How to fix it:\n"
            "  1. Close DB Browser for SQLite and any other program that has eloris.db open.\n"
            "  2. Make sure the folder is NOT inside OneDrive and is not read-only:\n"
            "       attrib -R \"" + str(data_dir()) + "\" /S /D\n"
            "  3. If it still fails, delete the 'data' folder (it is recreated empty) and start again.\n")


def init():
    try:
        data_dir().mkdir(parents=True, exist_ok=True)
        media_dir().mkdir(parents=True, exist_ok=True)
    except OSError as e:
        if os.environ.get("ELORIS_DATA"):
            raise SystemExit(f"\nEloris cannot create its data folder:\n  {data_dir()}\n({e})\n")
        # The program's own folder is protected (common on Windows). Use a folder in the user's profile instead.
        fallback = pathlib.Path.home() / "eloris-data"
        print(f"Note: Windows does not allow writing to {data_dir()}.\n      Using {fallback} for the database and uploads instead.")
        os.environ["ELORIS_DATA"] = str(fallback)
        data_dir().mkdir(parents=True, exist_ok=True)
        media_dir().mkdir(parents=True, exist_ok=True)
    check_writable()
    con = connect()
    try:
        con.execute("PRAGMA journal_mode=WAL")
        version = con.execute("PRAGMA user_version").fetchone()[0]
        con.execute("PRAGMA foreign_keys=OFF")          # needed to rebuild a table; checked again below
        for number, sql in enumerate(MIGRATIONS, start=1):
            if number > version:
                con.executescript("BEGIN;\n" + sql + f"\nPRAGMA user_version={number};\nCOMMIT;")
        con.execute("PRAGMA foreign_keys=ON")
        broken = con.execute("PRAGMA foreign_key_check").fetchall()
        if broken:
            raise SystemExit("Database check failed after upgrade: " + repr([tuple(r) for r in broken[:3]]))
    finally:
        con.close()


@contextmanager
def tx(con):
    """BEGIN IMMEDIATE ... COMMIT, rolled back if anything raises."""
    con.execute("BEGIN IMMEDIATE")
    try:
        yield con
    except BaseException:
        con.execute("ROLLBACK")
        raise
    else:
        con.execute("COMMIT")