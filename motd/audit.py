"""MOTD — daily SSH behaviour digest for small servers.

Reads auth.log, keeps a small SQLite baseline per account, and prints the day's
findings: impossible travel, new authorized keys, sudo bursts, brute-force bursts.

Run as root (or with read access to auth.log) from a systemd timer.
"""

from __future__ import annotations

import collections
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

AUTH = Path(os.environ.get("MOTD_AUTH", "/var/log/auth.log"))
DB_PATH = Path(os.environ.get("MOTD_DB", "/var/lib/motd/baseline.sqlite"))
FAIL_THRESHOLD = int(os.environ.get("MOTD_FAIL_THRESHOLD", "10"))

FAIL_PW = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
ACCEPT = re.compile(r"Accepted (?:publickey|password) for (\S+) from (\d+\.\d+\.\d+\.\d+).*?(SHA256:\S+)?")
SUDO_FAIL = re.compile(r"sudo.*authentication failure.*user=(\S+)")
NEW_KEY = re.compile(r"Accepted publickey for (\S+).*?(SHA256:\S+)")


def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        create table if not exists keys (
            user text, fp text, accepted_at text,
            primary key (user, fp)
        );
        create table if not exists logins (
            user text, ip text, at text
        );
        create table if not exists digests (day text, lines text);
        """
    )
    return conn


def brute_forces(lines: list[str]) -> list[str]:
    counts = collections.Counter(FAIL_PW.findall("\n".join(lines)))
    return [
        f"brute force: {count} failures for {user} from {ip}"
        for (user, ip), count in counts.most_common(5)
        if count >= FAIL_THRESHOLD
    ]


def new_keys(conn: sqlite3.Connection, lines: list[str]) -> list[str]:
    found = []
    for line in lines:
        match = NEW_KEY.search(line)
        if not match:
            continue
        user, fps = match.group(1), match.group(2)
        fp = fps or "unknown"
        cur = conn.execute(
            "insert or ignore into keys(user, fp, accepted_at) values (?,?,?)",
            (user, fp, datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        if cur.rowcount:
            found.append(f"new key accepted: {user} ({fp[:16]}…)")
    return found


def sudo_bursts(lines: list[str]) -> list[str]:
    stamps: dict[str, list[datetime]] = collections.defaultdict(list)
    now = datetime.now()
    for line in lines:
        match = SUDO_FAIL.search(line)
        if match:
            stamps[match.group(1)].append(now)
    out = []
    for user, hits in stamps.items():
        if len(hits) >= 3:
            out.append(f"sudo burst: {len(hits)} failed sudo attempts by {user}")
    return out


def impossible_travel(conn: sqlite3.Connection, lines: list[str]) -> list[str]:
    """Two accepted logins from different /16s within 30 minutes."""
    recent = conn.execute(
        "select user, ip, at from logins where at > ?",
        ((datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat(),),
    ).fetchall()
    by_user: dict[str, set[str]] = collections.defaultdict(set)
    for user, ip, _at in recent:
        by_user[user].add(".".join(ip.split(".")[:2]))
    out = []
    for user, nets in by_user.items():
        if len(nets) > 1:
            out.append(f"impossible travel: {user} logged in from {sorted(nets)} inside 30m")
    for line in lines:
        match = ACCEPT.search(line)
        if match:
            conn.execute(
                "insert into logins(user, ip, at) values (?,?,?)",
                (match.group(1), match.group(2), datetime.now(timezone.utc).isoformat(timespec="seconds")),
            )
    return out


def run() -> list[str]:
    if not AUTH.exists():
        return [f"auth log not found: {AUTH} (set MOTD_AUTH)"]
    lines = AUTH.read_text(errors="ignore").splitlines()[-5000:]
    conn = db()
    findings = [
        *brute_forces(lines),
        *new_keys(conn, lines),
        *sudo_bursts(lines),
        *impossible_travel(conn, lines),
    ]
    conn.execute(
        "insert into digests(day, lines) values (?,?)",
        (datetime.now().date().isoformat(), "\n".join(findings)),
    )
    conn.commit()
    return findings


def main() -> None:
    findings = run()
    print("\n".join(findings) if findings else "quiet day")


if __name__ == "__main__":
    main()
