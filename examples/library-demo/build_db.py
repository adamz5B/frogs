"""One-off script used to build api/library.db's schema + seed data.

Not referenced by frogs itself at runtime — kept here purely so the
database can be regenerated later if it's ever deleted, rather than as
part of the example's request-serving path.
"""

import os
import sqlite3
from datetime import datetime, timedelta, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "api", "library.db")

if os.path.exists(DB_PATH):
    os.remove(DB_PATH)

conn = sqlite3.connect(DB_PATH)
conn.executescript(
    """
    CREATE TABLE books (
        id INTEGER PRIMARY KEY,
        title TEXT NOT NULL,
        author TEXT NOT NULL,
        isbn TEXT NOT NULL,
        deleted INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE members (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        deleted INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE rentals (
        id INTEGER PRIMARY KEY,
        book_id INTEGER NOT NULL REFERENCES books(id),
        member_id INTEGER NOT NULL REFERENCES members(id),
        checked_out_at TEXT NOT NULL,
        due_at TEXT NOT NULL,
        returned_at TEXT
    );

    CREATE TABLE settings (
        rental_period_days INTEGER NOT NULL,
        librarian_username TEXT NOT NULL,
        librarian_password TEXT NOT NULL
    );
    """
)

books = [
    ("The Hobbit", "J.R.R. Tolkien", "9780345339683"),
    ("Dune", "Frank Herbert", "9780441172719"),
    ("The Left Hand of Darkness", "Ursula K. Le Guin", "9780441478125"),
    ("Foundation", "Isaac Asimov", "9780553293357"),
    ("A Wizard of Earthsea", "Ursula K. Le Guin", "9780553262505"),
    ("Neuromancer", "William Gibson", "9780441569595"),
]
conn.executemany("INSERT INTO books (title, author, isbn) VALUES (?, ?, ?)", books)

members = [
    ("Alice Nguyen", "alice@example.com"),
    ("Ben Carter", "ben@example.com"),
    ("Chloe Dubois", "chloe@example.com"),
]
conn.executemany("INSERT INTO members (name, email) VALUES (?, ?)", members)


def rfc3339(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


now = datetime.now(timezone.utc)
rental_period_days = 14

rentals = [
    # Dune, checked out by Alice, still out, due in the future.
    (2, 1, rfc3339(now - timedelta(days=3)), rfc3339(now - timedelta(days=3) + timedelta(days=rental_period_days)), None),
    # Foundation, checked out and returned by Ben — rental history.
    (
        4,
        2,
        rfc3339(now - timedelta(days=20)),
        rfc3339(now - timedelta(days=20) + timedelta(days=rental_period_days)),
        rfc3339(now - timedelta(days=15)),
    ),
]
conn.executemany(
    "INSERT INTO rentals (book_id, member_id, checked_out_at, due_at, returned_at) VALUES (?, ?, ?, ?, ?)",
    rentals,
)

conn.execute(
    "INSERT INTO settings (rental_period_days, librarian_username, librarian_password) VALUES (?, ?, ?)",
    (rental_period_days, "librarian", "changeme123"),
)

conn.commit()
conn.close()
print(f"built {DB_PATH}")
