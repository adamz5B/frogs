"""One-off script used to build api/orders.db's schema + seed data.

Not referenced by frogs itself at runtime — kept here purely so the
database can be regenerated later if it's ever deleted, rather than as
part of the example's request-serving path.
"""

import os
import sqlite3
from datetime import datetime, timedelta, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "api", "orders.db")

if os.path.exists(DB_PATH):
    os.remove(DB_PATH)

conn = sqlite3.connect(DB_PATH)
conn.executescript(
    """
    CREATE TABLE products (
        sku         TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        category    TEXT NOT NULL,
        price       REAL NOT NULL,
        currency    TEXT NOT NULL,
        description TEXT,
        in_stock    INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE customers (
        id         INTEGER PRIMARY KEY,
        name       TEXT NOT NULL,
        email      TEXT NOT NULL,
        tier       TEXT NOT NULL DEFAULT 'bronze',
        created_at TEXT NOT NULL
    );

    CREATE TABLE orders (
        id              INTEGER PRIMARY KEY,
        customer_id     INTEGER NOT NULL REFERENCES customers(id),
        status          TEXT NOT NULL,
        subtotal        REAL NOT NULL,
        tax             REAL NOT NULL,
        total           REAL NOT NULL,
        currency        TEXT NOT NULL,
        placed_at       TEXT NOT NULL,
        tracking_number TEXT
    );

    CREATE TABLE order_items (
        id          INTEGER PRIMARY KEY,
        order_id    INTEGER NOT NULL REFERENCES orders(id),
        sku         TEXT NOT NULL REFERENCES products(sku),
        name        TEXT NOT NULL,
        quantity    INTEGER NOT NULL,
        unit_price  REAL NOT NULL,
        line_total  REAL NOT NULL
    );

    CREATE TABLE api_keys (
        key    TEXT PRIMARY KEY,
        active BOOLEAN NOT NULL DEFAULT 1
    );
    """
)


def rfc3339(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


now = datetime.now(timezone.utc)

products = [
    ("WIDGET-S", "Small Widget", "widgets", 9.99, "USD", "A small widget.", 1),
    ("WIDGET-L", "Large Widget", "widgets", 19.99, "USD", "A large widget.", 1),
    ("GADGET-1", "Gadget Mk1", "gadgets", 49.5, "USD", "The original gadget.", 1),
    ("GADGET-2", "Gadget Mk2", "gadgets", 79.0, "USD", "The improved gadget.", 1),
    ("GIZMO-X", "Gizmo X", "gizmos", 129.99, "USD", "A premium gizmo.", 0),
]
conn.executemany(
    "INSERT INTO products (sku, name, category, price, currency, description, in_stock) VALUES (?, ?, ?, ?, ?, ?, ?)",
    products,
)

customers = [
    ("Alice Nguyen", "alice@example.com", "gold", rfc3339(now - timedelta(days=400))),
    ("Ben Carter", "ben@example.com", "silver", rfc3339(now - timedelta(days=200))),
    ("Chloe Dubois", "chloe@example.com", "bronze", rfc3339(now - timedelta(days=30))),
]
conn.executemany(
    "INSERT INTO customers (name, email, tier, created_at) VALUES (?, ?, ?, ?)",
    customers,
)

orders = [
    # Alice: a delivered order, already shipped with a tracking number.
    (1, "delivered", 39.97, 3.20, 43.17, "USD", rfc3339(now - timedelta(days=10)), "1Z999AA10123456784"),
    # Ben: a pending order — the one worth trying POST /orders/{id}/cancel against.
    (2, "pending", 79.0, 6.32, 85.32, "USD", rfc3339(now - timedelta(hours=2)), None),
    # Chloe: an already-shipped order — cancelling this one should 409.
    (3, "shipped", 49.5, 3.96, 53.46, "USD", rfc3339(now - timedelta(days=1)), "1Z999AA10987654321"),
]
conn.executemany(
    "INSERT INTO orders (customer_id, status, subtotal, tax, total, currency, placed_at, tracking_number) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    orders,
)

order_items = [
    (1, "WIDGET-S", "Small Widget", 1, 9.99, 9.99),
    (1, "WIDGET-L", "Large Widget", 1, 19.99, 19.99),
    (1, "WIDGET-S", "Small Widget", 1, 9.99, 9.99),
    (2, "GADGET-2", "Gadget Mk2", 1, 79.0, 79.0),
    (3, "GADGET-1", "Gadget Mk1", 1, 49.5, 49.5),
]
conn.executemany(
    "INSERT INTO order_items (order_id, sku, name, quantity, unit_price, line_total) VALUES (?, ?, ?, ?, ?, ?)",
    order_items,
)

conn.execute("INSERT INTO api_keys (key, active) VALUES (?, ?)", ("orders-demo-key", 1))
conn.execute("INSERT INTO api_keys (key, active) VALUES (?, ?)", ("revoked-key", 0))

conn.commit()
conn.close()
print(f"built {DB_PATH}")
