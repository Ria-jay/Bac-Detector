"""
In-memory data and auth for the demo app.

All tokens are static strings — no JWT signing needed for testing.
Every "secret" here is intentional and public; this app exists solely
to demonstrate broken access control patterns.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

USERS: dict[str, dict] = {
    "1": {
        "id": "1",
        "name": "Alice",
        "email": "alice@example.com",
        "role": "user",
        "ssn": "123-45-6789",         # sensitive field — should not leak cross-user
        "balance": 1000.00,
    },
    "2": {
        "id": "2",
        "name": "Bob",
        "email": "bob@example.com",
        "role": "user",
        "ssn": "987-65-4321",
        "balance": 500.00,
    },
    "3": {
        "id": "3",
        "name": "Admin",
        "email": "admin@example.com",
        "role": "admin",
        "ssn": "000-00-0000",
        "balance": 0.00,
    },
}

# ---------------------------------------------------------------------------
# Static bearer tokens  →  user id
# ---------------------------------------------------------------------------

TOKEN_MAP: dict[str, str] = {
    "token-alice": "1",
    "token-bob":   "2",
    "token-admin": "3",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def get_user_by_token(token: str) -> dict | None:
    """Return the user record for a bearer token, or None if invalid."""
    uid = TOKEN_MAP.get(token)
    if uid is None:
        return None
    return USERS.get(uid)


def is_admin(user: dict) -> bool:
    return user.get("role") == "admin"
