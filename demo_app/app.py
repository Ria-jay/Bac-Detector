"""
Intentionally Vulnerable Demo API
==================================
A minimal FastAPI application with deliberate broken access control bugs.
Used exclusively for BAC Detector integration testing.

DO NOT deploy this to any real environment.

Endpoints
---------
GET /health
    Public endpoint. No auth required. Negative control — should NOT be flagged.

GET /users/{user_id}
    BUG: Returns any user's full record to any authenticated identity.
    Intended finding: IDOR (alice can read bob's record including SSN).

GET /me/profile
    BUG: Returns the profile of the user whose ID matches a query param,
    falling back to the caller's own profile. Because both alice and bob call
    this and get their own distinct profiles, the horizontal escalation
    detector flags it as an account-scoped endpoint with different bodies.
    Intended finding: horizontal_escalation (POTENTIAL).

GET /admin/users
    BUG: No role check — any authenticated user can call this and get the
    full user list that is meant for admins only.
    Intended finding: vertical_escalation.

GET /admin/stats
    Same bug as /admin/users — included to give the vertical detector
    a second data point.
"""

from __future__ import annotations

from fastapi import FastAPI, HTTPException, Header
from typing import Optional

from demo_app.data import USERS, get_user_by_token, is_admin

app = FastAPI(
    title="BAC Detector Demo API",
    description="Intentionally vulnerable API for integration testing.",
    version="1.0.0",
)


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------

def _require_auth(authorization: Optional[str]) -> dict:
    """
    Extract and validate a Bearer token from the Authorization header.
    Returns the user dict or raises 401.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = authorization.removeprefix("Bearer ").strip()
    user = get_user_by_token(token)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    """
    Public health check. No auth required.
    NEGATIVE CONTROL — this must NOT appear in BAC findings.
    """
    return {"status": "ok", "service": "bac-demo"}


@app.get("/users/{user_id}")
def get_user(
    user_id: str,
    authorization: Optional[str] = Header(default=None),
):
    """
    Return a user's full record.

    BUG: No ownership check. Any authenticated user can read any other
    user's record, including their SSN and balance.
    Expected finding: IDOR — alice can read bob's record (user_id=2).
    """
    _require_auth(authorization)   # auth required — but NO ownership check

    user = USERS.get(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.get("/me/profile")
def get_my_profile(
    authorization: Optional[str] = Header(default=None),
):
    """
    Return the authenticated user's own profile.

    This is correctly implemented — the response is scoped to the caller.
    However, because alice and bob receive different response bodies at the
    same endpoint, the horizontal escalation detector flags it as a
    POTENTIAL horizontal escalation candidate requiring manual verification.
    Expected finding: horizontal_escalation (POTENTIAL).
    """
    user = _require_auth(authorization)
    # Correctly scoped — only returns caller's own data
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
        "balance": user["balance"],
    }


@app.get("/admin/users")
def list_all_users(
    authorization: Optional[str] = Header(default=None),
):
    """
    Return the full user list.

    BUG: No role check. Any authenticated user can reach this admin endpoint.
    Expected finding: vertical_escalation — alice (role=user) gets 200.
    """
    _require_auth(authorization)   # auth required — but NO role check

    return {"users": list(USERS.values()), "total": len(USERS)}


@app.get("/admin/stats")
def get_stats(
    authorization: Optional[str] = Header(default=None),
):
    """
    Return aggregate statistics.

    BUG: Same missing role check as /admin/users.
    Provides a second vertical escalation signal.
    """
    _require_auth(authorization)   # auth required — but NO role check

    return {
        "total_users": len(USERS),
        "total_balance": sum(u["balance"] for u in USERS.values()),
        "admin_count": sum(1 for u in USERS.values() if u["role"] == "admin"),
    }
