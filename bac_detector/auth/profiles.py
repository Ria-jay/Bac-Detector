"""
Authentication profile helpers.

Translates IdentityProfile models into httpx-ready headers and cookies
for use in the replay engine.

This is the single source of truth for auth header/cookie construction.
The IdentityProfile model itself does not contain this logic — keeping
models as pure data and auth behaviour in this module.
"""

from bac_detector.models.identity import AuthMechanism, IdentityProfile


def build_request_headers(identity: IdentityProfile) -> dict[str, str]:
    """
    Build the HTTP headers required for a given identity's requests.

    Merges bearer token, custom headers, and any other auth-related
    headers into a single dict ready for use with httpx.

    Priority order (highest wins):
      1. Authorization header (from bearer token)
      2. Custom headers (from identity.custom_headers)

    Args:
        identity: The IdentityProfile to build headers for.

    Returns:
        Dict of HTTP header name -> value.
    """
    headers: dict[str, str] = {}

    # Custom headers applied first — auth header may override if needed
    headers.update(identity.custom_headers)

    if identity.auth_mechanism == AuthMechanism.BEARER:
        if identity.token:
            headers["Authorization"] = f"Bearer {identity.token}"
    elif identity.auth_mechanism in (AuthMechanism.HEADER, AuthMechanism.NONE):
        # HEADER: custom_headers already applied above
        # NONE: unauthenticated / guest — no auth header added
        pass
    # COOKIE: cookies are passed separately via build_request_cookies(),
    # not as headers, so nothing extra to do here.

    return headers


def build_request_cookies(identity: IdentityProfile) -> dict[str, str]:
    """
    Build the cookie dict for a given identity.

    Args:
        identity: The IdentityProfile to build cookies for.

    Returns:
        Dict of cookie name -> value (empty for non-cookie auth mechanisms).
    """
    if identity.auth_mechanism == AuthMechanism.COOKIE:
        return dict(identity.cookies)
    return {}
