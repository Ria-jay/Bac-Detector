# Broken Access Control Assessment Report

**Target:** http://localhost:8888  
**Date:** 2026-04-03  
**Tool:** BAC Detector v0.1.0  
**Scan ID:** `330e13b0-2f26-46a2-8b59-fd6d14472948`

---

## Executive Summary

**1 confirmed** broken access control issue(s) were identified that require immediate attention. An additional 4 potential issue(s) require manual verification. See individual findings for reproduction steps and remediation guidance.

### Finding Counts

| | |
|---|---|
| Total findings | 5 |
| Confirmed | 1 |
| Potential | 4 |

### Severity Breakdown

- 🟠 High: **3**
- 🟡 Medium: **2**

---

## Scan Metadata

| Property | Value |
|---|---|
| Scan ID | `330e13b0-2f26-46a2-8b59-fd6d14472948` |
| Target | http://localhost:8888 |
| Status | completed |
| Started | 2026-04-03 15:38:23 UTC |
| Duration | 10.0s |
| Endpoints discovered | 41 |
| Discovery sources | endpoint_list |
| Requests sent | 48 |
| Identities tested | `user1`, `user2` |

---

## Authorization Matrix

_✅ = access granted (2xx)  🚫 = access denied (401/403)  ❌ = error_

| Endpoint | user1 | user2 |
|---|---|---|
| `GET /community/api/v2/community/posts/recent` | ✅ 200 | ✅ 200 |
| `GET /community/api/v2/community/posts/search` | 400 | 400 |
| `GET /community/api/v2/community/posts/{post_id}` | 400 | 400 |
| `GET /identity/api/v2/admin/users` | 404 | 404 |
| `GET /identity/api/v2/admin/users/{user_id}` | 404 | 404 |
| `GET /identity/api/v2/user/dashboard` | ✅ 200 | ✅ 200 |
| `GET /identity/api/v2/user/pictures` | 405 | 405 |
| `GET /identity/api/v2/user/videos` | 405 | 405 |
| `GET /identity/api/v2/user/videos/{video_id}` | 400 | 400 |
| `GET /identity/api/v2/vehicle/vehicles` | ✅ 200 | ✅ 200 |
| `GET /identity/api/v2/vehicle/{vehicle_id}/location` | 400 | 400 |
| `GET /identity/api/v2/vehicle/{vehicle_id}/qr_code` | 400 | 400 |
| `GET /workshop/api/mechanic` | ✅ 200 | ✅ 200 |
| `GET /workshop/api/mechanic/mechanic_report` | 500 | 500 |
| `GET /workshop/api/mechanic/service_request/{service_id}` | 404 | 404 |
| `GET /workshop/api/mechanic/service_requests` | ✅ 200 | ✅ 200 |
| `GET /workshop/api/mechanic/{mechanic_id}` | 404 | 404 |
| `GET /workshop/api/shop/orders/all` | ✅ 200 | ✅ 200 |
| `GET /workshop/api/shop/orders/{order_id}` | 404 | 404 |
| `GET /workshop/api/shop/products` | ✅ 200 | ✅ 200 |

---

## Confirmed Findings

### Finding 1: IDOR: user2 accessed user1's object at /workshop/api/shop/orders/{order_id}

| | |
|---|---|
| **Severity** | 🟠 High |
| **Confidence** | ✅ Confirmed |
| **Category** | IDOR / BOLA |
| **Endpoint** | `GET /workshop/api/shop/orders/{order_id}` |
| **Method** | `GET` |
| **Attacker identity** | `user2` |
| **Victim identity** | `user1` |
| **Object ID** | `7` |

#### Description

Identity 'user2' successfully accessed object ID '7' at /workshop/api/shop/orders/{order_id}, which is owned by identity 'user1'. The server returned HTTP 200 without enforcing object-level ownership verification.

#### Evidence

Non-owner received HTTP 200. Owner received HTTP 200. Response bodies are identical to owner's response.

**Response snippet (attacker):**

```
{"order":{"id":7,"user":{"email":"testb@email.com","number":"0987654322"},"product":{"id":2,"name":"Wheel","price":"10.00","image_url":"images/wheel.svg"},"quantity":1,"status":"return pending","transaction_id":"30ae46b9-8ac3-4bf7-bceb-d409cda51c95","creat
```

#### Reproduction Steps

1. Authenticate as 'user2' using its configured credentials.
2. Send GET http://localhost:8888/workshop/api/shop/orders/7
3. Observe HTTP 200 response with resource data.
4. Compare response to what 'user1' receives for the same request.

#### Why This Is Broken Access Control

The application returns a successful response to a non-owner identity without verifying that the requesting user has ownership or delegated access to the requested object. This is a direct violation of object-level authorization (OWASP API Security Top 10: API1 - BOLA).

#### Business Impact

Any authenticated user may be able to access, read, or enumerate data belonging to other users. Depending on the data at this endpoint, this could expose PII, financial records, or other sensitive information.

#### Remediation

Implement per-request ownership verification: before returning a resource, confirm the authenticated user's identity matches the resource owner, or that an explicit permission delegation exists. Do not rely solely on authentication — also enforce authorization at the object level.


---

## Potential Findings (Requires Verification)

### Finding 1: Vertical escalation: 'user' role accessed privileged endpoint /identity/api/v2/user/dashboard

| | |
|---|---|
| **Severity** | 🟠 High |
| **Confidence** | ⚠️ Potential |
| **Category** | Vertical Privilege Escalation |
| **Endpoint** | `GET /identity/api/v2/user/dashboard` |
| **Method** | `GET` |
| **Attacker identity** | `user1` |

#### Description

Identity 'user1' with role 'user' successfully accessed /identity/api/v2/user/dashboard, which appears to be a privileged endpoint. The expected behavior is that only a privileged identity should have access.

#### Evidence

'user1' (user) received HTTP 200. No higher-privilege baseline available.

**Response snippet (attacker):**

```
{"id":9,"name":"TestB","email":"testb@email.com","number":"0987654322","picture_url":"data:image/jpeg;base64,/9j/4AAQSkZJRgABAgAAAQABAAD/7QAwUGhvdG9zaG9wIDMuMAA4QklNBAQAAAAAABMcAnQAB1BpY29DVEYcAgAAAgAEAP/hC/lodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvADw/eHBhY2t
```

#### Reproduction Steps

1. Authenticate as 'user1' using its configured credentials.
2. Send GET http://localhost:8888/identity/api/v2/user/dashboard
3. Observe HTTP 200 response — expected 401 or 403.

#### Why This Is Broken Access Control

The application does not enforce role-based access control on this endpoint. A low-privileged identity received a successful response on a path reserved for privileged roles. This constitutes vertical privilege escalation (OWASP API Security Top 10: API5 - Broken Function Level Authorization).

#### Business Impact

Low-privileged users may be able to access administrative functionality, view privileged data, or perform actions reserved for admin roles. This could lead to full account takeover or data breach in severe cases.

#### Remediation

Implement role-based access control (RBAC) checks at the function/endpoint level. Verify the authenticated user's role before processing the request. Consider using middleware or decorators to enforce role requirements consistently across all privileged endpoints.

### Finding 2: Vertical escalation: 'user' role accessed privileged endpoint /identity/api/v2/user/dashboard

| | |
|---|---|
| **Severity** | 🟠 High |
| **Confidence** | ⚠️ Potential |
| **Category** | Vertical Privilege Escalation |
| **Endpoint** | `GET /identity/api/v2/user/dashboard` |
| **Method** | `GET` |
| **Attacker identity** | `user2` |

#### Description

Identity 'user2' with role 'user' successfully accessed /identity/api/v2/user/dashboard, which appears to be a privileged endpoint. The expected behavior is that only a privileged identity should have access.

#### Evidence

'user2' (user) received HTTP 200. No higher-privilege baseline available.

**Response snippet (attacker):**

```
{"id":8,"name":"Testy","email":"testyy@email.com","number":"0987654321","picture_url":null,"video_url":null,"video_name":null,"available_credit":90.0,"video_id":0,"role":"ROLE_USER"}
```

#### Reproduction Steps

1. Authenticate as 'user2' using its configured credentials.
2. Send GET http://localhost:8888/identity/api/v2/user/dashboard
3. Observe HTTP 200 response — expected 401 or 403.

#### Why This Is Broken Access Control

The application does not enforce role-based access control on this endpoint. A low-privileged identity received a successful response on a path reserved for privileged roles. This constitutes vertical privilege escalation (OWASP API Security Top 10: API5 - Broken Function Level Authorization).

#### Business Impact

Low-privileged users may be able to access administrative functionality, view privileged data, or perform actions reserved for admin roles. This could lead to full account takeover or data breach in severe cases.

#### Remediation

Implement role-based access control (RBAC) checks at the function/endpoint level. Verify the authenticated user's role before processing the request. Consider using middleware or decorators to enforce role requirements consistently across all privileged endpoints.

### Finding 3: Inconsistent protection: 'user1' denied read but allowed list on 'mechanic'

| | |
|---|---|
| **Severity** | 🟡 Medium |
| **Confidence** | ⚠️ Potential |
| **Category** | Inconsistent Sibling Action Protection |
| **Endpoint** | `GET /workshop/api/mechanic` |
| **Method** | `GET` |
| **Attacker identity** | `user1` |

#### Description

Identity 'user1' is denied access to 'GET /workshop/api/mechanic/{mechanic_id}' (read) but is allowed to perform 'list' on a sibling endpoint 'GET /workshop/api/mechanic' within the same 'mechanic' resource family. This suggests authorization is applied inconsistently across actions on the same resource.

#### Evidence

'user1' was DENIED read on 'GET /workshop/api/mechanic/{mechanic_id}' (HTTP 404) but ALLOWED list on 'GET /workshop/api/mechanic' (HTTP 200) within the same 'mechanic' resource family.

#### Reproduction Steps

1. Authenticate as 'user1'.
2. Send GET /workshop/api/mechanic/{mechanic_id} — observe HTTP 404 (denied).
3. Send GET /workshop/api/mechanic — observe HTTP 200 (allowed).
4. Both requests act on the same resource family. One should be at least as restricted as the other.

#### Why This Is Broken Access Control

Authorization controls should be applied consistently across all actions within the same resource family. Allowing a more sensitive or equivalent action while denying a less sensitive one often indicates missing or incomplete authorization checks.

#### Business Impact

An attacker may exploit the allowed action to access or modify data they should not have access to, bypassing the denied action's intended protection.

#### Remediation

Review authorization logic for all endpoints in the 'mechanic' resource family. Ensure that the same ownership and role checks are applied consistently across all actions. Consider centralizing authorization logic for the resource family.

### Finding 4: Inconsistent protection: 'user2' denied read but allowed list on 'mechanic'

| | |
|---|---|
| **Severity** | 🟡 Medium |
| **Confidence** | ⚠️ Potential |
| **Category** | Inconsistent Sibling Action Protection |
| **Endpoint** | `GET /workshop/api/mechanic` |
| **Method** | `GET` |
| **Attacker identity** | `user2` |

#### Description

Identity 'user2' is denied access to 'GET /workshop/api/mechanic/{mechanic_id}' (read) but is allowed to perform 'list' on a sibling endpoint 'GET /workshop/api/mechanic' within the same 'mechanic' resource family. This suggests authorization is applied inconsistently across actions on the same resource.

#### Evidence

'user2' was DENIED read on 'GET /workshop/api/mechanic/{mechanic_id}' (HTTP 404) but ALLOWED list on 'GET /workshop/api/mechanic' (HTTP 200) within the same 'mechanic' resource family.

#### Reproduction Steps

1. Authenticate as 'user2'.
2. Send GET /workshop/api/mechanic/{mechanic_id} — observe HTTP 404 (denied).
3. Send GET /workshop/api/mechanic — observe HTTP 200 (allowed).
4. Both requests act on the same resource family. One should be at least as restricted as the other.

#### Why This Is Broken Access Control

Authorization controls should be applied consistently across all actions within the same resource family. Allowing a more sensitive or equivalent action while denying a less sensitive one often indicates missing or incomplete authorization checks.

#### Business Impact

An attacker may exploit the allowed action to access or modify data they should not have access to, bypassing the denied action's intended protection.

#### Remediation

Review authorization logic for all endpoints in the 'mechanic' resource family. Ensure that the same ownership and role checks are applied consistently across all actions. Consider centralizing authorization logic for the resource family.


---

## Appendix: Tested Endpoints

_41 endpoints discovered from endpoint_list._

| Method | Path | IDOR Candidate |
|---|---|---|
| `HttpMethod.POST` | `/identity/api/auth/signup` |  |
| `HttpMethod.POST` | `/identity/api/auth/login` |  |
| `HttpMethod.POST` | `/identity/api/auth/forget-password` |  |
| `HttpMethod.POST` | `/identity/api/auth/v3/check-otp` |  |
| `HttpMethod.POST` | `/identity/api/auth/v2/user/reset-password` |  |
| `HttpMethod.GET` | `/identity/api/v2/user/dashboard` |  |
| `HttpMethod.GET` | `/identity/api/v2/user/videos` |  |
| `HttpMethod.PUT` | `/identity/api/v2/user/videos/{video_id}` |  |
| `HttpMethod.DELETE` | `/identity/api/v2/user/videos/{video_id}` |  |
| `HttpMethod.GET` | `/identity/api/v2/user/videos/{video_id}` |  |
| `HttpMethod.POST` | `/identity/api/v2/user/videos/convert_video` |  |
| `HttpMethod.GET` | `/identity/api/v2/user/pictures` |  |
| `HttpMethod.GET` | `/identity/api/v2/vehicle/vehicles` |  |
| `HttpMethod.POST` | `/identity/api/v2/vehicle/add_vehicle` |  |
| `HttpMethod.GET` | `/identity/api/v2/vehicle/{vehicle_id}/location` |  |
| `HttpMethod.GET` | `/identity/api/v2/vehicle/{vehicle_id}/qr_code` |  |
| `HttpMethod.POST` | `/identity/api/v2/vehicle/qr_code` |  |
| `HttpMethod.POST` | `/identity/api/v2/vehicle/resend_email` |  |
| `HttpMethod.GET` | `/community/api/v2/community/posts/recent` |  |
| `HttpMethod.GET` | `/community/api/v2/community/posts/{post_id}` |  |
| `HttpMethod.POST` | `/community/api/v2/community/posts` |  |
| `HttpMethod.PUT` | `/community/api/v2/community/posts/{post_id}` |  |
| `HttpMethod.DELETE` | `/community/api/v2/community/posts/{post_id}` |  |
| `HttpMethod.POST` | `/community/api/v2/community/posts/{post_id}/comment` |  |
| `HttpMethod.GET` | `/community/api/v2/community/posts/search` |  |
| `HttpMethod.POST` | `/community/api/v2/coupon/validate-coupon` |  |
| `HttpMethod.GET` | `/workshop/api/shop/products` |  |
| `HttpMethod.POST` | `/workshop/api/shop/orders` |  |
| `HttpMethod.GET` | `/workshop/api/shop/orders/all` |  |
| `HttpMethod.GET` | `/workshop/api/shop/orders/{order_id}` | ✓ |
| `HttpMethod.POST` | `/workshop/api/shop/orders/return_order` |  |
| `HttpMethod.GET` | `/workshop/api/mechanic` |  |
| `HttpMethod.POST` | `/workshop/api/mechanic/mechanic_report` |  |
| `HttpMethod.GET` | `/workshop/api/mechanic/mechanic_report` |  |
| `HttpMethod.GET` | `/workshop/api/mechanic/{mechanic_id}` |  |
| `HttpMethod.POST` | `/workshop/api/mechanic/service_request` |  |
| `HttpMethod.GET` | `/workshop/api/mechanic/service_requests` |  |
| `HttpMethod.GET` | `/workshop/api/mechanic/service_request/{service_id}` |  |
| `HttpMethod.GET` | `/identity/api/v2/admin/users` |  |
| `HttpMethod.GET` | `/identity/api/v2/admin/users/{user_id}` | ✓ |
| `HttpMethod.DELETE` | `/identity/api/v2/admin/users/{user_id}` | ✓ |
