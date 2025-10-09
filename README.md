An extensible, defense‑in‑depth Intrusion Detection & Prevention module for Magento 2.
#v2.2.4
New: Added a nice clean block page with contact details rather than the one line error message "An error has happened during application run. See exception log for details."

#v2.2.3


Fixed not blocking ip addresses


Fixed not removing expired ip's


Fixed logging


Added whitelist.

#v2.0.0
Refactor extension to fix grids not loading

#V1.1.1

Fix: On re-install we see "SQLSTATE[42000]: Syntax error or access violation: 1061 Duplicate key name 'MERLIN_INTRUSION_EVENT_IP', query was: ALTER TABLE merlin_intrusion_event ADD INDEX MERLIN_INTRUSION_EVENT_IP (ip), ADD INDEX MERLIN_INTRUSION_EVENT_CREATED_AT (created_at)"
SQLSTATE[42000]: Syntax error or access violation: 1061 Duplicate key name 'MERLIN_BLOCKED_IP_IP', query was: ALTER TABLE merlin_blocked_ip ADD INDEX MERLIN_BLOCKED_IP_IP (ip), ADD INDEX MERLIN_BLOCKED_IP_EXPIRES_AT (expires_at)

#v1.1.0

Fix: Fix ACL Permissions for events and blocks

Fix: Safety fix: the IDS no longer blocks inside the **adminhtml** area to prevent lockouts

New: Added Full Admin Grids for **Intrusion Events** and **Blocked IPs** (with CRUD + mass delete).

#v1.0.0

Initial Release

My initial release focuses on safe, composable primitives: request inspection, brute‑force throttling, IP blocking, honeypots, event logging, and admin/system configuration. It’s built to be production‑ready but conservative by default. You can extend each detector via DI.

# Setup & usage

1) Deploy the module into `app/code/Merlin/IntrusionDetection`.
2) `bin/magento module:enable Merlin_IntrusionDetection && bin/magento setup:upgrade`
3) Configure in **Stores → Configuration → Security → Merlin Intrusion Detection**.
4) Start in **Detect** mode to observe events. Switch to **Block** to actively return HTTP 403 and optionally auto‑block offending IPs.
5) CLI helpers:
- `bin/magento merlin:id:block-ip 1.2.3.4 120 "manual test"`
- `bin/magento merlin:id:unblock-ip 1.2.3.4`
- `bin/magento merlin:id:list-blocked`



# Roadmap & Feature Ideas


- **GeoIP velocity checks**: sudden country jumps per session/IP.
- **Header sanity**: invalid Host, spoofed X-Forwarded-For, missing Accept headers.
- **GraphQL & REST hardening**: schema‑aware allowlists, depth/complexity limits.
- **File upload guard**: MIME sniffing, extension allowlist, scan via ClamAV/ICAP.
- **Admin path cloak**: randomize backend path detection + decoy endpoints.
- **2FA enforcement hooks**: deny risky IPs even pre‑auth.
- **Behavioral bot scoring**: sliding window + exponential backoff blocking.
- **Reputation lists**: optional integration with AbuseIPDB/Spamhaus (cachable, privacy‑aware).
- **CSP & security headers**: auto‑inject recommended headers with per‑route overrides.
- **Checkout abuse detection**: carding/BIN velocity, failed AVS/CVV spikes.
- **Captcha on demand**: trigger Captcha only when a risk score threshold is hit.
- **Webhook to SIEM**: stream `merlin_intrusion_event` to Splunk/ELK via queue.
- **Admin grids**: UI for Events & Blocked IPs with export, bulk actions.
- **Decoy admin users**: honey‑credentials to instantly flag attackers.
- **Inventory of scanners**: rolling UA/IP fingerprints to preemptively tarp.


# Notes
- This module is intentionally minimal in UI but strong in core mechanics.
- Avoid over‑blocking: keep **Detect** mode ON first, watch `merlin_intrusion_event`, then enable Blocking
- Ensure correct client IP: if behind HAProxy/Varnish, make sure Magento is reading `X-Forwarded-For` correctly (set `trusted_proxies`).
