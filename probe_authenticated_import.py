#!/usr/bin/env python3
"""Safe auth-only probe: sends no account data."""
import getpass, urllib.request, urllib.error
BASE = "https://dpm-license-server.onrender.com"
base = input(f"Central server URL [{BASE}]: ").strip().rstrip("/") or BASE
token = getpass.getpass("DPM_LICENSE_ADMIN_TOKEN (hidden): ").strip()
if not token:
    raise SystemExit("No token supplied; stopped.")
req = urllib.request.Request(
    base + "/v1/admin/import-local-accounts",
    data=b'{"probe": true}',
    method="POST",
    headers={
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer " + token,
    },
)
try:
    with urllib.request.urlopen(req, timeout=20) as response:
        print(f"HTTP {response.status}; body={response.read().decode('utf-8', 'replace')}")
except urllib.error.HTTPError as exc:
    print(f"HTTP {exc.code}; body={exc.read().decode('utf-8', 'replace')}")
