#!/usr/bin/env python3
"""Safe POST-only admin diagnostic. Does not send account data."""
import getpass, json, urllib.request, urllib.error
BASE='https://dpm-license-server.onrender.com'
base=input(f'Central server URL [{BASE}]: ').strip().rstrip('/') or BASE
token=getpass.getpass('Render DPM_LICENSE_ADMIN_TOKEN (input hidden): ').strip()
if not token: raise SystemExit('No token supplied; stopped.')
data=json.dumps({'probe':True,'admin_token':token}).encode()
req=urllib.request.Request(base+'/admin-import',data=data,method='POST',headers={'Content-Type':'application/json','Accept':'application/json'})
try:
    with urllib.request.urlopen(req,timeout=20) as r:
        body=r.read().decode('utf-8','replace')
        print(f'HTTP {r.status}; body={body[:1000] or "[empty]"}')
except urllib.error.HTTPError as e:
    body=e.read().decode('utf-8','replace')
    print(f'HTTP {e.code}; body={body[:1000] or "[empty response body]"}')
    for k in ('Content-Type','Content-Length','CF-RAY','Server','Date'):
        if e.headers.get(k): print(f'{k}: {e.headers.get(k)}')
except Exception as e:
    print(f'Request failed: {type(e).__name__}: {e}')
