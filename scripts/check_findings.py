import urllib.request, json

req = urllib.request.Request(
    'http://127.0.0.1:8000/api/v1/auth/login',
    data=json.dumps({'email': 'owner@aegis.example', 'password': 'Password123!'}).encode('utf-8'),
    headers={'Content-Type': 'application/json'}
)
resp = urllib.request.urlopen(req)
token = json.loads(resp.read().decode('utf-8'))['access_token']

req2 = urllib.request.Request(
    'http://127.0.0.1:8000/api/v1/findings',
    headers={'Authorization': f'Bearer {token}'}
)
resp2 = urllib.request.urlopen(req2)
data = json.loads(resp2.read().decode('utf-8'))
items = data.get('items', [])
print(f'Total Active Findings in Control Plane: {len(items)}')
for idx, f in enumerate(items, start=1):
    rule = f.get('rule_key', 'unknown')
    sev = f.get('severity', 'UNKNOWN')
    sink = f.get('sink_signature', 'N/A')
    print(f' [{idx:02d}] Rule: {rule:<24} | Severity: {sev:<10} | Sink: {sink}')
