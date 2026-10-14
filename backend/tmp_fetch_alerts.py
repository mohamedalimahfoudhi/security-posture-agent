import urllib.request, urllib.parse, json

def main():
    login_data = urllib.parse.urlencode({'username':'admin','password':'admin'}).encode()
    req = urllib.request.Request('http://127.0.0.1:8000/api/auth/login', data=login_data, headers={'Content-Type':'application/x-www-form-urlencoded'})
    resp = urllib.request.urlopen(req).read().decode()
    token = json.loads(resp).get('access_token')
    if not token:
        print('LOGIN_FAILED', resp)
        return
    req2 = urllib.request.Request('http://127.0.0.1:8000/api/alerts/', headers={'Authorization':f'Bearer {token}'})
    alerts = json.loads(urllib.request.urlopen(req2).read().decode())
    out_path = '../frontend/screenshots/alerts.json'
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(alerts, f, indent=2)
    print('WROTE', len(alerts), 'to', out_path)

if __name__ == '__main__':
    main()
