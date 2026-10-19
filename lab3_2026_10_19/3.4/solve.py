#!/usr/bin/env python3
# Zadanie 3.4 - weryfikacja podpisu JWT (z / bez), manipulacja payloadu
import base64, json, jwt

def replace_role(token, old, new):
    p = token.split(".")
    payload_bytes = base64.urlsafe_b64decode(p[1] + "==")
    fake_payload = payload_bytes.decode().replace(old, new)
    fake_payload_b64 = base64.urlsafe_b64encode(fake_payload.encode()).decode().rstrip("=")
    return p[0] + "." + fake_payload_b64 + "." + p[2]

SECRET_KEY = "secret"
ALG = "HS256"

# 1) Create JWT token
payload = {"id": 1, "role": "user"}
token = jwt.encode(payload, SECRET_KEY, algorithm=ALG)
print(f"Original Token: {token}\n")

# 2) + 3) Tamper payload (role: user -> admin), zachowujac oryginalny podpis
tampered = replace_role(token, "user", "admin")
print(f"Tampered Token: {tampered}\n")

# 4) Decode ORIGINAL - bez i z weryfikacja
print("[orig] bez weryfikacji:", jwt.decode(token, options={"verify_signature": False}))
print("[orig] z weryfikacja  :", jwt.decode(token, SECRET_KEY, algorithms=[ALG]))
print()

# 5) Decode TAMPERED - bez i z weryfikacja
print("[tamp] bez weryfikacji:", jwt.decode(tampered, options={"verify_signature": False}))
try:
    print("[tamp] z weryfikacja  :", jwt.decode(tampered, SECRET_KEY, algorithms=[ALG]))
except Exception as ex:
    print("[tamp] z weryfikacja  :", type(ex).__name__, "-", ex)
