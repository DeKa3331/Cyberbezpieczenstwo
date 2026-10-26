import jwt, datetime
SECRET = "mysecret"; ALG = "HS256"
payload = {"user_id": 1, "username": "student",
           "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)}
token = jwt.encode(payload, SECRET, algorithm=ALG)
print("[OK] poprawny:", jwt.decode(token, SECRET, algorithms=[ALG]))

# (e) zmiana tokena przed dekodowaniem (psujemy ostatni znak podpisu)
tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
try:
    jwt.decode(tampered, SECRET, algorithms=[ALG])
except Exception as ex:
    print("(e) zmieniony token ->", type(ex).__name__, "-", ex)

# (f) dekodowanie zlym sekretem
try:
    jwt.decode(token, "zlysekret", algorithms=[ALG])
except Exception as ex:
    print("(f) zly sekret     ->", type(ex).__name__, "-", ex)
