# Zadanie 3.1 — Generowanie JWT i zrozumienie struktury

**Cel:** uzupełnić szablon `app.py` (biblioteka PyJWT) o kodowanie i dekodowanie
tokena JWT, a następnie sprawdzić zachowanie przy manipulacji tokenem (e) i
złym sekrecie (f).

- Kontener: `docker run -it --name jwtex1 docker.io/mazurkatarzyna/jwt-ex1`
- Biblioteka: **PyJWT**, algorytm **HS256**, sekret `mysecret`

## Uzupełniony kod (`app.py`)

```python
# Generate JWT
token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
print("JWT:", token)

# Decode
decoded_payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
print("Decoded Payload:", decoded_payload)
```

## Wynik

```
JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjox...  .  adeP5FKt...
Decoded Payload: {'user_id': 1, 'username': 'student', 'exp': 1792406025}
```

Struktura tokena (3 części Base64url oddzielone kropkami):
- **header** – `{"alg":"HS256","typ":"JWT"}`
- **payload** – `{"user_id":1,"username":"student","exp":...}`
- **signature** – `HMAC-SHA256(header + "." + payload, SECRET_KEY)`

## (e) Zmiana tokena przed dekodowaniem
Zmiana choćby jednego znaku tokena → przeliczony podpis ≠ przysłany →
`InvalidSignatureError: Signature verification failed`.
Payload jest podpisany, nie szyfrowany — da się go odczytać, ale nie podmienić
bez znajomości sekretu.

## (f) Zły sekret przy dekodowaniu
Dekodowanie innym sekretem → serwer liczy inny HMAC niż zapisany w tokenie →
`InvalidSignatureError`. Cała integralność opiera się na tajności sekretu.

```
[OK] poprawny: {'user_id': 1, 'username': 'student', 'exp': ...}
(e) zmieniony token -> InvalidSignatureError - Signature verification failed
(f) zly sekret      -> InvalidSignatureError - Signature verification failed
```

## Wniosek
Podpis HMAC gwarantuje **integralność i autentyczność** payloadu. Bez sekretu
nie da się wygenerować poprawnego podpisu, więc serwer odrzuci każdy
zmodyfikowany lub obcym kluczem podpisany token.
