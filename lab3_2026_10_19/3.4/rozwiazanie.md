# Zadanie 3.4 — Weryfikacja podpisu JWT

**Cel:** pokazać różnicę między dekodowaniem JWT **z** weryfikacją podpisu i
**bez** niej, oraz skutek manipulacji payloadu.

- Kontener: `docker run -it --name jwtex4 docker.io/mazurkatarzyna/jwt-ex4`
- Szablon `template.py` dostarcza funkcję `replace_role()` (podmiana w payload
  + ponowne złożenie tokena z **oryginalnym** podpisem).
- `SECRET_KEY = "secret"`, `payload = {"id":1,"role":"user"}`, algorytm HS256.

## Rozwiązanie (`solve.py`)

Kluczowe wywołania PyJWT:
```python
# bez weryfikacji podpisu:
jwt.decode(token, options={"verify_signature": False})
# z weryfikacja:
jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
```

## Wynik

```
Original Token: eyJhbGci...R5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6InVzZXIifQ.gYH6y5BE...LOaY
Tampered Token: eyJhbGci...R5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6ImFkbWluIn0.gYH6y5BE...LOaY
                 ^^^ ten sam header          ^^^ payload role=admin           ^^^ ten sam podpis

[orig] bez weryfikacji: {'id': 1, 'role': 'user'}
[orig] z weryfikacja  : {'id': 1, 'role': 'user'}

[tamp] bez weryfikacji: {'id': 1, 'role': 'admin'}        <-- podmiana zaakceptowana!
[tamp] z weryfikacja  : InvalidSignatureError - Signature verification failed  <-- odparte
```

## Wnioski (a–d)
- **(a)** Token = `header.payload.signature` (Base64url).
- **(b)** Z weryfikacją — zwraca payload tylko jeśli podpis pasuje do sekretu.
- **(c)** Bez weryfikacji — zwraca payload **bez sprawdzania podpisu** (czysty odczyt).
- **(d)** Po podmianie `role: user → admin` przy **zachowanym starym podpisie**:
  - **bez weryfikacji** → serwer akceptuje `role=admin` → **eskalacja uprawnień**,
  - **z weryfikacją** → `InvalidSignatureError`, bo podpis nie pasuje do
    zmienionego payloadu → atak odparty.

**Morał:** każdy token od klienta musi być dekodowany **z weryfikacją podpisu**.
`verify_signature=False` zamienia JWT w zwykły, niechroniony JSON.
