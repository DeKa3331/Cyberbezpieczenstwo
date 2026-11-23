# Zadanie 4.1 — Port Scanning (Metasploit, moduł `portscan/tcp`)

> **Cel:** z poziomu `msfconsole` przeskanować podsieć `10.10.10.0/24` i znaleźć
> żywe hosty oraz otwarte porty (rekonesans pod kolejne zadania 4.2–4.6).

| | |
|---|---|
| **Środowisko** | `docker compose -f docker-compose-metasploit-ssh.yml up -d` |
| **Atakujący** | kontener `metasploit` (`msf6 v6.5.11-dev`) |
| **Moduł** | `auxiliary/scanner/portscan/tcp` |
| **Zakres** | `RHOSTS 10.10.10.0/24`, `PORTS 22,21,80` |

## a) Uruchomienie środowiska
```bash
cd ~/Desktop/cyberbezpieczenstwo/lab7_2026-11-23
sudo docker compose -f docker-compose-metasploit-ssh.yml up -d
sudo docker compose -f docker-compose-metasploit-ssh.yml ps   # 6 serwerów SSH + metasploit
```

Wejście do konsoli Metasploita:
```bash
sudo docker exec -it metasploit bash
./msfconsole
```

## b) Skan portów
```
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.10.10.0/24
set PORTS 22,21,80
set THREADS 20
run
```

Wynik:
```
[+] 10.10.10.10 - 10.10.10.10:22 - TCP OPEN
[+] 10.10.10.11 - 10.10.10.11:22 - TCP OPEN
[+] 10.10.10.12 - 10.10.10.12:22 - TCP OPEN
[+] 10.10.10.13 - 10.10.10.13:22 - TCP OPEN
[+] 10.10.10.14 - 10.10.10.14:22 - TCP OPEN
[*] Scanned 256 of 256 hosts (100% complete)
```

![Skan portów portscan/tcp → 5 hostów, port 22 otwarty](screeny/01_portscan_22_open.png)

## Odpowiedzi
- **Żywe hosty:** 5 → `10.10.10.10`, `.11`, `.12`, `.13`, `.14`
- **Otwarty port:** na wszystkich **22/tcp (SSH)**; porty 21 i 80 zamknięte
- To nasza powierzchnia ataku pod dalsze zadania (każdy host = inna podatność SSH):
  `.11` user-enum (CVE-2018-15473), `.13` libssh auth bypass (CVE-2018-10933),
  `.10` słabe hasła (bruteforce).

## Czego uczy zadanie
`portscan/tcp` to prosty skaner TCP wbudowany w Metasploit — przydatny, gdy
działamy już z poziomu `msfconsole` (bez wychodzenia do `nmap`). `THREADS`
przyspiesza skan równoległością, `PORTS` ogranicza do interesujących usług.
Rekonesans portów to pierwszy krok każdego testu — mapuje, co w ogóle jest
wystawione, zanim dobierzemy moduł eksploatujący.
