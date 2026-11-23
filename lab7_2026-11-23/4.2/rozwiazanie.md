# Zadanie 4.2 — Service / Version Detection (moduł `ssh_version`)

> **Cel:** zidentyfikować wersje demonów SSH na hostach znalezionych w 4.1
> (`10.10.10.10-14`) — banner, produkt, wersja, OS — żeby dobrać właściwy
> exploit do każdego z nich.

| | |
|---|---|
| **Moduł** | `auxiliary/scanner/ssh/ssh_version` |
| **Zakres** | `RHOSTS 10.10.10.10-14` |

## Uruchomienie
```
use auxiliary/scanner/ssh/ssh_version
set RHOSTS 10.10.10.10-14
set THREADS 5
run
```

Moduł łączy się z portem 22 każdego hosta, czyta **banner** (`SSH-2.0-...`)
i przez bazę `recog` (`fingerprint_db ssh.banner`) rozpoznaje produkt, wersję,
a często i system operacyjny oraz obsługiwane algorytmy szyfrowania.

## Wynik — mapa wersji
| Host | Banner | Produkt / wersja | OS |
|------|--------|------------------|-----|
| `10.10.10.10` | `OpenSSH_8.2p1 Ubuntu-4ubuntu0.13` | OpenSSH 8.2p1 | Ubuntu 20.04 |
| `10.10.10.11` | `OpenSSH_7.7` | OpenSSH 7.7 | — |
| `10.10.10.12` | `OpenSSH_7.2p2 Ubuntu-4ubuntu2.10` | OpenSSH 7.2p2 | Ubuntu 16.04 |
| `10.10.10.13` | `libssh_0.8.3` | **libssh 0.8.3** | — |
| `10.10.10.14` | `OpenSSH_6.7p1 Debian-5+deb8u8` | OpenSSH 6.7p1 | Debian 8 |

![ssh_version → banery i wersje 5 hostów](screeny/01_ssh_version.png)

## Powiązanie z kolejnymi zadaniami
- **`.11` OpenSSH 7.7** → podatny na **CVE-2018-15473** (user enumeration po
  czasie odpowiedzi; dotyczy OpenSSH < 7.8) → **zad. 4.3**
- **`.13` libssh 0.8.3** → podatny na **CVE-2018-10933** (auth bypass; libssh
  0.6–0.8.3 po stronie serwera) → **zad. 4.6**
- **`.10` OpenSSH 8.2p1** → brak znanej dziury w samym demonie → cel na
  **bruteforce słabych haseł** (zad. 4.4)

## Czego uczy zadanie
Fingerprinting wersji to krok po skanie portów — sam otwarty port 22 nic nie
mówi, dopiero **produkt + wersja** pozwala dopasować konkretny CVE/exploit.
`ssh_version` od razu podaje też algorytmy i oznacza słabe (`Deprecated`,
`Weak elliptic curve`), co przydaje się w audycie konfiguracji.

> Uwaga: ostrzeżenia `recog ... regexp_factory.rb warning` to kosmetyczny log
> biblioteki (nested repeat w regexie), nie błąd skanu.
