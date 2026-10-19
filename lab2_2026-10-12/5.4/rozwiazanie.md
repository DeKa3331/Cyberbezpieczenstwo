# Zadanie 5.4 — Cockpit CMS (CVE-2023-4195) — ⚠️ NIEDOKOŃCZONE

> **Status: niedokończone.** Środowisko uruchomione i rozpoznane, ale nie
> dokończono uploadu web shella ani dostępu po SSH (części d–g).

**Cel:** Cockpit CMS 0.12.2 podatny na RFI/arbitrary upload → RCE → dostęp do
serwera SSH.

- Cockpit: `http://127.0.0.1:4195`
- SSH: `127.0.0.1:8022` (uwaga: w PDF błędnie podano „2022"; `docker` mapuje 8022)

## Co zrobiono
- **(a/b)** Uruchomiono kontenery: `rcex4` (Cockpit, 4195) i `sshex4` (SSH, 8022).
- Zainstalowano Cockpita (`/install`), konto admina `admin/admin`, zalogowano.
- **(c)** Zidentyfikowano punkt wejścia: menedżer plików **Finder**
  (`http://127.0.0.1:4195/finder`) jako miejsce uploadu.
- Przygotowano web shell `webshell.php` (formularz `cmd` + `system()`).

## Co pozostało (TODO)
- **(d)** Wgrać `webshell.php` przez Finder do katalogu serwowanego przez web.
- **(e)** Uruchomić RCE (`?cmd=id`), a następnie z web shella połączyć się
  z kontenerem SSH (`127.0.0.1:8022`) — udowodnić dostęp.
- **(f)** Sprawdzić oficjalny fix (link „here" w instrukcji).
- **(g)** Oszacować CVSS.

## Pliki
- `webshell.php` — przygotowany web shell (do wgrania przez Finder).
