<?php
// Corpus VULNIX: vulnerabilidades conocidas. NO DESPLEGAR.
$conn = mysqli_connect('localhost', 'app', getenv('DB_PASS'), 'shop');

$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id;
$result = mysqli_query($conn, $sql);

$name = $_GET['name'];
echo "<h1>Hola " . $name . "</h1>";

$host = $_POST['host'];
system("ping -c 1 " . $host);

$page = $_GET['page'];
include($page . '.php');

$data = unserialize($_COOKIE['prefs']);

$file = $_GET['file'];
readfile('/var/www/files/' . $file);

$hash = md5($password);
