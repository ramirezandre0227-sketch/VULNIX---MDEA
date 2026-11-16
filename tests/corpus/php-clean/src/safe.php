<?php
// Corpus VULNIX: proyecto negativo de referencia (patrones seguros parecidos a los vulnerables).
$pdo = new PDO($dsn, $user, getenv('DB_PASSWORD'));
$id = (int) $_GET['id'];
$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
$stmt->execute([$id]);
$name = $_GET['name'] ?? '';
echo '<h1>Hola ' . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . '</h1>';
$host = $_POST['host'] ?? '';
if (filter_var($host, FILTER_VALIDATE_IP)) { system('ping -c 1 ' . escapeshellarg($host)); }
$pages = ['home' => 'home.php', 'about' => 'about.php'];
$page = $pages[$_GET['page'] ?? 'home'] ?? 'home.php';
include __DIR__ . '/views/' . $page;
$prefs = json_decode($_COOKIE['prefs'] ?? '{}', true);
$file = basename($_GET['file'] ?? '');
readfile('/var/www/files/' . $file);
$hash = password_hash($password, PASSWORD_ARGON2ID);
$token = bin2hex(random_bytes(32));
