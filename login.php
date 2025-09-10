<?php
session_start();

/* -----------------------------------
   Load sensitive credentials securely
   (stored outside web root)
------------------------------------ */
$secrets = require '/etc/appsecrets/login-demo.php';

$DB_HOST = $secrets['DB_HOST'];
$DB_NAME = $secrets['DB_NAME'];
$DB_USER = $secrets['DB_USER'];
$DB_PASS = $secrets['DB_PASS'];

/* Default failure flag */
$failed = false;

try {
    // Create PDO connection to MariaDB
    $dsn = "mysql:host=$DB_HOST;dbname=$DB_NAME;charset=utf8mb4";
    $pdo = new PDO($dsn, $DB_USER, $DB_PASS, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (Exception $e) {
    // If DB connection fails, show 500 error
    http_response_code(500);
    echo "Database connection error.";
    exit;
}

/* -----------------------------------
   Handle POST login requests
------------------------------------ */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = $_POST['username'] ?? '';
    $p = $_POST['password'] ?? '';

    // Prepared statement to avoid SQL Injection
    $stmt = $pdo->prepare('SELECT passhash FROM users WHERE username = :u LIMIT 1');
    $stmt->execute([':u' => $u]);
    $row = $stmt->fetch();

    // Verify user password hash
    if (!$row || !password_verify($p, $row['passhash'])) {
        // Important: return 401 so Fail2Ban can catch it
        http_response_code(401);
        $failed = true;
    } else {
        // Successful login -> set session and redirect
        $_SESSION['user'] = $u;
        header('Location: /welcome.php');
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Login Page</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body {font-family: sans-serif; background:#f5f5f5; display:flex; align-items:center; justify-content:center; min-height:100vh;}
    .card {background:#fff; padding:24px; border-radius:12px; width:100%; max-width:360px; box-shadow:0 6px 20px rgba(0,0,0,.08);}
    h1 {font-size:20px; margin-top:0; text-align:center}
    .msg {margin:10px 0; color:#b00020; text-align:center}
    label {display:block; margin:10px 0 6px}
    input {width:100%; padding:10px; border:1px solid #ddd; border-radius:8px}
    button {margin-top:14px; width:100%; padding:10px; border:0; border-radius:8px; cursor:pointer; background:#0a7cff; color:#fff; font-weight:600}
  </style>
</head>
<body>
  <div class="card">
    <h1>Login</h1>
    <?php if ($failed): ?>
      <div class="msg">Invalid username or password</div>
    <?php endif; ?>
    <form method="POST" action="/login.php">
      <label>Username</label>
      <input name="username" autocomplete="username" required>

      <label>Password</label>
      <input name="password" type="password" autocomplete="current-password" required>

      <button type="submit">Login</button>
    </form>
  </div>
</body>
</html>
