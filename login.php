<?php
/**
 * Minimal, secure-ish login page for our demo.
 * - Reads DB credentials from a protected file outside the web root: /etc/appsecrets/db_config.php
 * - Uses PDO with prepared statements to prevent SQL injection.
 * - Uses password_hash()/password_verify() compatible hashes stored in the DB.
 * - Returns HTTP 401 on failed auth (useful for WAF rules).
 * - Starts a session and redirects to /welcome.php on success.
 */

declare(strict_types=1);

session_start();

/* ----------------------------------------------
   1) Load DB credentials from a secure location
   - The file /etc/appsecrets/db_config.php is owned by root, group apache, mode 640.
   - It defines constants: DB_HOST, DB_NAME, DB_USER, DB_PASS
   - Keeping secrets outside /var/www/html reduces accidental exposure.
------------------------------------------------ */
require_once '/etc/appsecrets/db_config.php';

// Map constants to local variables (purely stylistic)
$DB_HOST = DB_HOST;
$DB_NAME = DB_NAME;
$DB_USER = DB_USER;
$DB_PASS = DB_PASS;

/* ----------------------------------------------
   2) Handle POSTed login attempts
   - $failed flag controls the error message and HTTP code (401 on failure).
   - We intentionally keep logic minimal; our primary brute-force protection
     will come from AWS WAF (rate limits, CAPTCHA/custom keys).
------------------------------------------------ */
$failed = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  // Sanitize basic inputs (trim spaces; main protection is prepared statements)
  $u = isset($_POST['username']) ? trim((string)$_POST['username']) : '';
  $p = isset($_POST['password']) ? (string)$_POST['password'] : '';

  try {
    /* ----------------------------------------------
       3) Connect to MariaDB via PDO
       - ERRMODE_EXCEPTION so errors throw exceptions (we can catch them).
       - DEFAULT_FETCH_MODE = FETCH_ASSOC for clarity.
       - charset=utf8mb4 to support full Unicode.
    ------------------------------------------------ */
    $dsn = "mysql:host={$DB_HOST};dbname={$DB_NAME};charset=utf8mb4";
    $pdo = new PDO($dsn, $DB_USER, $DB_PASS, [
      PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
      PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);

    /* ----------------------------------------------
       4) Fetch password hash for the given username
       - Prepared statement prevents SQL injection.
       - If user exists, verify with password_verify().
    ------------------------------------------------ */
    $stmt = $pdo->prepare("SELECT passhash FROM users WHERE username = :u LIMIT 1");
    $stmt->execute([':u' => $u]);
    $row = $stmt->fetch();

    $ok = ($row && password_verify($p, $row['passhash']));

    if ($ok) {
      /* ----------------------------------------------
         5) Success: set session and redirect to welcome
         - Session indicates an authenticated user.
         - In real apps, also rotate session ID (session_regenerate_id(true)).
      ------------------------------------------------ */
      $_SESSION['user'] = $u;
      // Optional hardening: session_regenerate_id(true);
      header('Location: /welcome.php', true, 302);
      exit;
    } else {
      /* ----------------------------------------------
         6) Failure: return HTTP 401 (Unauthorized)
         - Useful signal for WAF rules and logging.
         - Do not reveal which field was wrong.
      ------------------------------------------------ */
      http_response_code(401);
      $failed = true;
    }
  } catch (Throwable $e) {
    /* ----------------------------------------------
       7) Database or runtime error
       - Return HTTP 500 to indicate server error.
       - Do not echo $e->getMessage() to users (avoid info leakage).
       - In production, log the error to a file/system logger.
    ------------------------------------------------ */
    http_response_code(500);
    $failed = true;
  }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Login</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <!--
    8) Minimal, clean UI
    - Lightweight CSS (no external dependencies) so the page is portable.
    - Keep it simple; the focus of the research is AWS WAF protections.
  -->
  <style>
    :root {
      --bg:#eef6ff; --card:#fff; --muted:#666; --accent:#0a7cff; --border:#e6e6e6;
      --danger:#c62828; --shadow:0 10px 30px rgba(0,0,0,.08);
    }
    *{box-sizing:border-box}
    body{margin:0;display:grid;place-items:center;min-height:100vh;background:var(--bg);
         font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#111}
    .card{background:var(--card);padding:28px;border-radius:14px;box-shadow:var(--shadow);
          width:100%;max-width:380px;border:1px solid var(--border)}
    h1{margin:0 0 16px}
    label{display:block;margin:10px 0 6px;font-weight:600}
    input{width:100%;padding:10px;border:1px solid #ddd;border-radius:10px}
    button{margin-top:14px;width:100%;padding:12px;border:0;border-radius:10px;
           background:var(--accent);color:#fff;font-weight:700;cursor:pointer}
    .err{color:var(--danger);margin-top:8px}
    .muted{color:var(--muted);font-size:13px;margin-top:10px;line-height:1.5}
    .tips{margin-top:10px;background:#f7fbff;border:1px dashed #cfe7ff;padding:10px;border-radius:10px}
    code{background:#f5f5f5;padding:2px 6px;border-radius:6px}
  </style>
</head>
<body>
  <div class="card">
    <h1>Login</h1>

    <?php if ($failed): ?>
      <!-- 9) Generic error: we do not disclose which field failed -->
      <div class="err">Invalid username or password.</div>
    <?php endif; ?>

    <!--
      10) Basic login form
      - Method POST (credentials are not exposed in the URL).
      - Server-side validation only (client-side can be added if needed).
    -->
    <form method="POST" autocomplete="off">
      <label>Username</label>
      <input name="username" placeholder="admin" required />

      <label>Password</label>
      <input name="password" type="password" placeholder="••••••••" required />

      <button type="submit">Sign in</button>
    </form>

    <!--
      11) Notes for the reader (research/demo context)
      - Explain the role of AWS WAF in protecting this endpoint.
      - Mention that brute-force safeguards are intentionally minimal here,
        because WAF rate-based rules / CAPTCHA / custom keys are the focus.
    -->
    <div class="tips">
      <div class="muted">
        This demo keeps application-side throttling minimal on purpose.
        In the research, we will apply <b>AWS WAF</b> protections on this endpoint
        (<code>/login.php</code>) using rate-based rules, optional CAPTCHA,
        and (if needed) custom keys (e.g., a device/session cookie) to avoid
        penalizing entire NATed networks.
      </div>
    </div>
  </div>
</body>
</html>
