<?php
/**
 * Admin-style welcome/dashboard page (UI-only changes).
 * - Keeps the same auth/session/redirect/logout logic as before.
 * - No changes to security-sensitive behavior.
 */

declare(strict_types=1);

session_start();

/* 1) Guard: only allow access if the user is logged in */
if (!isset($_SESSION['user'])) {
  header('Location: /login.php', true, 302);
  exit;
}

$user = htmlspecialchars((string)$_SESSION['user'], ENT_QUOTES, 'UTF-8');

/* 2) Handle logout (simple GET action) */
if (isset($_GET['action']) && $_GET['action'] === 'logout') {
  $_SESSION = [];
  if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
  }
  session_destroy();
  header('Location: /login.php', true, 302);
  exit;
}

header('Content-Type: text/html; charset=UTF-8');
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Admin Panel</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <!--
    UI-only facelift:
    - Top navbar with user + logout
    - Sidebar navigation (placeholders)
    - Stats cards (placeholders)
    - Recent activity table (placeholder)
    No external CSS/JS; pure CSS for portability.
  -->
  <style>
    :root{
      --bg:#f5f7fb; --panel:#ffffff; --border:#e7e9f0; --muted:#667085;
      --ink:#0f172a; --accent:#0a7cff; --accent-ink:#0a58ca; --success:#12b886; --warn:#f59f00; --danger:#e03131;
      --shadow:0 10px 30px rgba(16,24,40,.06);
    }
    *{box-sizing:border-box}
    html,body{height:100%}
    body{
      margin:0; background:var(--bg); color:var(--ink);
      font:14px/1.5 system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
      display:grid; grid-template-rows:auto 1fr;
    }

    /* Top navbar */
    .topbar{
      background:#fff; border-bottom:1px solid var(--border); box-shadow:var(--shadow);
      display:flex; align-items:center; justify-content:space-between; padding:10px 16px;
      position:sticky; top:0; z-index:50;
    }
    .brand{display:flex; align-items:center; gap:10px; font-weight:800; letter-spacing:.2px}
    .brand .dot{width:10px;height:10px;border-radius:50%;background:var(--accent);display:inline-block}
    .userbar{display:flex; align-items:center; gap:8px}
    .userpill{background:#eef6ff;border:1px solid #d9e9ff;color:#12428f;padding:6px 10px;border-radius:999px;font-weight:600}
    .logout{
      text-decoration:none; background:var(--accent); color:#fff; padding:8px 12px; border-radius:10px;
      border:1px solid transparent; font-weight:700;
    }
    .logout:hover{background:var(--accent-ink)}

    /* Layout: sidebar + main */
    .shell{
      display:grid; grid-template-columns:260px 1fr; gap:18px; padding:18px; align-items:start;
    }
    @media (max-width: 900px){
      .shell{grid-template-columns:1fr}
      .sidebar{position:static;width:auto}
    }

    /* Sidebar */
    .sidebar{
      background:var(--panel); border:1px solid var(--border); border-radius:14px; box-shadow:var(--shadow);
      padding:14px; position:sticky; top:72px;
    }
    .navsec{margin-top:8px}
    .navsec h4{margin:10px 8px; color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.6px}
    .nav{display:grid; gap:6px; list-style:none; padding:0; margin:0}
    .nav a{
      display:flex; align-items:center; gap:8px; padding:10px 12px; border-radius:10px; color:var(--ink);
      text-decoration:none; border:1px solid transparent;
    }
    .nav a.active{background:#eef6ff; border-color:#d9e9ff; color:#12428f; font-weight:700}
    .nav a:hover{background:#f6f9ff}

    /* Main content */
    .main{
      display:grid; gap:18px;
    }

    /* Hero card */
    .hero{
      background:linear-gradient(180deg,#ffffff 0%, #fafdff 100%);
      border:1px solid var(--border); border-radius:14px; box-shadow:var(--shadow); padding:18px;
      display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap;
    }
    .hero h1{margin:0; font-size:22px}
    .muted{color:var(--muted)}

    /* Stat cards */
    .stats{display:grid; grid-template-columns:repeat(4,1fr); gap:12px}
    @media (max-width: 1100px){ .stats{grid-template-columns:repeat(2,1fr)} }
    @media (max-width: 560px){ .stats{grid-template-columns:1fr} }
    .card{
      background:var(--panel); border:1px solid var(--border); border-radius:14px; box-shadow:var(--shadow); padding:14px;
    }
    .kpi{display:flex; align-items:flex-end; justify-content:space-between}
    .kpi h3{margin:0 0 6px; font-size:13px; color:var(--muted); letter-spacing:.2px}
    .kpi .num{font-size:26px; font-weight:800}
    .tag{font-size:12px; padding:2px 8px; border-radius:8px; background:#f6f9ff; border:1px solid #e6efff; color:#12428f}

    /* Table */
    .tablecard .head{display:flex; align-items:center; justify-content:space-between; margin-bottom:8px}
    table{width:100%; border-collapse:separate; border-spacing:0; overflow:hidden; border-radius:12px; border:1px solid var(--border)}
    th,td{padding:10px 12px; text-align:left; border-bottom:1px solid var(--border)}
    th{font-size:12px; color:var(--muted); background:#fbfcff}
    tr:last-child td{border-bottom:0}
    .badge{display:inline-block; padding:4px 8px; border-radius:999px; font-size:12px; border:1px solid #e6eaf2}
    .ok{background:#e6fcf5; border-color:#c3f7e7; color:#09694b}
    .warn{background:#fff7e6; border-color:#ffe1a3; color:#7a5200}
    .bad{background:#ffe8e8; border-color:#ffc9c9; color:#7a1a1a}

    /* Small helpers */
    .btn{display:inline-block; padding:8px 12px; border-radius:10px; text-decoration:none; font-weight:700}
    .btn.muted{background:#f2f4f8; border:1px solid var(--border); color:#334}
  </style>
</head>
<body>
  <!-- Top bar -->
  <div class="topbar">
    <div class="brand">
      <span class="dot"></span> Admin Panel
    </div>
    <div class="userbar">
      <span class="userpill">👤 <?php echo $user; ?></span>
      <a class="logout" href="/welcome.php?action=logout" title="Logout">Logout</a>
    </div>
  </div>

  <!-- Shell layout -->
  <div class="shell">
    <!-- Sidebar -->
    <aside class="sidebar">
      <div class="navsec">
        <h4>Navigation</h4>
        <ul class="nav">
          <li><a class="active" href="/welcome.php">Dashboard</a></li>
          <li><a href="/login.php">Login</a></li>
          <!-- Placeholders for future features -->
          <li><a href="#">Users</a></li>
          <li><a href="#">Settings</a></li>
          <li><a href="#">Security</a></li>
        </ul>
      </div>
    </aside>

    <!-- Main -->
    <main class="main">
      <!-- Hero -->
      <section class="hero">
        <div>
          <h1>Welcome, <?php echo $user; ?> 👋</h1>
          <div class="muted">This is a simple admin-style dashboard. Core security demo happens on <code>/login.php</code> with AWS WAF.</div>
        </div>
        <a class="btn muted" href="/login.php">Back to Login</a>
      </section>

      <!-- KPIs -->
      <section class="stats">
        <div class="card">
          <div class="kpi">
            <div>
              <h3>Active Sessions</h3>
              <div class="num">1</div>
            </div>
            <span class="tag">Demo</span>
          </div>
        </div>
        <div class="card">
          <div class="kpi">
            <div>
              <h3>Failed Logins (last min)</h3>
              <div class="num">—</div>
            </div>
            <span class="badge warn">WAF rule</span>
          </div>
        </div>
        <div class="card">
          <div class="kpi">
            <div>
              <h3>CAPTCHA Challenges</h3>
              <div class="num">—</div>
            </div>
            <span class="badge ok">Optional</span>
          </div>
        </div>
        <div class="card">
          <div class="kpi">
            <div>
              <h3>Blocked Sources</h3>
              <div class="num">—</div>
            </div>
            <span class="badge bad">Rate limit</span>
          </div>
        </div>
      </section>

      <!-- Recent activity (placeholder) -->
      <section class="card tablecard">
        <div class="head">
          <h3 style="margin:0">Recent Activity</h3>
          <span class="muted">Sample / demo only</span>
        </div>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Event</th>
              <th>Details</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Just now</td>
              <td>Login</td>
              <td>User <code><?php echo $user; ?></code> signed in</td>
              <td><span class="badge ok">OK</span></td>
            </tr>
            <tr>
              <td>—</td>
              <td>Brute-force check</td>
              <td>Protected by AWS WAF (rate-based rule)</td>
              <td><span class="badge warn">WAF</span></td>
            </tr>
            <tr>
              <td>—</td>
              <td>Security</td>
              <td>Optional CAPTCHA on /login.php</td>
              <td><span class="badge">Info</span></td>
            </tr>
          </tbody>
        </table>
      </section>
    </main>
  </div>
</body>
</html>
