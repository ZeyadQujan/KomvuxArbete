<?php
session_start();

// Guard: only logged-in users
if (!isset($_SESSION['user'])) {
  header('Location: /login.php');
  exit;
}

// CSRF token
if (empty($_SESSION['csrf'])) {
  $_SESSION['csrf'] = bin2hex(random_bytes(16));
}
$csrf = $_SESSION['csrf'];

// ---- Helpers ----
function f2b_status($jail) {
  $allowed = ['weblogin','weblogin-24h'];
  if (!in_array($jail, $allowed, true)) return '';
  $cmd = "sudo /usr/bin/fail2ban-client status " . escapeshellarg($jail);
  return shell_exec($cmd . " 2>&1") ?: '';
}
function parse_banned($statusText) {
  $ips = [];
  foreach (explode("\n", $statusText) as $line) {
    if (stripos($line, 'Banned IP list:') !== false) {
      [, $v] = array_pad(explode(':', $line, 2), 2, '');
      $v = trim($v);
      if ($v !== '') {
        foreach (preg_split('/\s+/', $v) as $ip) {
          $ip = trim($ip, ", ");
          if ($ip !== '') $ips[] = $ip;
        }
      }
    }
  }
  return $ips;
}
function parse_counters($statusText) {
  $c = ['cur_failed'=>0,'tot_failed'=>0,'cur_banned'=>0,'tot_banned'=>0];
  foreach (explode("\n", $statusText) as $line) {
    if (stripos($line, 'Currently failed:') !== false) {
      $c['cur_failed'] = (int)filter_var($line, FILTER_SANITIZE_NUMBER_INT);
    } elseif (stripos($line, 'Total failed:') !== false) {
      $c['tot_failed'] = (int)filter_var($line, FILTER_SANITIZE_NUMBER_INT);
    } elseif (stripos($line, 'Currently banned:') !== false) {
      $c['cur_banned'] = (int)filter_var($line, FILTER_SANITIZE_NUMBER_INT);
    } elseif (stripos($line, 'Total banned:') !== false) {
      $c['tot_banned'] = (int)filter_var($line, FILTER_SANITIZE_NUMBER_INT);
    }
  }
  return $c;
}

// ---- Unban from ALL jails ----
$unban_msg = '';
$ALL_JAILS = ['weblogin','weblogin-24h'];

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'unban') {
  if (!hash_equals($_SESSION['csrf'], $_POST['csrf'] ?? '')) {
    $unban_msg = 'Invalid CSRF token.';
  } else {
    $ip = $_POST['ip'] ?? '';
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
      $unban_msg = 'Invalid IP address.';
    } else {
      $results = [];
      foreach ($ALL_JAILS as $jail) {
        $cmd = 'sudo /usr/local/sbin/f2b-unban.sh ' .
               escapeshellarg($jail) . ' ' . escapeshellarg($ip);
        $out = shell_exec($cmd . ' 2>&1');
        $results[] = $jail . ': ' . trim($out ?: 'Done');
      }
      $unban_msg = htmlspecialchars(implode(' | ', $results), ENT_QUOTES, 'UTF-8');
    }
  }
}

// ---- Fetch statuses ----
$st_short = f2b_status('weblogin');
$st_long  = f2b_status('weblogin-24h');

$ban_short = parse_banned($st_short);
$ban_long  = parse_banned($st_long);
$c_short   = parse_counters($st_short);
$c_long    = parse_counters($st_long);

$user = htmlspecialchars($_SESSION['user'], ENT_QUOTES, 'UTF-8');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Admin Dashboard</title>
<style>
  :root{
    --bg:#eef6ff; --card:#fff; --muted:#667085; --accent:#0a7cff; --border:#eaeaea;
    --shadow:0 8px 26px rgba(0,0,0,.08);
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;color:#111}
  .layout{display:grid; grid-template-columns: 320px 1fr; gap:18px; padding:24px; max-width:1200px; margin:0 auto}
  .card{background:var(--card); border-radius:16px; box-shadow:var(--shadow); border:1px solid var(--border)}
  .sidebar{position:sticky; top:24px; height:fit-content}
  .header{padding:20px; text-align:center}
  .title{margin:0; font-size:28px}
  .muted{color:var(--muted); font-size:14px; margin-top:6px}
  .section{padding:18px 18px 6px}
  .section h3{margin:0 0 10px; font-size:16px}
  .kpis{display:grid; grid-template-columns: repeat(2, minmax(120px,1fr)); gap:10px}
  .kpi{background:#f6f9ff; border:1px solid var(--border); border-radius:12px; padding:12px}
  .kpi b{display:block; font-size:20px}
  .list{max-height:220px; overflow:auto; border:1px solid var(--border); border-radius:12px; padding:8px; background:#fcfdff}
  .list table{width:100%; border-collapse:collapse}
  .list th,.list td{padding:8px; border-bottom:1px solid #f0f0f0; text-align:left; font-size:14px}
  .content{display:grid; gap:18px}
  .content .card{padding:20px}
  .btn{display:inline-block; padding:10px 14px; border-radius:10px; border:0; background:var(--accent); color:#fff; font-weight:700; cursor:pointer}
  .btn.outline{background:#fff; color:var(--accent); border:1px solid var(--accent)}
  .row{display:flex; gap:10px; flex-wrap:wrap}
  input,select{padding:10px; border:1px solid var(--border); border-radius:10px; width:100%}
  .grid-actions{display:grid; grid-template-columns: repeat(auto-fit, minmax(220px,1fr)); gap:12px}
  .msg{margin-top:8px; color:var(--accent)}
  .label{font-size:13px; color:var(--muted); margin-bottom:6px}
  .pill{display:inline-block; padding:2px 8px; border-radius:999px; background:#eef3ff; color:#2a4bff; font-size:12px; border:1px solid #dfe7ff}
</style>
</head>
<body>

<div class="layout">
  <!-- Sidebar: Fail2Ban Panel -->
  <aside class="card sidebar">
    <div class="header">
      <h1 class="title">Welcome, <?php echo $user; ?> 👋</h1>
      <div class="muted">Fail2Ban overview</div>
    </div>

    <div class="section">
      <h3>Short jail <span class="pill">weblogin</span></h3>
      <div class="kpis">
        <div class="kpi"><span>Currently failed</span><b><?php echo $c_short['cur_failed']; ?></b></div>
        <div class="kpi"><span>Total failed</span><b><?php echo $c_short['tot_failed']; ?></b></div>
        <div class="kpi"><span>Currently banned</span><b><?php echo $c_short['cur_banned']; ?></b></div>
        <div class="kpi"><span>Total banned</span><b><?php echo $c_short['tot_banned']; ?></b></div>
      </div>
      <div class="label">Banned IPs (short)</div>
      <div class="list">
        <?php if ($ban_short): ?>
          <table>
            <tr><th>#</th><th>IP</th></tr>
            <?php foreach ($ban_short as $i=>$ip): ?>
              <tr><td><?php echo $i+1; ?></td><td><?php echo htmlspecialchars($ip, ENT_QUOTES, 'UTF-8'); ?></td></tr>
            <?php endforeach; ?>
          </table>
        <?php else: ?>
          <div class="muted">No IPs banned in short jail.</div>
        <?php endif; ?>
      </div>
    </div>

    <div class="section" style="padding-bottom:18px">
      <h3>Long jail <span class="pill">weblogin-24h</span></h3>
      <div class="kpis">
        <div class="kpi"><span>Currently failed</span><b><?php echo $c_long['cur_failed']; ?></b></div>
        <div class="kpi"><span>Total failed</span><b><?php echo $c_long['tot_failed']; ?></b></div>
        <div class="kpi"><span>Currently banned</span><b><?php echo $c_long['cur_banned']; ?></b></div>
        <div class="kpi"><span>Total banned</span><b><?php echo $c_long['tot_banned']; ?></b></div>
      </div>
      <div class="label">Banned IPs (24h)</div>
      <div class="list">
        <?php if ($ban_long): ?>
          <table>
            <tr><th>#</th><th>IP</th></tr>
            <?php foreach ($ban_long as $i=>$ip): ?>
              <tr><td><?php echo $i+1; ?></td><td><?php echo htmlspecialchars($ip, ENT_QUOTES, 'UTF-8'); ?></td></tr>
            <?php endforeach; ?>
          </table>
        <?php else: ?>
          <div class="muted">No IPs banned in long jail.</div>
        <?php endif; ?>
      </div>
    </div>
  </aside>

  <!-- Main content: Admin actions (pretty placeholders + unban) -->
  <main class="content">
    <div class="card">
      <h2 style="margin-top:0">Admin quick actions</h2>
      <div class="grid-actions">
        <button class="btn outline" disabled title="Coming soon">➕ Create user</button>
        <button class="btn outline" disabled title="Coming soon">🔐 Rotate DB password</button>
        <button class="btn outline" disabled title="Coming soon">🧹 Purge old logs</button>
        <button class="btn outline" disabled title="Coming soon">📦 Backup database</button>
      </div>
      <p class="muted" style="margin-top:8px">These are placeholders for demo aesthetics — we can implement them later.</p>
    </div>

    <div class="card">
      <h2 style="margin-top:0">Unban an IP (all jails)</h2>
      <?php if ($unban_msg): ?><div class="msg"><?php echo $unban_msg; ?></div><?php endif; ?>
      <form method="POST" class="row" style="align-items:flex-end">
        <input type="hidden" name="csrf" value="<?php echo htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8'); ?>">
        <input type="hidden" name="action" value="unban">
        <div style="flex:2 1 260px">
          <div class="label">IP address (IPv4)</div>
          <input name="ip" placeholder="e.g. 203.0.113.7" required>
        </div>
        <div style="flex:0 0 auto">
          <button type="submit" class="btn">Unban from all</button>
        </div>
      </form>
      <p class="muted">This will remove the IP from both <code>weblogin</code> and <code>weblogin-24h</code> using a sudo-protected wrapper script.</p>
    </div>

    <div class="card">
      <h2 style="margin-top:0">About this demo</h2>
      <p class="muted">
        Short jail: 3 failed logins within 60s → 2 min ban. |
        Long jail: 10 failed logins within 24h → 7 days ban.
      </p>
      <p class="muted">We can add auto-refresh (AJAX) later so stats update without reloading the page.</p>
    </div>
  </main>
</div>

</body>
</html>
