<?php
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();
require_once __DIR__ . '/lib.php';

$form_error = '';

// Handle form POSTs
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action   = $_POST['action'] ?? '';
    $vault_id = trim($_POST['vault'] ?? '');

    if ($action === 'new') {
        if (!wi_check_rate_limit()) {
            $form_error = 'Too many attempts from your IP address. Please wait a moment before trying again.';
        } else {
            $_SESSION['vault_id'] = bin2hex(random_bytes(16));
            $_SESSION['started']  = time();
            header('Location: index.php');
            exit;
        }
    }

    if ($action === 'open') {
        if (!wi_valid($vault_id)) {
            $form_error = 'Invalid vault ID. Enter the 32-character hex ID from your saved vault URL.';
        } else {
            $_SESSION['vault_id'] = $vault_id;
            $_SESSION['started']  = $_SESSION['started'] ?? time();
            header('Location: index.php');
            exit;
        }
    }

    if ($action === 'close') {
        session_destroy();
        header('Location: index.php');
        exit;
    }

    if ($action === 'delete') {
        $sid = $_SESSION['vault_id'] ?? '';
        if ($sid && wi_valid($sid)) {
            wi_delete_vault($sid);
        }
        session_destroy();
        header('Location: index.php?notice=deleted');
        exit;
    }
}

// JSON API for live refresh (GET ?api=calls — reads vault from session)
if (isset($_GET['api']) && $_GET['api'] === 'calls') {
    $sid = $_SESSION['vault_id'] ?? '';
    if ($sid && wi_valid($sid)) {
        wi_cleanup();
        header('Content-Type: application/json');
        echo json_encode(wi_read_calls($sid));
    } else {
        http_response_code(400);
        echo '[]';
    }
    exit;
}

// Load vault data
$vault_id  = $_SESSION['vault_id'] ?? '';
$has_vault = $vault_id && wi_valid($vault_id);
$calls     = [];
$notice    = $_GET['notice'] ?? '';

if ($has_vault) {
    wi_cleanup();
    $calls = wi_read_calls($vault_id);
}

$webhook_url     = WI_WEBHOOK_URL . ($has_vault ? '?vault=' . urlencode($vault_id) : '');
$call_count      = count($calls);
$session_started = isset($_SESSION['started'])
    ? gmdate('d M Y, H:i:s', $_SESSION['started']) . ' UTC'
    : '';

// Helper: safe HTML output
function h(string $s): string {
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// Helper: format UTC timestamp for display
function fmt_ts(string $ts): string {
    $d = new DateTime($ts, new DateTimeZone('UTC'));
    return $d->format('d M Y, H:i:s') . ' UTC';
}

function method_color(string $m): string {
    switch (strtoupper($m)) {
        case 'POST':   return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200';
        case 'GET':    return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200';
        case 'PUT':    return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200';
        case 'DELETE': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200';
        case 'PATCH':  return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200';
        default:       return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Maileon Webhook Inspector</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = { darkMode: 'class' };
    </script>
    <style>
        body { font-family: 'Inter', system-ui, -apple-system, sans-serif; }
        .transition-all-200 { transition: all 0.2s ease; }
        pre { white-space: pre-wrap; word-break: break-all; }
        .vault-id-mask { letter-spacing: 0.08em; font-family: monospace; }
        .copy-btn:active { transform: scale(0.95); }
        details > summary { cursor: pointer; list-style: none; }
        details > summary::-webkit-details-marker { display: none; }
        details[open] .chevron { transform: rotate(180deg); }
        .chevron { transition: transform 0.2s ease; }
        .call-body { animation: slideDown 0.2s ease; }
        @keyframes slideDown {
            from { opacity: 0; transform: translateY(-4px); }
            to   { opacity: 1; transform: translateY(0); }
        }
        .json-key    { color: #7c3aed; }
        .json-string { color: #059669; }
        .json-number { color: #d97706; }
        .json-bool   { color: #2563eb; }
        .json-null   { color: #6b7280; }
        .dark .json-key    { color: #a78bfa; }
        .dark .json-string { color: #34d399; }
        .dark .json-number { color: #fbbf24; }
        .dark .json-bool   { color: #60a5fa; }
        .dark .json-null   { color: #9ca3af; }
    </style>
</head>
<body class="bg-gray-50 dark:bg-gray-950 text-gray-900 dark:text-gray-100 min-h-screen">

<!-- ── Top Nav ─────────────────────────────────────────────────────────── -->
<header class="bg-white dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800 sticky top-0 z-50 shadow-sm">
    <div class="max-w-5xl mx-auto px-4 py-3 flex items-center justify-between gap-4">
        <div class="flex items-center gap-3">
            <svg class="w-7 h-7 text-blue-600 dark:text-blue-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                      d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/>
            </svg>
            <span class="font-semibold text-lg tracking-tight">Maileon Webhook Inspector</span>
        </div>
        <div class="flex items-center gap-2">
            <?php if ($has_vault): ?>
            <form method="post" action="index.php" style="display:inline">
                <input type="hidden" name="action" value="close">
                <button type="submit"
                        class="text-sm px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 hover:bg-gray-100 dark:hover:bg-gray-800 transition-all-200">
                    New session
                </button>
            </form>
            <?php endif; ?>
            <button id="dark-toggle" onclick="toggleDark()"
                    class="p-2 rounded-lg border border-gray-300 dark:border-gray-600 hover:bg-gray-100 dark:hover:bg-gray-800 transition-all-200"
                    title="Toggle dark mode">
                <svg id="icon-sun" class="w-4 h-4 hidden" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" clip-rule="evenodd"/>
                </svg>
                <svg id="icon-moon" class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                    <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z"/>
                </svg>
            </button>
        </div>
    </div>
</header>

<main class="max-w-5xl mx-auto px-4 py-8">

<?php if ($notice === 'deleted'): ?>
<div class="mb-6 px-4 py-3 bg-green-100 dark:bg-green-900/40 border border-green-300 dark:border-green-700 rounded-xl text-green-800 dark:text-green-300 text-sm flex items-center gap-2">
    <svg class="w-4 h-4 shrink-0" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"/></svg>
    All vault data has been permanently deleted.
</div>
<?php endif; ?>

<?php if (!$has_vault): ?>
<!-- ══════════════════════════════════════════════════════════════════════ -->
<!-- LANDING PAGE                                                          -->
<!-- ══════════════════════════════════════════════════════════════════════ -->

<div class="mb-10 text-center">
    <h1 class="text-3xl font-bold tracking-tight mb-3">Inspect Maileon Webhook Calls</h1>
    <p class="text-gray-500 dark:text-gray-400 text-lg max-w-2xl mx-auto">
        A private, encrypted endpoint that captures and displays your Maileon webhook payloads —
        no account required.
    </p>
</div>

<!-- How it works -->
<div class="grid md:grid-cols-4 gap-4 mb-10">
    <?php
    $steps = [
        ['1', 'Generate your vault', 'Click "Generate new vault". A random, unique vault ID is created — this ID is your access key.'],
        ['2', 'Save your vault ID', 'Copy and store your vault ID. You will need it to reopen this vault in a new browser session.'],
        ['3', 'Configure Maileon', 'In your Maileon account go to Settings → Webhooks and paste the generated webhook URL.'],
        ['4', 'Inspect the data', 'Trigger a test event in Maileon and return here to view the captured payload with full headers and body.'],
    ];
    foreach ($steps as [$num, $title, $desc]):
    ?>
    <div class="bg-white dark:bg-gray-900 rounded-2xl p-5 border border-gray-200 dark:border-gray-800 shadow-sm">
        <div class="w-8 h-8 rounded-full bg-blue-600 text-white text-sm font-bold flex items-center justify-center mb-3">
            <?= $num ?>
        </div>
        <h3 class="font-semibold mb-1"><?= h($title) ?></h3>
        <p class="text-sm text-gray-500 dark:text-gray-400"><?= h($desc) ?></p>
    </div>
    <?php endforeach; ?>
</div>

<!-- Maileon webhook screenshot reference -->
<div class="mb-10 bg-white dark:bg-gray-900 rounded-2xl border border-gray-200 dark:border-gray-800 shadow-sm overflow-hidden">
    <div class="px-6 py-4 border-b border-gray-100 dark:border-gray-800">
        <h2 class="font-semibold">Maileon webhook configuration</h2>
        <p class="text-sm text-gray-500 dark:text-gray-400 mt-0.5">Configure the webhook in your Maileon account as shown below.</p>
    </div>
    <div class="p-6">
        <img src="./media/webhook_setup.png" alt="Maileon webhook setup screenshot"
             class="rounded-xl border border-gray-200 dark:border-gray-700 max-w-full mx-auto block shadow">
    </div>
</div>

<!-- Vault actions -->
<div class="bg-white dark:bg-gray-900 rounded-2xl border border-gray-200 dark:border-gray-800 shadow-sm overflow-hidden mb-8">
    <div class="px-6 py-5 border-b border-gray-100 dark:border-gray-800">
        <h2 class="font-semibold text-lg">Get started</h2>
        <p class="text-sm text-gray-500 dark:text-gray-400 mt-0.5">
            Generate a new vault or reopen an existing one using its vault ID.
        </p>
    </div>

    <?php if ($form_error !== ''): ?>
    <div class="mx-6 mt-5 flex gap-2 px-4 py-3 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-xl text-sm text-red-700 dark:text-red-300">
        <svg class="w-4 h-4 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/></svg>
        <?= h($form_error) ?>
    </div>
    <?php endif; ?>

    <div class="px-6 py-5 flex flex-col sm:flex-row gap-6">

        <!-- Generate new vault -->
        <div class="flex-1">
            <h3 class="font-medium mb-1 text-sm">New vault</h3>
            <p class="text-xs text-gray-500 dark:text-gray-400 mb-3">Creates a unique random vault and webhook URL.</p>
            <form method="post" action="index.php">
                <input type="hidden" name="action" value="new">
                <button type="submit"
                        class="w-full sm:w-auto px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium rounded-xl transition-all-200 shadow-sm">
                    Generate new vault →
                </button>
            </form>
        </div>

        <div class="hidden sm:block w-px bg-gray-200 dark:bg-gray-700 self-stretch"></div>
        <div class="block sm:hidden h-px bg-gray-200 dark:bg-gray-700"></div>

        <!-- Open existing vault -->
        <div class="flex-1">
            <h3 class="font-medium mb-1 text-sm">Reopen existing vault</h3>
            <p class="text-xs text-gray-500 dark:text-gray-400 mb-3">Paste the vault ID you saved when you first created it.</p>
            <form method="post" action="index.php">
                <input type="hidden" name="action" value="open">
                <div class="flex gap-2">
                    <input type="text" name="vault" required autocomplete="off" spellcheck="false"
                           placeholder="32-character vault ID"
                           class="flex-1 min-w-0 px-3 py-2.5 rounded-xl border border-gray-300 dark:border-gray-600 bg-gray-50 dark:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-blue-500 dark:focus:ring-blue-400 text-sm font-mono placeholder-gray-400">
                    <button type="submit"
                            class="shrink-0 px-4 py-2.5 bg-gray-800 hover:bg-gray-700 dark:bg-gray-700 dark:hover:bg-gray-600 text-white text-sm font-medium rounded-xl transition-all-200 shadow-sm">
                        Open →
                    </button>
                </div>
            </form>
        </div>

    </div>

    <!-- Privacy notice -->
    <div class="mx-6 mb-5 px-4 py-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-xl text-sm">
        <div class="flex gap-2">
            <svg class="w-4 h-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"/>
            </svg>
            <div class="text-amber-800 dark:text-amber-300">
                <strong>Access &amp; privacy:</strong> Your vault ID is your only credential — <strong>anyone with your vault ID can view your calls</strong>.
                Keep it private and do not include sensitive data in webhook payloads.
                Calls are stored AES-256 encrypted, retained for a maximum of <strong>7 days</strong> (last 5 calls), and can be deleted at any time from within the vault.
            </div>
        </div>
    </div>
</div>

<?php else: ?>
<!-- ══════════════════════════════════════════════════════════════════════ -->
<!-- VAULT VIEWER                                                          -->
<!-- ══════════════════════════════════════════════════════════════════════ -->

<!-- Vault ID save reminder -->
<div class="mb-6 px-4 py-3 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-xl text-sm flex items-start gap-3">
    <svg class="w-4 h-4 text-blue-500 dark:text-blue-400 shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
        <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"/>
    </svg>
    <div class="flex-1 min-w-0">
        <span class="text-blue-800 dark:text-blue-300 font-medium">Save your vault ID</span>
        <span class="text-blue-700 dark:text-blue-400"> — you will need it to reopen this vault in a new browser session.</span>
        <div class="mt-2 flex items-center gap-2">
            <code class="vault-id-mask text-xs bg-white dark:bg-blue-950 border border-blue-200 dark:border-blue-700 px-2 py-1 rounded text-blue-900 dark:text-blue-200 select-all">
                <?= h($vault_id) ?>
            </code>
            <button data-copy="<?= h($vault_id) ?>" onclick="copyText(this.dataset.copy, this)"
                    class="copy-btn text-xs px-2.5 py-1 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-all-200">
                Copy ID
            </button>
        </div>
    </div>
</div>

<!-- Session info bar -->
<div class="bg-white dark:bg-gray-900 rounded-2xl border border-gray-200 dark:border-gray-800 shadow-sm px-5 py-4 mb-6 flex flex-wrap items-center gap-4">
    <?php if ($session_started): ?>
    <div class="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
        <svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                  d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
        Session started: <span class="font-medium text-gray-700 dark:text-gray-300"><?= h($session_started) ?></span>
    </div>
    <div class="w-px h-4 bg-gray-200 dark:bg-gray-700 hidden sm:block"></div>
    <?php endif; ?>
    <div class="text-sm text-gray-500 dark:text-gray-400">
        <?= $call_count ?>/<?= WI_MAX_CALLS ?> calls stored &middot; expires after <?= WI_MAX_AGE / 86400 ?> days
    </div>
    <div class="ml-auto">
        <form method="post" action="index.php" onsubmit="return confirm('Close session? You can reopen it later using your vault ID.');">
            <input type="hidden" name="action" value="close">
            <button type="submit"
                    class="text-sm px-3 py-1.5 rounded-lg text-red-600 dark:text-red-400 border border-red-300 dark:border-red-700 hover:bg-red-50 dark:hover:bg-red-900/30 transition-all-200">
                Close session
            </button>
        </form>
    </div>
</div>

<!-- Webhook URL card -->
<div class="bg-white dark:bg-gray-900 rounded-2xl border border-gray-200 dark:border-gray-800 shadow-sm px-5 py-4 mb-6">
    <div class="flex items-center justify-between mb-3">
        <h2 class="font-semibold text-sm text-gray-700 dark:text-gray-300 uppercase tracking-wide">Your Webhook URL</h2>
        <span class="text-xs text-gray-400 dark:text-gray-500">Configure this in Maileon → Settings → Webhooks</span>
    </div>
    <div class="flex items-center gap-2">
        <code id="webhook-url-display"
              class="flex-1 text-sm bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-xl px-4 py-2.5 text-gray-800 dark:text-gray-200 break-all font-mono">
            <?= h($webhook_url) ?>
        </code>
        <button data-copy="<?= h($webhook_url) ?>" onclick="copyText(this.dataset.copy, this)"
                class="copy-btn shrink-0 px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-xl transition-all-200 shadow-sm font-medium">
            Copy
        </button>
    </div>
</div>

<!-- Calls section -->
<div class="bg-white dark:bg-gray-900 rounded-2xl border border-gray-200 dark:border-gray-800 shadow-sm overflow-hidden mb-6">
    <div class="px-5 py-4 border-b border-gray-100 dark:border-gray-800 flex items-center justify-between">
        <div>
            <h2 class="font-semibold">Recorded Calls</h2>
            <p class="text-sm text-gray-500 dark:text-gray-400 mt-0.5">
                Most recent first
            </p>
        </div>
        <button onclick="refreshCalls()"
                class="text-sm px-3 py-1.5 rounded-lg border border-gray-300 dark:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-800 transition-all-200 flex items-center gap-1.5">
            <svg id="refresh-icon" class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                      d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>
            </svg>
            Refresh
        </button>
    </div>

    <?php if (empty($calls)): ?>
    <div class="px-5 py-12 text-center text-gray-400 dark:text-gray-500">
        <svg class="w-10 h-10 mx-auto mb-3 opacity-40" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
                  d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/>
        </svg>
        <p class="text-sm font-medium mb-1">No calls recorded yet</p>
        <p class="text-xs">Configure the webhook URL in Maileon and trigger a test event.</p>
    </div>
    <?php else: ?>
    <div id="calls-list">
        <?php foreach ($calls as $idx => $call):
            $num      = $idx + 1;
            $ts       = h(fmt_ts($call['timestamp'] ?? ''));
            $method   = strtoupper($call['method'] ?? 'POST');
            $url      = $call['url'] ?? '';
            $headers  = $call['headers'] ?? [];
            $body     = $call['body'] ?? null;
            $body_raw = $call['body_raw'] ?? '';
            $is_json  = $call['is_json'] ?? false;
            $auth     = $call['auth'] ?? [];
            $has_auth = !empty($auth['username']);
            $hcount   = count($headers);
        ?>
        <details class="border-b border-gray-100 dark:border-gray-800 last:border-b-0 group" <?= $idx === 0 ? 'open' : '' ?>>
            <summary class="px-5 py-4 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-all-200 select-none">
                <div class="flex items-center gap-3">
                    <span class="text-xs font-mono text-gray-400 dark:text-gray-500 w-5 text-right shrink-0">#<?= $num ?></span>
                    <span class="text-xs font-bold px-2 py-0.5 rounded-md <?= method_color($method) ?> shrink-0">
                        <?= h($method) ?>
                    </span>
                    <span class="text-sm text-gray-600 dark:text-gray-300"><?= $ts ?></span>
                    <span class="ml-auto flex items-center gap-3">
                        <?php if ($has_auth): ?>
                        <span class="hidden sm:inline-flex items-center gap-1 text-xs text-gray-400 dark:text-gray-500">
                            <svg class="w-3 h-3" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd"/></svg>
                            Auth
                        </span>
                        <?php endif; ?>
                        <span class="hidden sm:inline text-xs text-gray-400 dark:text-gray-500"><?= $hcount ?> headers</span>
                        <svg class="chevron w-4 h-4 text-gray-400 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"/>
                        </svg>
                    </span>
                </div>
                <div class="mt-1.5 ml-8 text-xs text-gray-400 dark:text-gray-500 font-mono truncate" title="<?= h($url) ?>">
                    <?= h($url) ?>
                </div>
            </summary>

            <div class="call-body px-5 pb-5 pt-2 bg-gray-50/60 dark:bg-gray-800/30 border-t border-gray-100 dark:border-gray-800">

                <!-- Request URL -->
                <div class="mb-4">
                    <div class="text-xs font-semibold text-gray-400 dark:text-gray-500 uppercase tracking-wider mb-1.5">Request URL</div>
                    <div class="flex items-start gap-2">
                        <code class="flex-1 text-xs bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg px-3 py-2.5 text-gray-700 dark:text-gray-300 break-all font-mono">
                            <?= h($url) ?>
                        </code>
                        <button data-copy="<?= h($url) ?>" onclick="copyText(this.dataset.copy, this)"
                                class="copy-btn shrink-0 text-xs px-3 py-2.5 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-all-200">
                            Copy
                        </button>
                    </div>
                </div>

                <!-- Headers -->
                <?php if (!empty($headers)): ?>
                <div class="mb-4">
                    <div class="text-xs font-semibold text-gray-400 dark:text-gray-500 uppercase tracking-wider mb-1.5">
                        Headers (<?= $hcount ?>)
                    </div>
                    <div class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
                        <table class="w-full text-xs">
                            <?php foreach ($headers as $hname => $hval): ?>
                            <tr class="border-b border-gray-100 dark:border-gray-800 last:border-b-0 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                                <td class="px-3 py-2 font-medium text-purple-700 dark:text-purple-300 font-mono whitespace-nowrap align-top w-48">
                                    <?= h($hname) ?>
                                </td>
                                <td class="px-3 py-2 text-gray-600 dark:text-gray-400 font-mono break-all">
                                    <?= h($hval) ?>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </table>
                    </div>
                </div>
                <?php endif; ?>

                <!-- Body -->
                <div class="mb-4">
                    <div class="text-xs font-semibold text-gray-400 dark:text-gray-500 uppercase tracking-wider mb-1.5 flex items-center gap-2">
                        Body
                        <?php if ($is_json): ?>
                        <span class="px-1.5 py-0.5 bg-green-100 dark:bg-green-900/40 text-green-700 dark:text-green-300 rounded text-xs">JSON</span>
                        <?php elseif ($body_raw !== ''): ?>
                        <span class="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-800 text-gray-500 rounded text-xs">Raw</span>
                        <?php endif; ?>
                    </div>
                    <?php if ($body_raw === '' || $body_raw === null): ?>
                    <p class="text-xs text-gray-400 dark:text-gray-500 italic">Empty body</p>
                    <?php else: ?>
                    <div class="relative">
                        <pre id="body-<?= $idx ?>" class="text-xs bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg px-4 py-3 text-gray-700 dark:text-gray-300 overflow-auto max-h-80 leading-relaxed"><?php
                            if ($is_json) {
                                echo h(json_encode($body, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
                            } else {
                                echo h($body_raw);
                            }
                        ?></pre>
                        <button onclick="copyText(document.getElementById('body-<?= $idx ?>').textContent.trim(), this)"
                                class="copy-btn absolute top-2 right-2 text-xs px-2 py-1 bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded hover:bg-gray-200 dark:hover:bg-gray-700 transition-all-200">
                            Copy
                        </button>
                    </div>
                    <?php endif; ?>
                </div>

                <!-- Auth -->
                <?php if ($has_auth): ?>
                <div>
                    <div class="text-xs font-semibold text-gray-400 dark:text-gray-500 uppercase tracking-wider mb-1.5">Basic Auth</div>
                    <div class="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg px-3 py-2.5 text-xs font-mono">
                        <span class="text-purple-700 dark:text-purple-300">Username:</span>
                        <span class="ml-2 text-gray-700 dark:text-gray-300"><?= h($auth['username']) ?></span>
                        <span class="mx-3 text-gray-300 dark:text-gray-600">|</span>
                        <span class="text-purple-700 dark:text-purple-300">Password:</span>
                        <span class="ml-2 text-gray-400 dark:text-gray-500"><?= h($auth['password'] ?: '(none)') ?></span>
                    </div>
                </div>
                <?php endif; ?>

            </div>
        </details>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>
</div>

<!-- Danger zone -->
<div class="bg-white dark:bg-gray-900 rounded-2xl border border-red-200 dark:border-red-900 shadow-sm px-5 py-4">
    <h3 class="font-semibold text-sm text-red-700 dark:text-red-400 mb-1">Danger zone</h3>
    <p class="text-sm text-gray-500 dark:text-gray-400 mb-3">
        Permanently delete all recorded calls for this vault and close the session. This cannot be undone.
    </p>
    <form method="post" action="index.php" onsubmit="return confirm('Delete ALL recorded calls for this vault? This cannot be undone.');">
        <input type="hidden" name="action" value="delete">
        <button type="submit"
                class="text-sm px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-xl transition-all-200 font-medium">
            Delete all data
        </button>
    </form>
</div>

<?php endif; ?>
</main>

<!-- Footer -->
<footer class="mt-12 py-6 border-t border-gray-200 dark:border-gray-800 text-center text-xs text-gray-400 dark:text-gray-600">
    Maileon Webhook Inspector &copy; XQueue GmbH
</footer>

<script>
// ─── Dark mode ───────────────────────────────────────────────────────────────
function applyDark(dark) {
    document.documentElement.classList.toggle('dark', dark);
    document.getElementById('icon-sun').classList.toggle('hidden', !dark);
    document.getElementById('icon-moon').classList.toggle('hidden', dark);
}
function toggleDark() {
    const dark = !document.documentElement.classList.contains('dark');
    localStorage.setItem('wi_dark', dark ? '1' : '0');
    applyDark(dark);
}
(function() {
    const pref = localStorage.getItem('wi_dark');
    const sysDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    applyDark(pref !== null ? pref === '1' : sysDark);
})();

// ─── Copy to clipboard ────────────────────────────────────────────────────────
function copyText(text, btn) {
    navigator.clipboard.writeText(text).then(function() {
        var orig = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(function() { btn.textContent = orig; }, 1500);
    });
}

<?php if ($has_vault): ?>
// ─── Refresh ─────────────────────────────────────────────────────────────────
function refreshCalls() {
    var icon = document.getElementById('refresh-icon');
    icon.style.animation = 'spin 0.6s linear infinite';
    if (!icon.style.getPropertyValue('animation').includes('spin')) {
        var style = document.createElement('style');
        style.textContent = '@keyframes spin { to { transform: rotate(360deg); } }';
        document.head.appendChild(style);
    }
    setTimeout(function() { window.location.reload(); }, 200);
}
<?php endif; ?>
</script>
</body>
</html>
