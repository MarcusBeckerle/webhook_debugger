<?php
define('WI_MAX_CALLS',   5);
define('WI_MAX_AGE',     7 * 24 * 3600);
define('WI_VAULTS_DIR',  __DIR__ . '/tmp/vaults/');
define('WI_SECRET_FILE', __DIR__ . '/tmp/server.secret.php');
define('WI_WEBHOOK_URL', 'https://hosting.maileon.com/service/util/webhooks_debugger/webhook.php');

function wi_secret(): string {
    static $s;
    if (isset($s)) return $s;
    if (!file_exists(WI_SECRET_FILE)) {
        $dir = dirname(WI_SECRET_FILE);
        if (!is_dir($dir)) mkdir($dir, 0755, true);
        $s = bin2hex(random_bytes(32));
        file_put_contents(WI_SECRET_FILE, $s, LOCK_EX);
        return $s;
    }
    return ($s = trim(file_get_contents(WI_SECRET_FILE)));
}

function wi_enc_key(string $vault_id): string {
    return hash('sha256', $vault_id . '|enc|' . wi_secret(), true);
}

function wi_encrypt(string $plain, string $vault_id): string {
    $key = wi_enc_key($vault_id);
    $iv  = random_bytes(16);
    $ct  = openssl_encrypt($plain, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $ct);
}

function wi_decrypt(string $b64, string $vault_id): ?string {
    $key = wi_enc_key($vault_id);
    $raw = base64_decode($b64, true);
    if ($raw === false || strlen($raw) < 17) return null;
    $r = openssl_decrypt(substr($raw, 16), 'AES-256-CBC', $key, OPENSSL_RAW_DATA, substr($raw, 0, 16));
    return $r === false ? null : $r;
}

function wi_read_calls(string $vault_id): array {
    $f = WI_VAULTS_DIR . $vault_id . '/calls.php';
    if (!file_exists($f)) return [];
    $raw = file_get_contents($f);
    if (!$raw) return [];
    $json = wi_decrypt($raw, $vault_id);
    if ($json === null) return [];
    $d = json_decode($json, true);
    return is_array($d) ? $d : [];
}

function wi_write_calls(string $vault_id, array $calls): void {
    $dir = WI_VAULTS_DIR . $vault_id . '/';
    if (!is_dir($dir)) mkdir($dir, 0755, true);
    file_put_contents(
        $dir . 'calls.php',
        wi_encrypt(json_encode($calls, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), $vault_id),
        LOCK_EX
    );
}

function wi_delete_vault(string $vault_id): void {
    $f = WI_VAULTS_DIR . $vault_id . '/calls.php';
    if (file_exists($f)) @unlink($f);
    $d = WI_VAULTS_DIR . $vault_id . '/';
    if (is_dir($d)) @rmdir($d);
}

function wi_cleanup(): void {
    if (!is_dir(WI_VAULTS_DIR)) return;
    $cutoff = time() - WI_MAX_AGE;
    $entries = @scandir(WI_VAULTS_DIR);
    if (!$entries) return;
    foreach ($entries as $e) {
        if (!preg_match('/^[a-f0-9]{32}$/', $e)) continue;
        $f = WI_VAULTS_DIR . $e . '/calls.php';
        $d = WI_VAULTS_DIR . $e . '/';
        if (!file_exists($f) || filemtime($f) < $cutoff) {
            if (file_exists($f)) @unlink($f);
            if (is_dir($d)) @rmdir($d);
        }
    }
}

function wi_valid(string $id): bool {
    return (bool) preg_match('/^[a-f0-9]{32}$/', $id);
}

// Rate limit: max 30 vault-open attempts per IP per hour
function wi_check_rate_limit(): bool {
    $ip     = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $dir    = __DIR__ . '/tmp/ratelimit/';
    if (!is_dir($dir)) mkdir($dir, 0755, true);
    $file   = $dir . hash('sha256', $ip) . '.php';
    $now    = time();
    $window = 3600;
    $max    = 30;

    $data = ['count' => 0, 'since' => $now];
    if (file_exists($file)) {
        $raw = json_decode(file_get_contents($file), true);
        if (is_array($raw) && ($now - $raw['since']) < $window) {
            $data = $raw;
        }
    }

    if ($data['count'] >= $max) return false;

    $data['count']++;
    file_put_contents($file, json_encode($data), LOCK_EX);
    return true;
}

function wi_full_url(array $s): string {
    $tls  = !empty($s['HTTPS']) && $s['HTTPS'] !== 'off';
    $host = isset($s['HTTP_HOST']) ? $s['HTTP_HOST'] : $s['SERVER_NAME'];
    return ($tls ? 'https' : 'http') . '://' . $host . ($s['REQUEST_URI'] ?? '/');
}

function wi_request_headers(array $s): array {
    $h = [];
    foreach ($s as $k => $v) {
        if (strpos($k, 'HTTP_') === 0) {
            $name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($k, 5)))));
            if (strtolower($name) === 'authorization') {
                $v = preg_replace('/^(\S+\s+).+/', '$1[REDACTED]', $v);
            }
            $h[$name] = $v;
        } elseif ($k === 'CONTENT_TYPE') {
            $h['Content-Type'] = $v;
        } elseif ($k === 'CONTENT_LENGTH') {
            $h['Content-Length'] = $v;
        }
    }
    ksort($h);
    return $h;
}
