<?php
/**
 * Webhook receiver endpoint
 *   POST ?vault=<id>  — record incoming call to encrypted vault storage
 *   GET  ?vault=<id>  — redirect to viewer UI (index.php)
 */
require_once __DIR__ . '/lib.php';

$method   = $_SERVER['REQUEST_METHOD'];
$vault_id = trim($_GET['vault'] ?? '');

if ($method === 'GET') {
    $target = 'index.php' . ($vault_id ? '?vault=' . urlencode($vault_id) : '');
    header('Location: ' . $target);
    exit;
}

if ($method === 'POST') {
    if (!$vault_id || !wi_valid($vault_id)) {
        http_response_code(400);
        header('Content-Type: text/plain');
        echo 'Bad Request: missing or invalid vault parameter';
        exit;
    }

    wi_cleanup();

    $body_raw  = (string) file_get_contents('php://input');
    $body_json = json_decode($body_raw, true);

    $call = [
        'id'        => bin2hex(random_bytes(8)),
        'timestamp' => gmdate('c'),
        'method'    => $method,
        'url'       => wi_full_url($_SERVER),
        'headers'   => wi_request_headers($_SERVER),
        'body_raw'  => $body_raw,
        'body'      => $body_json !== null ? $body_json : $body_raw,
        'is_json'   => $body_json !== null,
        'auth'      => [
            'username' => $_SERVER['PHP_AUTH_USER'] ?? '',
            'password' => !empty($_SERVER['PHP_AUTH_PW']) ? '***' : '',
        ],
    ];

    $calls  = wi_read_calls($vault_id);
    $cutoff = gmdate('c', time() - WI_MAX_AGE);

    // Remove expired entries and enforce max count
    $calls = array_values(array_filter($calls, function ($c) use ($cutoff) {
        return isset($c['timestamp']) && $c['timestamp'] >= $cutoff;
    }));
    array_unshift($calls, $call);
    $calls = array_slice($calls, 0, WI_MAX_CALLS);

    wi_write_calls($vault_id, $calls);

    http_response_code(200);
    header('Content-Type: text/plain');
    echo 'OK';
    exit;
}

http_response_code(405);
header('Allow: GET, POST');
echo 'Method Not Allowed';
