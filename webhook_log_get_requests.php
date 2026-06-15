<?php

// THIS HOOK WILL LOG GET REQUESTS, TOO

ini_set('display_errors',1);
ini_set('display_startup_errors',1);
error_reporting(-1);

$absolute_url = full_url($_SERVER);
$content = stream_get_contents(detectRequestBody());
$lastUsername = "";
$lastPassword = "";

if (!empty($_SERVER['PHP_AUTH_USER'])) {
	$lastUsername = $_SERVER['PHP_AUTH_USER'];
	$lastPassword = $_SERVER['PHP_AUTH_PW'];
}

// Only save, if some body content has been submitted
$file = 'tmp/lastcall.data';
//if ($_SERVER['REQUEST_METHOD'] == "POST") {
    // When dumping GET requests, make sure to set "" manually
    if (empty($content)) $content="\"\"";
	$content = "{\"lastUrl\": \"$absolute_url\", \"lastContent\": $content, \"lastUsername\": \"$lastUsername\", \"lastPassword\": \"$lastPassword\"}";
	file_put_contents($file, $content);
//}

// Get the body data
function detectRequestBody() {
    $rawInput = fopen('php://input', 'r');
    $tempStream = fopen('php://temp', 'r+');
    stream_copy_to_stream($rawInput, $tempStream);
    rewind($tempStream);
    return $tempStream;
}

function url_origin($s, $use_forwarded_host=false) {
    $ssl = (!empty($s['HTTPS']) && $s['HTTPS'] == 'on') ? true:false;
    $sp = strtolower($s['SERVER_PROTOCOL']);
    $protocol = substr($sp, 0, strpos($sp, '/')) . (($ssl) ? 's' : '');
    $port = $s['SERVER_PORT'];
    $port = ((!$ssl && $port=='80') || ($ssl && $port=='443')) ? '' : ':'.$port;
    $host = ($use_forwarded_host && isset($s['HTTP_X_FORWARDED_HOST'])) ? $s['HTTP_X_FORWARDED_HOST'] : (isset($s['HTTP_HOST']) ? $s['HTTP_HOST'] : null);
    $host = isset($host) ? $host : $s['SERVER_NAME'] . $port;
    return $protocol . '://' . $host;
}

function full_url($s, $use_forwarded_host=false) {
    return url_origin($s, $use_forwarded_host) . $s['REQUEST_URI'];
}


// Show last logged entry
$content = json_decode(file_get_contents($file));
$lastUrl = $content->lastUrl;
$lastContent = $content->lastContent;
$lastUsername = $content->lastUsername;
$lastPassword = $content->lastPassword;

?>

<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
    <link rel="stylesheet" type="text/css" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/css/bootstrap.min.css">
	<link rel="stylesheet" type="text/css" href="https://code.jquery.com/ui/1.11.4/themes/smoothness/jquery-ui.css">
	<style type="text/css">
		input[readonly] {
			background-color: white !important;
		}
		.footer {
			position: fixed;
			font-size: 1em;
			font-family: Arial;
			padding: 2px 5px;
			margin: 0 1%;
			text-align: right;
			
			min-width: 400px;
			width: 98%;
			bottom: 2px;
			color: black;
		}
	</style>
	<script src="https://code.jquery.com/jquery-1.11.3.js"></script>
	<script src="https://code.jquery.com/ui/1.11.4/jquery-ui.min.js"></script>
	<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.5/js/bootstrap.min.js"></script>
    <title>Maileon - Transactions</title>
</head>
<body>
<h1>Example for webhook data</h1>
<div style="margin:20px">
<h2>Setup Maileon</h2>
In your Maileon account create under "Settings - Webhooks" a webhook and configure some data to be sent, like shown in the screenshot.<br />
Then click on the link: <i>"Trigger test event with current configuration"</i><br />
<img src="./media/webhook_setup.png" style="width:50%;margin:auto;margin-top:20px;"/><br /><br />
</div>
<div style="margin:20px;padding-bottom:40px">
<h2>Last recorded call</h2>
Hint: only calls with JSON-body will be recorded!<br /><br />

<div style="width:90%;margin:auto;background-color:#F0F0F0;border-width:1px;border-color:blue;padding:20px">
<b><?=$lastUrl?></b> <br />
<pre><?=json_encode($lastContent, JSON_PRETTY_PRINT);?></pre>

<?php
if (!empty($lastUsername)) {
	echo "<br />Login-Credentials: $lastUsername:*$lastPassword*";
}
?>
</div>
</div>
<div style="width: 100%">
	<div class="footer ui-widget-header">
		Examples 2017 &copy; XQueue GmbH (<a href="./download/webhook_example.zip">Download example</a>)
	</div>
</div>
</body>
</html>