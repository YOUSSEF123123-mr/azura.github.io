<?php // تأكد من أن هذا هو السطر الأول بدون أي مسافات أو أسطر فارغة قبله
// security.php - ملف حماية شامل لتأمين الصفحات

// 1. تفعيل إعدادات الأمان العامة لـ PHP
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/database/logs/php_errors.log');
ini_set('expose_php', '0');
ini_set('allow_url_fopen', '0');
ini_set('allow_url_include', '0');

// 2. إعدادات الجلسة (Session) للحماية من Session Hijacking
ini_set('session.use_strict_mode', '1');
ini_set('session.cookie_httponly', '1');
// ini_set('session.cookie_secure', '1'); // تفعيل مع HTTPS
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.gc_maxlifetime', 1800);

// بدء الجلسة بأمان، مع التحقق من عدم بدئها مسبقًا
if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_lifetime' => 1800,
        'read_and_close' => false,
        'use_cookies' => 1,
        'use_only_cookies' => 1,
    ]);
}

// 3. دالة لتسجيل الأخطاء
function logSecurityEvent($message, $type = 'Security') {
    $logDir = __DIR__ . '/database/logs';
    $logFile = $logDir . '/security.log';
    $currentTime = date("Y-m-d H:i:s", time());

    if (!is_dir($logDir)) {
        if (!mkdir($logDir, 0755, true) || !is_writable($logDir)) {
            error_log("Failed to create or write to log directory: $logDir");
            return;
        }
    }

    if (!file_exists($logFile)) {
        if (!touch($logFile) || !chmod($logFile, 0644)) {
            error_log("Failed to create or set permissions for log file: $logFile");
            return;
        }
    }

    $entry = "[$currentTime] [$type] $message | IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'Unknown') .
             " | User-Agent: " . ($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown') . "\n";

    if (!file_put_contents($logFile, $entry, FILE_APPEND)) {
        error_log("Failed to write to security log: $logFile");
    }
}

// 4. حماية ضد CSRF
function generateCsrfToken() {
    if (empty($_SESSION['csrf_token']) || !isset($_SESSION['csrf_token_time']) || (time() - $_SESSION['csrf_token_time']) > 3600) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $_SESSION['csrf_token_time'] = time();
    }
    return $_SESSION['csrf_token'];
}

function validateCsrfToken($token) {
    if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        logSecurityEvent("CSRF token validation failed | Provided: " . ($token ?? 'None'), 'CSRF Alert');
        http_response_code(403);
        exit("403 - Forbidden: Invalid CSRF token");
    }
    unset($_SESSION['csrf_token'], $_SESSION['csrf_token_time']);
    generateCsrfToken();
}

// 5. حماية ضد Brute Force
function enforceBruteForceProtection($maxAttempts = 5, $lockoutTime = 300) {
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    $attemptKey = "login_attempts_" . hash('sha256', $clientIp);

    if (!isset($_SESSION[$attemptKey]) || !is_array($_SESSION[$attemptKey])) {
        $_SESSION[$attemptKey] = ['count' => 0, 'last_attempt' => 0];
    }

    if (!is_int($_SESSION[$attemptKey]['last_attempt']) || !is_int($_SESSION[$attemptKey]['count'])) {
        logSecurityEvent("Invalid Brute Force session data detected", 'Brute Force Alert');
        $_SESSION[$attemptKey] = ['count' => 1, 'last_attempt' => time()];
        return function () use ($attemptKey) {};
    }

    if ($_SESSION[$attemptKey]['count'] >= $maxAttempts) {
        $timeSinceLastAttempt = time() - $_SESSION[$attemptKey]['last_attempt'];
        if ($timeSinceLastAttempt < $lockoutTime) {
            logSecurityEvent("Brute force lockout triggered | Attempts: {$_SESSION[$attemptKey]['count']}", 'Brute Force Alert');
            http_response_code(429);
            exit("429 - Too Many Requests: Try again in " . ceil(($lockoutTime - $timeSinceLastAttempt) / 60) . " minutes.");
        } else {
            $_SESSION[$attemptKey] = ['count' => 0, 'last_attempt' => 0];
        }
    }

    return function () use ($attemptKey) {
        $_SESSION[$attemptKey]['count'] = min($_SESSION[$attemptKey]['count'] + 1, PHP_INT_MAX);
        $_SESSION[$attemptKey]['last_attempt'] = time();
    };
}

// 6. تنظيف المدخلات
function sanitizeInput($input) {
    if (is_array($input)) {
        return array_map(__FUNCTION__, $input);
    }
    if (!is_string($input)) {
        return '';
    }
    $input = trim($input);
    $input = htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8', false);
    $input = strip_tags($input);
    return $input;
}

// 7. التحقق من طريقة الطلب
function enforceRequestMethod($allowedMethod = 'POST') {
    $allowedMethod = strtoupper($allowedMethod);
    if ($_SERVER['REQUEST_METHOD'] !== $allowedMethod) {
        logSecurityEvent("Invalid request method: {$_SERVER['REQUEST_METHOD']} | Expected: $allowedMethod", 'Request Alert');
        http_response_code(405);
        header("Allow: $allowedMethod");
        exit("405 - Method Not Allowed");
    }
}

// 8. حماية الرؤوس
function secureHeaders() {
    header("X-Content-Type-Options: nosniff");
    header("X-Frame-Options: DENY");
    header("X-XSS-Protection: 1; mode=block");
    // header("Strict-Transport-Security: max-age=31536000; includeSubDomains"); // تفعيل مع HTTPS
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; base-uri 'self'; form-action 'self'");
    header("Referrer-Policy: strict-origin-when-cross-origin");
    header_remove("X-Powered-By");
    header("Cache-Control: no-store, no-cache, must-revalidate");
    header("Pragma: no-cache");
}

// 9. حماية الملفات الحساسة
function protectSensitiveFiles($directory) {
    if (!is_dir($directory)) {
        if (!mkdir($directory, 0755, true) || !is_writable($directory)) {
            logSecurityEvent("Failed to create sensitive directory: $directory", 'File Protection Alert');
            return;
        }
    }

    $htaccessFile = "$directory/.htaccess";
    if (!file_exists($htaccessFile)) {
        $htaccessContent = "Deny from all\nOptions -Indexes";
        if (!@file_put_contents($htaccessFile, $htaccessContent)) {
            logSecurityEvent("Failed to create .htaccess in: $directory", 'File Protection Alert');
        }
    }

    $indexFile = "$directory/index.php";
    if (!file_exists($indexFile)) {
        $indexContent = "<?php\nheader('HTTP/1.1 403 Forbidden');\nheader('Content-Type: text/plain');\necho 'Access Denied';\nexit;";
        if (!@file_put_contents($indexFile, $indexContent)) {
            logSecurityEvent("Failed to create index.php in: $directory", 'File Protection Alert');
        }
    }
}

// 10. تفعيل الحماية
function initializeSecurity($allowedMethod = 'POST', $maxAttempts = 5, $lockoutTime = 300, $dbDir = 'database/accounts') {
    logSecurityEvent("Security initialization started", 'Initialization');
    secureHeaders();
    enforceRequestMethod($allowedMethod);
    $incrementAttempts = enforceBruteForceProtection(max(1, (int)$maxAttempts), max(60, (int)$lockoutTime));
    protectSensitiveFiles($dbDir);
    generateCsrfToken();

    return [
        'incrementAttempts' => $incrementAttempts,
        'csrfToken' => $_SESSION['csrf_token']
    ];
}