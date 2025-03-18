<?php // تأكد من أن هذا هو السطر الأول بدون أي مسافات أو أسطر فارغة قبله
/**
 * تسجيل الأخطاء في ملف مع تنسيق محسّن يجمع الأحداث حسب التاريخ داخل مجلد database/logs
 *
 * @param string $errorMessage رسالة الخطأ
 * @param string $errorType نوع الخطأ (افتراضي: General)
 * @param ?Throwable $exception استثناء (اختياري)
 * @param array $errorContext سياق إضافي للخطأ (اختياري)
 * @return void
 */
function logError(string $errorMessage, string $errorType = 'General', ?Throwable $exception = null, array $errorContext = []): void {
    // تحديد مسار مجلد السجلات داخل database
    $logDir = __DIR__ . '/database/logs';
    $logFile = $logDir . '/errors.log';

    // الحصول على الوقت الحالي وعنوان IP وUser-Agent
    $currentTime = date("Y-m-d H:i:s");
    $dateOnly = date("Y-m-d"); // التاريخ فقط (بدون الوقت)
    $timeOnly = date("H:i:s"); // الوقت فقط
    $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';

    // قراءة المحتوى الحالي لتحديد آخر تاريخ مسجل
    $lastDate = null;
    if (file_exists($logFile) && filesize($logFile) > 0) {
        $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines) {
            foreach (array_reverse($lines) as $line) {
                if (preg_match('/^=== Date: (\d{4}-\d{2}-\d{2}) ===/', $line, $matches)) {
                    $lastDate = $matches[1];
                    break;
                }
            }
        }
    }

    // إعداد الإدخال مع تنسيق محسّن
    $logEntry = '';
    if ($lastDate !== $dateOnly) {
        $logEntry .= "\n=== Date: $dateOnly ===\n";
    }

    $logEntry .= "---- Event at $timeOnly ----\n";
    $logEntry .= "  Type: $errorType\n";
    $logEntry .= "  Message: $errorMessage\n";
    $logEntry .= "  IP: $ipAddress\n";
    $logEntry .= "  User-Agent: $userAgent\n";

    // إضافة تفاصيل الاستثناء إذا كان موجودًا
    if ($exception instanceof Throwable) {
        $logEntry .= "  Exception: {$exception->getMessage()}\n";
        $logEntry .= "  File: {$exception->getFile()}\n";
        $logEntry .= "  Line: {$exception->getLine()}\n";
        $logEntry .= "  Stack Trace: {$exception->getTraceAsString()}\n";
    }

    // إضافة سياق الخطأ إذا كان موجودًا
    if (!empty($errorContext)) {
        $logEntry .= "  Context: " . json_encode($errorContext, JSON_UNESCAPED_UNICODE) . "\n";
    }

    // التحقق من وجود المجلد الأب (database)
    $parentDir = __DIR__ . '/database';
    if (!is_dir($parentDir)) {
        if (!mkdir($parentDir, 0755, true) && !is_dir($parentDir)) {
            error_log("Cannot create parent directory: {$parentDir}");
            return;
        }
    }

    // التحقق من وجود مجلد السجلات
    if (!is_dir($logDir)) {
        if (!mkdir($logDir, 0755, true) && !is_dir($logDir)) {
            error_log("Cannot create log directory: {$logDir}");
            return;
        }
    }

    // التحقق من وجود الملف وصلاحياته
    if (!file_exists($logFile)) {
        if (!touch($logFile)) {
            error_log("Cannot create log file: {$logFile}");
            return;
        }
        if (!chmod($logFile, 0644)) {
            error_log("Cannot set permissions for log file: {$logFile}");
            return;
        }
        // إضافة ترويسة أولية للملف الجديد
        file_put_contents($logFile, "=== Date: $dateOnly ===\n");
    }

    // التحقق من إمكانية الكتابة
    if (!is_writable($logFile)) {
        if (!chmod($logFile, 0644)) {
            error_log("Log file is not writable and cannot fix permissions: {$logFile}");
            return;
        }
    }

    // تدوير السجلات إذا تجاوزت 5MB
    if (file_exists($logFile) && filesize($logFile) > 5 * 1024 * 1024) {
        $archiveFile = $logDir . '/errors_' . date("Y-m-d_H-i-s") . '.log';
        if (!rename($logFile, $archiveFile)) {
            error_log("Cannot rotate log file to: {$archiveFile}");
            return;
        }
        if (!touch($logFile)) {
            error_log("Cannot recreate log file after rotation: {$logFile}");
            return;
        }
        if (!chmod($logFile, 0644)) {
            error_log("Cannot set permissions for recreated log file: {$logFile}");
            return;
        }
        // إضافة ترويسة للملف الجديد بعد التدوير
        file_put_contents($logFile, "=== Date: $dateOnly ===\n");
    }

    // كتابة السجل في الملف بدون قفل حصري
    if (file_put_contents($logFile, $logEntry, FILE_APPEND) === false) {
        error_log("Failed to write to log file: {$logFile}");
    }
}

// التقاط أخطاء PHP (Fatal, Warning, Notice)
set_error_handler(function ($errno, $errstr, $errfile, $errline) {
    $errorTypeMap = [
        E_ERROR => 'Fatal Error',
        E_WARNING => 'Warning',
        E_PARSE => 'Parsing Error',
        E_NOTICE => 'Notice',
        E_CORE_ERROR => 'Core Error',
        E_CORE_WARNING => 'Core Warning',
        E_COMPILE_ERROR => 'Compile Error',
        E_COMPILE_WARNING => 'Compile Warning',
        E_USER_ERROR => 'User Error',
        E_USER_WARNING => 'User Warning',
        E_USER_NOTICE => 'User Notice',
        E_RECOVERABLE_ERROR => 'Recoverable Error',
        E_DEPRECATED => 'Deprecated',
        E_USER_DEPRECATED => 'User Deprecated',
    ];

    $errorType = $errorTypeMap[$errno] ?? 'Unknown Error';
    logError($errstr, $errorType, null, [
        'File' => $errfile,
        'Line' => $errline,
        'ErrorCode' => $errno
    ]);
    return false;
});

// التقاط الاستثناءات غير المعالجة
set_exception_handler(function (Throwable $exception) {
    logError($exception->getMessage(), 'Uncaught Exception', $exception);
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: text/plain');
        echo "Internal Server Error";
    }
    exit;
});

// التقاط الأخطاء الحرجة عند الإغلاق
register_shutdown_function(function () {
    $error = error_get_last();
    if ($error && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
        logError($error['message'], 'Shutdown Error', null, [
            'File' => $error['file'],
            'Line' => $error['line'],
            'Type' => $error['type']
        ]);
        if (!headers_sent()) {
            http_response_code(500);
            header('Content-Type: text/plain');
            echo "Fatal Error Occurred";
        }
    }
});

// إعدادات عرض الأخطاء
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/database/logs/php_errors.log');