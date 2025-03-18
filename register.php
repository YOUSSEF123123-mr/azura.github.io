<?php
ob_start(); // بدء التخزين المؤقت للإخراج
require_once 'security.php';

// تفعيل الحماية لصفحة استقبال النموذج (POST)
$security = initializeSecurity('POST');
$incrementAttempts = $security['incrementAttempts'];
$csrfToken = $security['csrfToken'];

require_once 'error_log.php';

$directory = 'database/accounts';
if (!is_dir($directory)) {
    mkdir($directory, 0755, true);
}

try {
    $db = new SQLite3("$directory/users.db", SQLITE3_OPEN_CREATE | SQLITE3_OPEN_READWRITE);
    $db->busyTimeout(5000);

    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL CHECK(length(username) >= 3 AND length(username) <= 50),
        phone_number TEXT UNIQUE NOT NULL CHECK(length(phone_number) >= 10 AND length(phone_number) <= 15),
        password TEXT NOT NULL CHECK(length(password) >= 12),
        ip_address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )");

    $columns = $db->query("PRAGMA table_info(users)");
    $has_phone_number = $has_ip_address = false;
    while ($column = $columns->fetchArray(SQLITE3_ASSOC)) {
        if ($column['name'] === 'phone_number') $has_phone_number = true;
        if ($column['name'] === 'ip_address') $has_ip_address = true;
    }
    if (!$has_phone_number) $db->exec("ALTER TABLE users ADD COLUMN phone_number TEXT UNIQUE CHECK(length(phone_number) >= 10 AND length(phone_number) <= 15)");
    if (!$has_ip_address) $db->exec("ALTER TABLE users ADD COLUMN ip_address TEXT");
} catch (Exception $e) {
    logSecurityEvent("Database Connection Error: " . $e->getMessage(), 'Database');
    $_SESSION['message'] = "❌ خطأ في الاتصال بقاعدة البيانات.";
    header("Location: index.php");
    $db->close();
    exit;
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    validateCsrfToken($_POST['csrf_token'] ?? '');

    $username = sanitizeInput($_POST["username"] ?? '');
    $username = preg_replace('/[^a-zA-Z0-9_]/', '', $username);
    $phone_number = sanitizeInput($_POST["phone_number"] ?? '');
    $password = $_POST["password"] ?? ''; // لا نستخدم sanitizeInput على كلمة المرور لأنها ستُشفر

    // تسجيل الإدخال الأصلي لرقم الهاتف
    logError("Raw phone input received: $phone_number", 'Phone Validation');

    // تنظيف وتطبيع رقم الهاتف
    $cleaned_phone_number = preg_replace('/[\s-]/', '', $phone_number);
    logError("After removing spaces/dashes: $cleaned_phone_number", 'Phone Validation');

    if (preg_match('/^\+?212/', $cleaned_phone_number)) {
        $cleaned_phone_number = preg_replace('/^\+?212/', '', $cleaned_phone_number);
        logError("After removing +212/212: $cleaned_phone_number", 'Phone Validation');
    }

    // إزالة الصفر الأول إذا كان موجودًا
    if (substr($cleaned_phone_number, 0, 1) === '0') {
        $cleaned_phone_number = substr($cleaned_phone_number, 1);
        logError("After removing leading zero: $cleaned_phone_number", 'Phone Validation');
    }

    $phone_number = '+212' . $cleaned_phone_number;
    logError("Final phone number: $phone_number", 'Phone Validation');

    $errors = [];

    if (empty($username)) {
        $errors['username'] = "اسم المستخدم مطلوب";
        $incrementAttempts();
    } elseif (strlen($username) < 3 || strlen($username) > 50) {
        $errors['username'] = "اسم المستخدم يجب أن يكون بين 3 و50 حرفًا";
        $incrementAttempts();
    } elseif (preg_match('/[^a-zA-Z0-9_]/', $username)) {
        $errors['username'] = "اسم المستخدم يجب أن يحتوي على أحرف وأرقام فقط";
        $incrementAttempts();
    }

    if (empty($phone_number)) {
        $errors['phone_number'] = "رقم الهاتف مطلوب";
        $incrementAttempts();
        logError("Phone number is empty", 'Validation Error');
    } elseif (!preg_match('/^\+212[0-9]{9}$/', $phone_number)) {
        $errors['phone_number'] = "رقم الهاتف غير صالح (مثال: +212623554269 أو 0623-554269)";
        $incrementAttempts();
        logError("Phone number validation failed: $phone_number", 'Validation Error');
    } else {
        logError("Phone number validated successfully: $phone_number", 'Phone Validation');
    }

    if (empty($password)) {
        $errors['password'] = "كلمة المرور مطلوبة";
        $incrementAttempts();
    } elseif (strlen($password) < 12) {
        $errors['password'] = "كلمة المرور يجب أن تكون 12 حرفًا على الأقل";
        $incrementAttempts();
    } elseif (!preg_match('/[A-Z]/', $password) || !preg_match('/[0-9]/', $password) || !preg_match('/[\W]/', $password)) {
        $errors['password'] = "كلمة المرور يجب أن تحتوي على حرف كبير، رقم، ورمز خاص على الأقل";
        $incrementAttempts();
    }

    if (!empty($errors)) {
        logSecurityEvent("Validation errors: " . json_encode($errors), 'Validation');
        $_SESSION['errors'] = $errors;
        $_SESSION['form_data'] = ['username' => $username, 'phone_number' => $phone_number];
        $_SESSION['message'] = "❌ يرجى تصحيح الأخطاء أدناه.";
        header("Location: index.php");
        $db->close();
        exit;
    }

    try {
        $stmt = $db->prepare("SELECT id FROM users WHERE username = :username OR phone_number = :phone_number");
        $stmt->bindValue(':username', $username, SQLITE3_TEXT);
        $stmt->bindValue(':phone_number', $phone_number, SQLITE3_TEXT);
        $result = $stmt->execute();

        if ($result->fetchArray()) {
            $stmt_username = $db->prepare("SELECT id FROM users WHERE username = :username");
            $stmt_username->bindValue(':username', $username, SQLITE3_TEXT);
            $result_username = $stmt_username->execute();
            if ($result_username->fetchArray(SQLITE3_NUM)) {
                $errors['username'] = "اسم المستخدم مستخدم بالفعل";
                $incrementAttempts();
            }

            $stmt_phone = $db->prepare("SELECT id FROM users WHERE phone_number = :phone_number");
            $stmt_phone->bindValue(':phone_number', $phone_number, SQLITE3_TEXT);
            $result_phone = $stmt_phone->execute();
            if ($result_phone->fetchArray(SQLITE3_NUM)) {
                $errors['phone_number'] = "رقم الهاتف مستخدم بالفعل";
                $incrementAttempts();
            }

            logSecurityEvent("Duplicate username or phone number", 'Validation');
            $_SESSION['errors'] = $errors;
            $_SESSION['form_data'] = ['username' => $username, 'phone_number' => $phone_number];
            $_SESSION['message'] = "❌ يرجى تصحيح الأخطاء أدناه.";
            header("Location: index.php");
            $db->close();
            exit;
        }

        $options = (PHP_VERSION_ID >= 70200 && defined('PASSWORD_ARGON2ID')) ? 
            ['memory_cost' => 1<<17, 'time_cost' => 4, 'threads' => 2] : 
            ['cost' => 12];
        $algo = (PHP_VERSION_ID >= 70200 && defined('PASSWORD_ARGON2ID')) ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
        $hashed_pass = password_hash($password, $algo, $options);

        $stmt = $db->prepare("INSERT INTO users (username, phone_number, password, ip_address) VALUES (:username, :phone_number, :password, :ip)");
        $stmt->bindValue(':username', $username, SQLITE3_TEXT);
        $stmt->bindValue(':phone_number', $phone_number, SQLITE3_TEXT);
        $stmt->bindValue(':password', $hashed_pass, SQLITE3_TEXT);
        $stmt->bindValue(':ip', $_SERVER['REMOTE_ADDR'], SQLITE3_TEXT);

        if ($stmt->execute()) {
            logSecurityEvent("New user registered: $username | Phone: $phone_number", 'Registration');
            $_SESSION['message'] = "✅ تم التسجيل بنجاح!";
            session_regenerate_id(true);
            header("Location: index.php");
            $db->close();
            exit;
        } else {
            logSecurityEvent("Failed to insert user: $username", 'Database');
            $_SESSION['message'] = "❌ حدث خطأ أثناء التسجيل.";
            header("Location: index.php");
            $db->close();
            exit;
        }
    } catch (Exception $e) {
        logSecurityEvent("Exception: " . $e->getMessage(), 'Exception');
        $_SESSION['message'] = "❌ خطأ غير متوقع.";
        header("Location: index.php");
        $db->close();
        exit;
    }
}
ob_end_flush(); // إنهاء التخزين المؤقت وإرسال الإخراج