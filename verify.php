<?php
// إعدادات الجلسة الآمنة
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1); // يتطلب HTTPS، قم بتعطيله في بيئة محلية إذا لزم الأمر
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.gc_maxlifetime', 1800); // مدة الجلسة 30 دقيقة
ini_set('session.use_strict_mode', 1); // منع استخدام معرف جلسة غير صالح

// بدء الجلسة
session_start();

// تضمين ملف تسجيل الأخطاء
require_once 'error_log.php';

// تضمين PHPMailer
require __DIR__ . '/vendor/autoload.php'; // استخدام __DIR__ لضمان المسار الصحيح
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// الحد من المحاولات المتكررة
$max_attempts = 5;
$lockout_time = 300; // 5 دقائق
$client_ip = $_SERVER['REMOTE_ADDR'];

// تهيئة متغيرات تتبع المحاولات إذا لم تكن موجودة
if (!isset($_SESSION['login_attempts'][$client_ip])) {
    $_SESSION['login_attempts'][$client_ip] = ['count' => 0, 'last_attempt' => 0];
}

// التحقق من الحظر المؤقت
if ($_SESSION['login_attempts'][$client_ip]['count'] >= $max_attempts) {
    $time_since_last_attempt = time() - $_SESSION['login_attempts'][$client_ip]['last_attempt'];
    if ($time_since_last_attempt < $lockout_time) {
        $_SESSION['message'] = "❌ لقد تجاوزت الحد الأقصى للمحاولات. حاول مجددًا بعد " . ceil(($lockout_time - $time_since_last_attempt) / 60) . " دقائق.";
        header("Location: index.php");
        exit;
    } else {
        $_SESSION['login_attempts'][$client_ip] = ['count' => 0, 'last_attempt' => 0];
    }
}

// التأكد من وجود مجلد database/accounts وأنه محمي
$directory = 'database/accounts';
if (!is_dir($directory)) {
    mkdir($directory, 0755, true);
    file_put_contents("$directory/.htaccess", "Deny from all");
    file_put_contents("$directory/index.php", "<?php header('HTTP/1.1 403 Forbidden'); exit;");
}

// إنشاء أو الاتصال بقاعدة بيانات SQLite
try {
    $db = new SQLite3("$directory/users.db", SQLITE3_OPEN_CREATE | SQLITE3_OPEN_READWRITE);
    $db->busyTimeout(5000);

    // إنشاء جدول المستخدمين مع قيود أمان إضافية
    $db->exec("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL CHECK(length(username) >= 3 AND length(username) <= 50),
        email TEXT UNIQUE NOT NULL CHECK(email LIKE '%@%.%' AND length(email) <= 255),
        password TEXT NOT NULL CHECK(length(password) >= 12),
        ip_address TEXT,
        verification_token TEXT,
        verified INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )");

    // إضافة الحقول الجديدة إذا لم تكن موجودة
    $columns = $db->query("PRAGMA table_info(users)");
    $has_ip_address = $has_verification_token = $has_verified = false;
    while ($column = $columns->fetchArray(SQLITE3_ASSOC)) {
        if ($column['name'] === 'ip_address') $has_ip_address = true;
        if ($column['name'] === 'verification_token') $has_verification_token = true;
        if ($column['name'] === 'verified') $has_verified = true;
    }
    if (!$has_ip_address) $db->exec("ALTER TABLE users ADD COLUMN ip_address TEXT");
    if (!$has_verification_token) $db->exec("ALTER TABLE users ADD COLUMN verification_token TEXT");
    if (!$has_verified) $db->exec("ALTER TABLE users ADD COLUMN verified INTEGER DEFAULT 0");
} catch (Exception $e) {
    logError("Database Connection Error: " . $e->getMessage() . " | IP: $client_ip", 'Database Error');
    $_SESSION['message'] = "❌ خطأ في الاتصال بقاعدة البيانات.";
    header("Location: index.php");
    exit;
}

// التحقق من وجود رمز CSRF
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// التعامل مع طلبات POST فقط
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // التحقق من صحة رمز CSRF
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        logError("CSRF validation failed | IP: $client_ip | Headers: " . json_encode(getallheaders()), 'Security Alert');
        $_SESSION['message'] = "❌ محاولة غير شرعية.";
        header("Location: index.php");
        exit;
    }

    // تعقيم المدخلات يدويًا
    $username = trim($_POST["username"] ?? '');
    $username = preg_replace('/[^a-zA-Z0-9_]/', '', $username);
    $email = filter_var(trim($_POST["email"] ?? ''), FILTER_SANITIZE_EMAIL);
    $password = $_POST["password"] ?? '';

    // مصفوفة لتخزين رسائل الخطأ التفصيلية
    $errors = [];

    // التحقق من صحة المدخلات
    if (empty($username)) {
        $errors['username'] = "اسم المستخدم مطلوب";
    } elseif (strlen($username) < 3 || strlen($username) > 50) {
        $errors['username'] = "اسم المستخدم يجب أن يكون بين 3 و50 حرفًا";
    } elseif (preg_match('/[^a-zA-Z0-9_]/', $username)) {
        $errors['username'] = "اسم المستخدم يجب أن يحتوي على أحرف وأرقام فقط";
    }

    if (empty($email)) {
        $errors['email'] = "البريد الإلكتروني مطلوب";
    } elseif (strlen($email) > 255) {
        $errors['email'] = "البريد الإلكتروني طويل جدًا";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors['email'] = "البريد الإلكتروني غير صالح";
    }

    if (empty($password)) {
        $errors['password'] = "كلمة المرور مطلوبة";
    } elseif (strlen($password) < 12) {
        $errors['password'] = "كلمة المرور يجب أن تكون 12 حرفًا على الأقل";
    } elseif (!preg_match('/[A-Z]/', $password) || !preg_match('/[0-9]/', $password) || !preg_match('/[\W]{2,}/', $password)) {
        $errors['password'] = "كلمة المرور يجب أن تحتوي على حرف كبير، رقم، ورمزين خاصين على الأقل";
    }

    // إذا كانت هناك أخطاء
    if (!empty($errors)) {
        $_SESSION['login_attempts'][$client_ip]['count']++;
        $_SESSION['login_attempts'][$client_ip]['last_attempt'] = time();
        logError("Registration failed due to input errors | IP: $client_ip", 'Validation Error');
        $_SESSION['errors'] = $errors;
        $_SESSION['form_data'] = ['username' => $username, 'email' => $email];
        $_SESSION['message'] = "❌ يرجى تصحيح الأخطاء أدناه.";
        header("Location: index.php");
        $db->close();
        exit;
    }

    try {
        // التحقق من وجود المستخدم أو البريد الإلكتروني مسبقًا
        $stmt = $db->prepare("SELECT id FROM users WHERE username = :username OR email = :email");
        $stmt->bindValue(':username', $username, SQLITE3_TEXT);
        $stmt->bindValue(':email', $email, SQLITE3_TEXT);
        $result = $stmt->execute();

        if ($result->fetchArray()) {
            $stmt_username = $db->prepare("SELECT id FROM users WHERE username = :username");
            $stmt_username->bindValue(':username', $username, SQLITE3_TEXT);
            $result_username = $stmt_username->execute();
            if ($result_username->fetchArray(SQLITE3_NUM)) {
                $errors['username'] = "اسم المستخدم مستخدم بالفعل";
            }

            $stmt_email = $db->prepare("SELECT id FROM users WHERE email = :email");
            $stmt_email->bindValue(':email', $email, SQLITE3_TEXT);
            $result_email = $stmt_email->execute();
            if ($result_email->fetchArray(SQLITE3_NUM)) {
                $errors['email'] = "البريد الإلكتروني مستخدم بالفعل";
            }

            $_SESSION['login_attempts'][$client_ip]['count']++;
            $_SESSION['login_attempts'][$client_ip]['last_attempt'] = time();
            logError("Duplicate username or email | IP: $client_ip", 'Validation Error');
            $_SESSION['errors'] = $errors;
            $_SESSION['form_data'] = ['username' => $username, 'email' => $email];
            $_SESSION['message'] = "❌ يرجى تصحيح الأخطاء أدناه.";
            header("Location: index.php");
            $db->close();
            exit;
        }

        // إنشاء رمز التحقق للبريد الإلكتروني
        $verification_token = bin2hex(random_bytes(16));

        // تشفير كلمة المرور باستخدام Argon2id إذا كان متاحًا
        $options = (PHP_VERSION_ID >= 70200 && defined('PASSWORD_ARGON2ID')) ? 
            ['memory_cost' => 1<<17, 'time_cost' => 4, 'threads' => 2] : 
            ['cost' => 12];
        $algo = (PHP_VERSION_ID >= 70200 && defined('PASSWORD_ARGON2ID')) ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
        $hashed_pass = password_hash($password, $algo, $options);

        // إدخال المستخدم في قاعدة البيانات مع رمز التحقق
        $stmt = $db->prepare("INSERT INTO users (username, email, password, ip_address, verification_token) VALUES (:username, :email, :password, :ip, :token)");
        $stmt->bindValue(':username', $username, SQLITE3_TEXT);
        $stmt->bindValue(':email', $email, SQLITE3_TEXT);
        $stmt->bindValue(':password', $hashed_pass, SQLITE3_TEXT);
        $stmt->bindValue(':ip', $client_ip, SQLITE3_TEXT);
        $stmt->bindValue(':token', $verification_token, SQLITE3_TEXT);

        if ($stmt->execute()) {
            // إرسال بريد التحقق باستخدام PHPMailer
            $verification_link = "http://localhost/MYSITE/verify.php?token=" . $verification_token; // استبدل بـ URL موقعك
            $email_body = "مرحبًا $username،\nيرجى تأكيد بريدك الإلكتروني عبر الرابط التالي:\n$verification_link\n\nإذا لم تقم بالتسجيل، تجاهل هذا البريد.";

            $mail = new PHPMailer(true);
            try {
                // إعدادات SMTP (مثال باستخدام Gmail)
                $mail->isSMTP();
                $mail->Host = 'smtp.gmail.com'; // استبدل بخادم SMTP الخاص بك
                $mail->SMTPAuth = true;
                $mail->Username = 'your-email@gmail.com'; // استبدل ببريدك الإلكتروني
                $mail->Password = 'your-app-password'; // استبدل بكلمة مرور التطبيق (App Password لـ Gmail)
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
                $mail->Port = 587;

                // إعدادات البريد
                $mail->setFrom('your-email@gmail.com', 'Your Site');
                $mail->addAddress($email, $username);
                $mail->isHTML(false);
                $mail->Subject = "تأكيد بريدك الإلكتروني";
                $mail->Body = $email_body;

                $mail->send();
                logError("New user registered: $username | IP: $client_ip | Verification token: $verification_token | Email sent", 'User Registration');
                $_SESSION['message'] = "✅ تم التسجيل بنجاح! تحقق من بريدك الإلكتروني لتأكيد الحساب.";
            } catch (Exception $e) {
                logError("Email sending failed: " . $mail->ErrorInfo . " | IP: $client_ip | User: $username", 'Email Error');
                $_SESSION['message'] = "✅ تم التسجيل بنجاح، لكن فشل إرسال بريد التحقق. اتصل بالدعم.";
            }

            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
            $_SESSION['login_attempts'][$client_ip] = ['count' => 0, 'last_attempt' => 0];
            session_regenerate_id(true); // تجديد معرف الجلسة
            $db->close();
            header("Location: index.php");
            exit;
        } else {
            $_SESSION['message'] = "❌ حدث خطأ أثناء التسجيل.";
            logError("Failed to insert user: $username | IP: $client_ip", 'Database Error');
            $db->close();
            header("Location: index.php");
            exit;
        }
    } catch (Exception $e) {
        $_SESSION['message'] = "❌ خطأ غير متوقع.";
        logError("Exception: " . $e->getMessage() . " | IP: $client_ip | Headers: " . json_encode(getallheaders()), 'Exception');
        $db->close();
        header("Location: index.php");
        exit;
    }
} else {
    $_SESSION['message'] = "❌ طريقة الطلب غير مدعومة.";
    header("Location: index.php");
    exit;
}