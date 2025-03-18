<?php
ob_start(); // بدء التخزين المؤقت للإخراج
require_once 'security.php';

// تفعيل الحماية لصفحة العرض (GET)
$security = initializeSecurity('GET');
$csrfToken = $security['csrfToken'];

require_once 'error_log.php';

$message = isset($_SESSION['message']) ? sanitizeInput($_SESSION['message']) : '';
unset($_SESSION['message']);

$errors = isset($_SESSION['errors']) ? sanitizeInput($_SESSION['errors']) : [];
unset($_SESSION['errors']);

$username = isset($_SESSION['form_data']['username']) ? sanitizeInput($_SESSION['form_data']['username']) : '';
$phone_number = isset($_SESSION['form_data']['phone_number']) ? sanitizeInput($_SESSION['form_data']['phone_number']) : '';
?>
<!DOCTYPE html>
<html lang="ar">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تسجيل حساب - Azura</title>
    <style>
        /* تعريف الخط المحلي باستخدام @font-face */
        @font-face {
            font-family: 'Cairo';
            src: url('fonts/Cairo-Regular.ttf') format('truetype');
            font-weight: 400; /* عادي */
            font-style: normal;
        }
        @font-face {
            font-family: 'Cairo';
            src: url('fonts/Cairo-Bold.ttf') format('truetype');
            font-weight: 700; /* غامق */
            font-style: normal;
        }
        @font-face {
            font-family: 'Cairo';
            src: url('fonts/Cairo-Medium.ttf') format('truetype');
            font-weight: 500; /* متوسط */
            font-style: normal;
        }
        @font-face {
            font-family: 'Cairo';
            src: url('fonts/Cairo-Light.ttf') format('truetype');
            font-weight: 300; /* خفيف */
            font-style: normal;
        }

        /* تطبيق خط Cairo على جميع العناصر */
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Cairo', 'Arial', sans-serif !important;
        }
        body {
            direction: rtl;
            background-color: #f7f7f7;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .page-wrapper {
            text-align: center;
            width: 100%;
            max-width: 450px;
            padding: 20px;
        }
        h1 {
            font-size: 36px;
            font-weight: 700;
            color: #1a73e8;
            margin-bottom: 25px;
            text-shadow: 1px 1px 4px rgba(0, 0, 0, 0.1);
            letter-spacing: 1px;
        }
        .container {
            background: #fff;
            padding: 25px;
            border: 1px solid #e0e0e0;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.05);
        }
        h2 {
            font-weight: 700;
            margin-bottom: 20px;
            color: #333;
        }
        .message {
            margin-bottom: 20px;
            padding: 12px;
            border-radius: 10px;
            font-size: 14px;
            font-weight: 500;
            opacity: 1;
            transition: opacity 0.5s ease-in-out;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }
        .success {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
        }
        .error {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
        }
        .form-group {
            position: relative;
            margin-bottom: 20px;
            text-align: right;
        }
        label {
            display: block;
            margin-bottom: 6px;
            font-size: 14px;
            font-weight: 500;
            color: #444;
        }
        .phone-container {
            position: relative;
            width: 100%;
            direction: ltr;
        }
        .phone-prefix {
            position: absolute;
            left: 12px;
            top: 50%;
            transform: translateY(-50%);
            color: #666;
            font-size: 14px;
            pointer-events: none;
        }
        input {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid #ddd;
            border-radius: 12px;
            font-size: 14px;
            font-weight: 400;
            background-color: #fafafa;
            transition: border-color 0.3s ease, box-shadow 0.3s ease;
        }
        input:focus {
            border-color: #4CAF50;
            box-shadow: 0 0 8px rgba(76, 175, 80, 0.2);
            background-color: #fff;
            outline: none;
        }
        #phone_number {
            direction: ltr;
            text-align: left;
            padding-left: 60px;
        }
        .error-message {
            color: #721c24;
            font-size: 12px;
            font-weight: 400;
            margin-top: 6px;
            display: none;
        }
        .input-error {
            border-color: #f5c6cb;
            box-shadow: 0 0 8px rgba(245, 198, 203, 0.3);
        }
        button {
            width: 100%;
            padding: 14px 20px;
            margin-top: 20px;
            border: none;
            background-color: #4CAF50;
            color: white;
            font-size: 16px;
            font-weight: 700;
            border-radius: 12px;
            cursor: pointer;
            transition: background-color 0.3s ease, box-shadow 0.3s ease, transform 0.2s ease;
            box-shadow: 0 3px 12px rgba(0, 0, 0, 0.1);
        }
        button:hover {
            background-color: #45a049;
            box-shadow: 0 5px 18px rgba(0, 0, 0, 0.15);
            transform: translateY(-2px);
        }
        button:active {
            transform: translateY(0);
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }
        .notice {
            font-size: 12px;
            color: #666;
            margin-top: 20px;
            text-align: center;
        }
        footer {
            margin-top: 20px;
            font-size: 11px;
            color: #888;
            text-align: center;
        }
        footer a {
            color: #1a73e8;
            text-decoration: none;
        }
        footer a:hover {
            text-decoration: underline;
        }
        @media (max-width: 480px) {
            .page-wrapper {
                max-width: 90%;
                padding: 15px;
            }
            h1 {
                font-size: 28px;
            }
            .container {
                padding: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="page-wrapper">
        <h1>Azura</h1>
        <div class="container">
            <h2>إنشاء حساب جديد</h2>

            <?php if (!empty($message)): ?>
                <div id="messageBox" class="message <?= strpos($message, '✅') !== false ? 'success' : 'error' ?>">
                    <?= htmlspecialchars($message) ?>
                </div>
            <?php endif; ?>

            <form action="register.php" method="POST" id="registerForm">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8') ?>">

                <div class="form-group">
                    <label for="username">اسم المستخدم:</label>
                    <input type="text" id="username" name="username" placeholder="أدخل اسم المستخدم" value="<?= htmlspecialchars($username) ?>">
                    <div id="usernameError" class="error-message"><?= isset($errors['username']) ? htmlspecialchars($errors['username']) : '' ?></div>
                </div>

                <div class="form-group">
                    <label for="phone_number">رقم الهاتف:</label>
                    <div class="phone-container">
                        <span class="phone-prefix">+212</span>
                        <input type="text" id="phone_number" name="phone_number" placeholder="623554269" value="<?= htmlspecialchars($phone_number ? preg_replace('/^\+?212/', '', $phone_number) : '') ?>">
                    </div>
                    <div id="phoneNumberError" class="error-message"><?= isset($errors['phone_number']) ? htmlspecialchars($errors['phone_number']) : '' ?></div>
                </div>

                <div class="form-group">
                    <label for="password">كلمة المرور:</label>
                    <input type="password" id="password" name="password" placeholder="••••••••">
                    <div id="passwordError" class="error-message"><?= isset($errors['password']) ? htmlspecialchars($errors['password']) : '' ?></div>
                </div>

                <button type="submit">تسجيل</button>
            </form>

            <div class="notice">
                يمكنك تسجيل رقم هاتفك دون رسالة تحقق. في تحديث قادم يجب عليك تأكيد رقم هاتفك.
            </div>
        </div>

        <footer>
            بتسجيل حسابك فإنك توافق على <a href="#">سياسة الخصوصية</a> و<a href="#">شروط الخدمة</a>.
        </footer>
    </div>

    <script>
        // دالة لإرسال السجل إلى الملف عبر AJAX
        function logToFile(message) {
            var xhr = new XMLHttpRequest();
            xhr.open("POST", "log_js.php", true);
            xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
            xhr.send("message=" + encodeURIComponent(message));
        }

        document.addEventListener("DOMContentLoaded", function () {
            const messageBox = document.getElementById("messageBox");
            if (messageBox) {
                setTimeout(() => {
                    messageBox.style.opacity = "0";
                    setTimeout(() => messageBox.style.display = "none", 500);
                }, 3000);
            }

            const errorElements = document.querySelectorAll('.error-message');
            errorElements.forEach(element => {
                if (element.textContent.trim()) {
                    element.style.display = 'block';
                    const input = element.previousElementSibling.tagName === 'INPUT' ? 
                        element.previousElementSibling : 
                        element.previousElementSibling.querySelector('input');
                    input.classList.add('input-error');
                }
            });

            const registerForm = document.getElementById("registerForm");
            const usernameInput = document.getElementById("username");
            const phoneNumberInput = document.getElementById("phone_number");
            const passwordInput = document.getElementById("password");
            const usernameError = document.getElementById("usernameError");
            const phoneNumberError = document.getElementById("phoneNumberError");
            const passwordError = document.getElementById("passwordError");

            registerForm.addEventListener("submit", function (event) {
                let isValid = true;
                usernameError.style.display = "none";
                phoneNumberError.style.display = "none";
                passwordError.style.display = "none";
                usernameInput.classList.remove("input-error");
                phoneNumberInput.classList.remove("input-error");
                passwordInput.classList.remove("input-error");

                const username = usernameInput.value.trim();
                let phoneNumber = phoneNumberInput.value.trim();
                const password = passwordInput.value.trim();

                if (username === "") {
                    usernameError.textContent = "اسم المستخدم مطلوب";
                    usernameError.style.display = "block";
                    usernameInput.classList.add("input-error");
                    isValid = false;
                } else if (username.length < 3) {
                    usernameError.textContent = "اسم المستخدم يجب أن يكون 3 أحرف على الأقل";
                    usernameError.style.display = "block";
                    usernameInput.classList.add("input-error");
                    isValid = false;
                } else if (/\s/.test(username)) {
                    usernameError.textContent = "اسم المستخدم لا يمكن أن يحتوي على مسافات";
                    usernameError.style.display = "block";
                    usernameInput.classList.add("input-error");
                    isValid = false;
                }

                // تنظيف وتطبيع رقم الهاتف مع تسجيل الخطوات
                logToFile("Initial phone input: " + phoneNumber);
                let cleanedPhoneNumber = phoneNumber.replace(/[\s-]/g, '');
                logToFile("After removing spaces/dashes: " + cleanedPhoneNumber);

                if (cleanedPhoneNumber.startsWith('+212')) {
                    cleanedPhoneNumber = cleanedPhoneNumber.substring(4);
                    logToFile("After removing +212: " + cleanedPhoneNumber);
                } else if (cleanedPhoneNumber.startsWith('212')) {
                    cleanedPhoneNumber = cleanedPhoneNumber.substring(3);
                    logToFile("After removing 212: " + cleanedPhoneNumber);
                }

                // إزالة الصفر الأول إذا كان موجودًا
                if (cleanedPhoneNumber.startsWith('0')) {
                    cleanedPhoneNumber = cleanedPhoneNumber.substring(1);
                    logToFile("After removing leading zero: " + cleanedPhoneNumber);
                }

                let finalPhoneNumber = '+212' + cleanedPhoneNumber;
                logToFile("Final phone number: " + finalPhoneNumber);

                if (phoneNumber === "" || !/^\+212[0-9]{9}$/.test(finalPhoneNumber)) {
                    phoneNumberError.textContent = "رقم الهاتف غير صالح (مثال: +212623554269 أو 0623-554269)";
                    phoneNumberError.style.display = "block";
                    phoneNumberInput.classList.add("input-error");
                    logToFile("Phone number validation failed: " + finalPhoneNumber);
                    isValid = false;
                } else {
                    logToFile("Phone number validated successfully: " + finalPhoneNumber);
                }

                if (password === "") {
                    passwordError.textContent = "كلمة المرور مطلوبة";
                    passwordError.style.display = "block";
                    passwordInput.classList.add("input-error");
                    isValid = false;
                } else if (password.length < 12) {
                    passwordError.textContent = "كلمة المرور يجب أن تكون 12 حرفًا على الأقل";
                    passwordError.style.display = "block";
                    passwordInput.classList.add("input-error");
                    isValid = false;
                } else if (!/[A-Z]/.test(password) || !/[0-9]/.test(password) || !/[\W]/.test(password)) {
                    passwordError.textContent = "كلمة المرور يجب أن تحتوي على حرف كبير، رقم، ورمز خاص";
                    passwordError.style.display = "block";
                    passwordInput.classList.add("input-error");
                    isValid = false;
                }

                if (isValid) {
                    phoneNumberInput.value = finalPhoneNumber;
                    logToFile("Form submitted with phone: " + finalPhoneNumber);
                } else {
                    event.preventDefault();
                }
            });
        });
    </script>
</body>
</html>
<?php ob_end_flush(); // إنهاء التخزين المؤقت وإرسال الإخراج ?>