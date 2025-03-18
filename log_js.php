<?php
require_once 'error_log.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['message'])) {
    $message = trim($_POST['message']);
    if (!empty($message)) {
        logError($message, 'JS Validation');
    }
    exit;
}