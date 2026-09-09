<?php
require_once __DIR__ . '/functions.php';

if (!empty($_SESSION['user_id'])) {
    log_activity($pdo, $_SESSION['user_id'], 'LOGOUT');
}

// Hancurkan session secara menyeluruh
$_SESSION = [];

if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params['path'], $params['domain'], $params['secure'], $params['httponly']);
}

session_destroy();
header('Location: login.php');
exit;
