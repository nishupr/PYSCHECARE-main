<?php
require_once __DIR__ . '/session_config.php';
session_start();

require_once __DIR__ . '/database.php';

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    header("Location: login.html");
    exit();
}

if (
    empty($_POST['csrf_token']) ||
    empty($_SESSION['csrf_token']) ||
    !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])
) {
    http_response_code(403);
    die("Invalid CSRF token.");
}

$username = trim($_POST["username"] ?? "");
$password = $_POST["password"] ?? "";

if ($username === "" || $password === "") {
    header("Location: login.html?error=invalid");
    exit();
}

try {
    $db = getAuthDatabase();
    $ip = getIPAddress();
    $rateKey = "login:" . $ip;

    // Check rate limit: 5 attempts per 15 minutes
    if (!checkRateLimit($db, $rateKey, 5, 900)) {
        header("Location: login.html?error=rate_limit");
        exit();
    }

    $stmt = $db->prepare(
        "SELECT id, username, password_hash FROM users WHERE username = :username"
    );
    $stmt->execute([':username' => $username]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password_hash'])) {
        resetAttempts($db, $rateKey);
        session_regenerate_id(true);
        $_SESSION["user_id"] = $user["id"];
        $_SESSION["username"] = $user["username"];
        header("Location: welcome.php");
        exit();
    }

    // Record failed attempt
    incrementAttempts($db, $rateKey);
} catch (PDOException $e) {
    header("Location: login.html?error=db");
    exit();
}

header("Location: login.html?error=invalid");
exit();
