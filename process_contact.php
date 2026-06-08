<?php
require_once __DIR__ . '/session_config.php';
require_once __DIR__ . '/validation.php';
session_start();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // Validate CSRF token
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(403);
        die("Invalid CSRF token.");
    }

    $name    = trim($_POST['name'] ?? '');
    $email   = trim($_POST['email'] ?? '');
    $message = trim($_POST['message'] ?? '');

    $validationError = validateContactInput($name, $email, $message);
    if ($validationError !== null) {
        http_response_code(400);
        die($validationError);
    }

    try {
        require_once __DIR__ . '/database.php';
        $db = getAuthDatabase();

        $stmt = $db->prepare("INSERT INTO contact_messages (name, email, message) VALUES (:name, :email, :message)");
        $stmt->execute([
            ':name' => $name,
            ':email' => $email,
            ':message' => $message
        ]);

        echo "Message received. Thank you, " . htmlspecialchars($name, ENT_QUOTES, 'UTF-8') . "!";
    } catch (PDOException $e) {
        http_response_code(500);
        die("Database error. Please try again later.");
    }
}
?>
